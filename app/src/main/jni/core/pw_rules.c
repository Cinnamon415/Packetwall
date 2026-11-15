/*
 * This file is part of Packetwall.
 *
 * Packetwall is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Compiled rules file format (UTF-8, one entry per line, tab separated), written by RulesCompiler.kt:
 *
 *   R <ref> <set> <who> <uid> <block> <reject> <kind> <value> <subs> <proto> <port> [<route>]
 *       route (allow rules): 0 = default, 1 = direct, 2 = through the upstream proxy
 *       kind: A = all, C = country (value = ISO code), S = prefix of an AS (expanded by the app),
 *             I = IP or CIDR, D = domain pattern
 *   L <set> <ref> <block> <reject> <path>
 *       a normalized list file: one entry per line, "#" comments. Entry prefixes:
 *       "!" = allow (else the list default), "=" = exact host (else + subdomains).
 *       IP / CIDR entries are detected automatically.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "pw_rules.h"
#include "common/utils.h"

#define KIND_ALL     'A'
#define KIND_COUNTRY 'C'
#define KIND_IP      'I'
#define KIND_DOMAIN  'D'
#define KIND_ASN     'S'   // a network prefix of an AS: matched like IP, ranked between country and CIDR

#define F_BLOCK  0x01
#define F_REJECT 0x02
#define F_SUBS   0x04
#define F_WILD   0x08   // pattern contains '*'
#define F_ROUTE_DIRECT 0x10
#define F_ROUTE_UP     0x20

#define MAX_LABELS 64
#define MAX_CANDIDATES 256

typedef struct {
    int32_t ref;
    int32_t uid;
    uint32_t str;       // offset into the string pool (domain pattern / country)
    int32_t next;       // hash chain
    int32_t score;
    uint16_t set;
    uint16_t port;
    uint8_t who;
    uint8_t flags;
    uint8_t kind;
    uint8_t proto;
    uint8_t ipver;
    uint8_t prefix;
    zdtun_ip_t ip;
} rule_t;

struct pw_engine {
    rule_t *rules;
    int num_rules, rules_cap;

    char *pool;
    uint32_t pool_len, pool_cap;

    // open addressing: literal domain -> first rule index + 1
    uint32_t *table;
    uint32_t table_cap;   // power of 2
    uint32_t table_used;

    // rules that need a linear scan (wildcards, IPs, countries, all)
    int32_t *linear;
    int num_linear, linear_cap;
};

/* ******************************************************* */

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    for(; *s; s++)
        h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

static uint32_t pool_add(pw_engine_t *e, const char *s) {
    size_t len = strlen(s) + 1;

    if(e->pool_len + len > e->pool_cap) {
        uint32_t cap = e->pool_cap ? e->pool_cap * 2 : 65536;
        while(cap < e->pool_len + len)
            cap *= 2;
        char *p = realloc(e->pool, cap);
        if(!p)
            return UINT32_MAX;
        e->pool = p;
        e->pool_cap = cap;
    }

    uint32_t off = e->pool_len;
    memcpy(e->pool + off, s, len);
    e->pool_len += len;
    return off;
}

static bool table_grow(pw_engine_t *e);

static int32_t* table_slot(pw_engine_t *e, const char *key, bool create) {
    if(create && ((e->table_used + 1) * 4 >= e->table_cap * 3)) {
        if(!table_grow(e))
            return NULL;
    }
    if(!e->table_cap)
        return NULL;

    uint32_t mask = e->table_cap - 1;
    uint32_t i = fnv1a(key) & mask;

    while(e->table[i]) {
        rule_t *r = &e->rules[e->table[i] - 1];
        if(strcmp(e->pool + r->str, key) == 0)
            return (int32_t*) &e->table[i];
        i = (i + 1) & mask;
    }

    return create ? (int32_t*) &e->table[i] : NULL;
}

static bool table_grow(pw_engine_t *e) {
    uint32_t old_cap = e->table_cap;
    uint32_t *old = e->table;
    uint32_t cap = old_cap ? old_cap * 2 : 1024;

    e->table = calloc(cap, sizeof(uint32_t));
    if(!e->table) {
        e->table = old;
        return false;
    }
    e->table_cap = cap;
    e->table_used = 0;

    for(uint32_t i = 0; i < old_cap; i++) {
        if(old[i]) {
            const char *key = e->pool + e->rules[old[i] - 1].str;
            uint32_t j = fnv1a(key) & (cap - 1);
            while(e->table[j])
                j = (j + 1) & (cap - 1);
            e->table[j] = old[i];
            e->table_used++;
        }
    }
    free(old);
    return true;
}

/* ******************************************************* */

static int split_labels(const char *s, const char **labels, int *lens) {
    int n = 0;
    const char *start = s;

    for(const char *p = s; ; p++) {
        if((*p == '.') || (*p == '\0')) {
            if(n >= MAX_LABELS)
                return -1;
            labels[n] = start;
            lens[n] = (int)(p - start);
            n++;
            if(*p == '\0')
                break;
            start = p + 1;
        }
    }
    return n;
}

// glob inside a label: '*' matches any run of characters (no dots)
static bool glob_label(const char *p, int plen, const char *s, int slen) {
    int pi = 0, si = 0, star = -1, mark = 0;

    while(si < slen) {
        if((pi < plen) && (p[pi] == '*')) {
            star = pi++;
            mark = si;
        } else if((pi < plen) && (p[pi] == s[si])) {
            pi++; si++;
        } else if(star >= 0) {
            pi = star + 1;
            si = ++mark;
        } else
            return false;
    }
    while((pi < plen) && (p[pi] == '*'))
        pi++;
    return pi == plen;
}

static bool match_labels(const char **pl, const int *plen, int pn,
                         const char **hl, const int *hlen, int hn) {
    if(pn == 0)
        return hn == 0;

    if((plen[0] == 2) && (pl[0][0] == '*') && (pl[0][1] == '*')) {
        // '**' = one or more labels
        for(int k = 1; k <= hn; k++) {
            if(match_labels(pl + 1, plen + 1, pn - 1, hl + k, hlen + k, hn - k))
                return true;
        }
        return false;
    }

    if(hn == 0)
        return false;
    if(!glob_label(pl[0], plen[0], hl[0], hlen[0]))
        return false;
    return match_labels(pl + 1, plen + 1, pn - 1, hl + 1, hlen + 1, hn - 1);
}

bool pw_match_domain(const char *pattern, const char *host, bool subdomains) {
    const char *pl[MAX_LABELS], *hl[MAX_LABELS];
    int plen[MAX_LABELS], hlen[MAX_LABELS];
    int pn = split_labels(pattern, pl, plen);
    int hn = split_labels(host, hl, hlen);

    if((pn <= 0) || (hn <= 0))
        return false;

    if(match_labels(pl, plen, pn, hl, hlen, hn))
        return true;

    if(subdomains) {
        for(int k = 1; k < hn; k++) {
            if(match_labels(pl, plen, pn, hl + k, hlen + k, hn - k))
                return true;
        }
    }
    return false;
}

/* ******************************************************* */

// Narrower targets get higher scores. Domain > IP > country > all.
static int32_t domain_score(const char *pattern, bool subs) {
    int literal = 0;
    bool any_wild = false, deep = false;
    const char *start = pattern;

    for(const char *p = pattern; ; p++) {
        if((*p == '.') || (*p == '\0')) {
            bool wild = (memchr(start, '*', p - start) != NULL);
            if(!wild)
                literal++;
            else {
                any_wild = true;
                if((p - start == 2) && (start[0] == '*') && (start[1] == '*'))
                    deep = true;
            }
            if(*p == '\0')
                break;
            start = p + 1;
        }
    }

    int32_t s = 1000 + literal * 10;
    if(!deep && !subs)
        s += 4;       // fixed depth
    if(!any_wild && !subs)
        s += 3;       // exact host
    else if(!any_wild && subs)
        s += 2;       // name + subdomains is narrower than '**.name'
    return s;
}

static int32_t final_score(int32_t base, uint8_t proto, uint16_t port) {
    return base * 4 + (port ? 2 : 0) + (proto ? 1 : 0);
}

static void to_lower(char *s) {
    for(; *s; s++)
        *s = (char) tolower((unsigned char) *s);
}

static int parse_cidr(const char *s, zdtun_ip_t *ip, uint8_t *ipver, uint8_t *prefix) {
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int pfx = -1;
    if(slash) {
        *slash = '\0';
        pfx = atoi(slash + 1);
    }

    memset(ip, 0, sizeof(*ip));
    int v = zdtun_parse_ip(buf, ip);
    if((v != 4) && (v != 6))
        return -1;

    int max = (v == 4) ? 32 : 128;
    if((pfx < 0) || (pfx > max))
        pfx = max;

    *ipver = (uint8_t) v;
    *prefix = (uint8_t) pfx;
    return 0;
}

static bool ip_in_cidr(const rule_t *r, uint8_t ipver, const zdtun_ip_t *ip) {
    if(r->ipver != ipver)
        return false;

    const uint8_t *a = (const uint8_t*) &r->ip;
    const uint8_t *b = (const uint8_t*) ip;
    int bits = r->prefix;
    int bytes = bits / 8;

    if(memcmp(a, b, bytes) != 0)
        return false;
    if(bits % 8) {
        uint8_t mask = (uint8_t)(0xFF << (8 - (bits % 8)));
        if((a[bytes] & mask) != (b[bytes] & mask))
            return false;
    }
    return true;
}

/* ******************************************************* */

static int add_rule(pw_engine_t *e, rule_t *r, const char *value) {
    if(e->num_rules >= e->rules_cap) {
        int cap = e->rules_cap ? e->rules_cap * 2 : 256;
        rule_t *n = realloc(e->rules, cap * sizeof(rule_t));
        if(!n)
            return -1;
        e->rules = n;
        e->rules_cap = cap;
    }

    r->next = -1;
    bool linear = true;

    switch(r->kind) {
        case KIND_ALL:
            r->score = final_score(0, r->proto, r->port);
            break;
        case KIND_COUNTRY:
            r->str = pool_add(e, value);
            if(r->str == UINT32_MAX)
                return -1;
            r->score = final_score(100, r->proto, r->port);
            break;
        case KIND_IP:
            if(parse_cidr(value, &r->ip, &r->ipver, &r->prefix) < 0)
                return 1; // skip
            r->score = final_score(300 + (r->prefix * 100) / ((r->ipver == 4) ? 32 : 128), r->proto, r->port);
            break;
        case KIND_ASN:
            if(parse_cidr(value, &r->ip, &r->ipver, &r->prefix) < 0)
                return 1;
            r->score = final_score(200, r->proto, r->port);
            break;
        case KIND_DOMAIN: {
            if(!value[0])
                return 1;
            if(strchr(value, '*'))
                r->flags |= F_WILD;
            r->str = pool_add(e, value);
            if(r->str == UINT32_MAX)
                return -1;
            r->score = final_score(domain_score(value, r->flags & F_SUBS), r->proto, r->port);
            linear = (r->flags & F_WILD);
            break;
        }
        default:
            return 1;
    }

    int idx = e->num_rules++;
    e->rules[idx] = *r;

    if(linear) {
        if(e->num_linear >= e->linear_cap) {
            int cap = e->linear_cap ? e->linear_cap * 2 : 64;
            int32_t *n = realloc(e->linear, cap * sizeof(int32_t));
            if(!n)
                return -1;
            e->linear = n;
            e->linear_cap = cap;
        }
        e->linear[e->num_linear++] = idx;
    } else {
        int32_t *slot = table_slot(e, value, true);
        if(!slot)
            return -1;
        if(*slot == 0) {
            e->table_used++;
            *slot = idx + 1;
        } else {
            // prepend to the chain of rules with the same pattern
            e->rules[idx].next = *slot - 1;
            *slot = idx + 1;
        }
    }
    return 0;
}

static char* trim(char *s) {
    while(isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while((end > s) && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

static int load_list(pw_engine_t *e, const char *path, uint16_t set, int32_t ref, bool block, bool reject) {
    FILE *f = fopen(path, "r");
    if(!f) {
        log_e("pw: cannot open list %s", path);
        return -1;
    }

    char line[512];
    int n = 0;

    while(fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if(!*s || (*s == '#'))
            continue;

        rule_t r = {0};
        r.ref = ref;
        r.uid = -1;
        r.set = set;
        r.who = 0;
        r.flags = (block ? F_BLOCK : 0) | (reject ? F_REJECT : 0) | F_SUBS;

        if(*s == '!') {
            r.flags &= ~(F_BLOCK | F_REJECT);
            s++;
        }
        if(*s == '=') {
            r.flags &= ~F_SUBS;
            s++;
        }
        to_lower(s);

        zdtun_ip_t ip;
        uint8_t v, pfx;
        r.kind = (parse_cidr(s, &ip, &v, &pfx) == 0) ? KIND_IP : KIND_DOMAIN;

        int rv = add_rule(e, &r, s);
        if(rv < 0) {
            fclose(f);
            return -1;
        }
        if(rv == 0)
            n++;
    }

    fclose(f);
    return n;
}

pw_engine_t* pw_engine_load(const char *path, char *err, int errlen) {
    FILE *f = fopen(path, "r");
    if(!f) {
        snprintf(err, errlen, "cannot open %s", path);
        return NULL;
    }

    pw_engine_t *e = calloc(1, sizeof(pw_engine_t));
    if(!e) {
        fclose(f);
        return NULL;
    }

    char line[1024];
    int lineno = 0;

    while(fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if(!*s || (*s == '#'))
            continue;

        char *fields[13];
        int nf = 0;
        char *save = NULL;
        for(char *tok = strtok_r(s, "\t", &save); tok && (nf < 13); tok = strtok_r(NULL, "\t", &save))
            fields[nf++] = tok;

        if((fields[0][0] == 'R') && ((nf == 12) || (nf == 13))) {
            rule_t r = {0};
            r.ref = atoi(fields[1]);
            r.set = (uint16_t) atoi(fields[2]);
            r.who = (uint8_t) atoi(fields[3]);
            r.uid = atoi(fields[4]);
            r.flags = (atoi(fields[5]) ? F_BLOCK : 0) | (atoi(fields[6]) ? F_REJECT : 0) |
                      (atoi(fields[9]) ? F_SUBS : 0);
            r.kind = (uint8_t) fields[7][0];
            r.proto = (uint8_t) atoi(fields[10]);
            r.port = (uint16_t) atoi(fields[11]);
            if(nf == 13) {
                int route = atoi(fields[12]);
                if(route == PW_ROUTE_DIRECT) r.flags |= F_ROUTE_DIRECT;
                else if(route == PW_ROUTE_UPSTREAM) r.flags |= F_ROUTE_UP;
            }

            char *value = fields[8];
            if(strcmp(value, "-") == 0)
                value = "";
            to_lower(value);

            if(add_rule(e, &r, value) < 0)
                goto oom;
        } else if((fields[0][0] == 'L') && (nf == 6)) {
            int n = load_list(e, fields[5], (uint16_t) atoi(fields[1]), atoi(fields[2]),
                              atoi(fields[3]) != 0, atoi(fields[4]) != 0);
            if(n < 0)
                log_w("pw: list %s not loaded", fields[5]);
        } else
            log_w("pw: invalid line %d", lineno);
    }

    fclose(f);
    log_i("pw: loaded %d rules (%d indexed, %d linear)", e->num_rules, e->table_used, e->num_linear);
    return e;

oom:
    fclose(f);
    snprintf(err, errlen, "out of memory");
    pw_engine_destroy(e);
    return NULL;
}

void pw_engine_destroy(pw_engine_t *e) {
    if(!e)
        return;
    free(e->rules);
    free(e->pool);
    free(e->table);
    free(e->linear);
    free(e);
}

int pw_engine_num_rules(const pw_engine_t *e) {
    return e ? e->num_rules : 0;
}

/* ******************************************************* */

typedef struct {
    int32_t idx[MAX_CANDIDATES];
    int n;
} candidates_t;

static void add_candidate(candidates_t *c, int32_t idx) {
    if(c->n < MAX_CANDIDATES)
        c->idx[c->n++] = idx;
}

static bool refine_ok(const rule_t *r, const pw_query_t *q) {
    if(r->proto && (r->proto != q->proto))
        return false;
    if(r->port && (r->port != q->port))
        return false;
    return true;
}

static bool who_ok(const rule_t *r, const pw_query_t *q) {
    if(r->who == 0)
        return true;
    if(q->dns_query)
        return true;   // evaluated separately, see pw_engine_eval
    return r->uid == q->uid;
}

static bool target_ok(const pw_engine_t *e, const rule_t *r, const pw_query_t *q) {
    switch(r->kind) {
        case KIND_ALL:
            return true;
        case KIND_COUNTRY:
            return q->country && q->country[0] && (strcasecmp(e->pool + r->str, q->country) == 0);
        case KIND_IP:
        case KIND_ASN:
            return q->ip && ip_in_cidr(r, q->ipver, q->ip);
        case KIND_DOMAIN:
            return q->host && q->host[0] &&
                   pw_match_domain(e->pool + r->str, q->host, r->flags & F_SUBS);
    }
    return false;
}

// true if a beats b
static bool better(const rule_t *a, const rule_t *b) {
    if(!b)
        return true;
    if(a->score != b->score)
        return a->score > b->score;
    // tie: block wins
    return (a->flags & F_BLOCK) && !(b->flags & F_BLOCK);
}

static pw_verdict_t verdict(const rule_t *r) {
    pw_verdict_t v = {
        .matched = true,
        .block = (r->flags & F_BLOCK) != 0,
        .reject = (r->flags & F_REJECT) != 0,
        .route = (r->flags & F_BLOCK) ? PW_ROUTE_DEFAULT :
                 (r->flags & F_ROUTE_DIRECT) ? PW_ROUTE_DIRECT : (r->flags & F_ROUTE_UP) ? PW_ROUTE_UPSTREAM : PW_ROUTE_DEFAULT,
        .ref = r->ref,
    };
    return v;
}

pw_verdict_t pw_engine_eval(const pw_engine_t *e, const pw_query_t *q) {
    pw_verdict_t none = {0};
    if(!e || !e->num_rules)
        return none;

    candidates_t c;
    c.n = 0;

    // literal domains: the host itself and every parent domain
    if(q->host && q->host[0] && e->table_cap) {
        char host[256];
        strncpy(host, q->host, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
        to_lower(host);

        const char *h = host;
        bool exact = true;
        while(h && *h) {
            int32_t *slot = table_slot((pw_engine_t*) e, h, false);
            if(slot) {
                for(int32_t i = *slot - 1; i >= 0; i = e->rules[i].next) {
                    const rule_t *r = &e->rules[i];
                    if((exact || (r->flags & F_SUBS)) && refine_ok(r, q) && who_ok(r, q))
                        add_candidate(&c, i);
                }
            }
            h = strchr(h, '.');
            if(h)
                h++;
            exact = false;
        }
    }

    for(int k = 0; k < e->num_linear; k++) {
        const rule_t *r = &e->rules[e->linear[k]];
        if(refine_ok(r, q) && who_ok(r, q) && target_ok(e, r, q))
            add_candidate(&c, e->linear[k]);
    }

    if(c.n == 0)
        return none;

    if(q->dns_query) {
        // The query comes from netd on behalf of some app. Do not block at DNS level if any
        // app/group allows this name: the connection itself will be checked with the real uid.
        for(int k = 0; k < c.n; k++) {
            const rule_t *r = &e->rules[c.idx[k]];
            if((r->who != 0) && !(r->flags & F_BLOCK) && (r->kind == KIND_DOMAIN))
                return none;
        }
    }

    // sets are numbered by priority; find the max set id among candidates
    int max_set = 0;
    for(int k = 0; k < c.n; k++)
        if(e->rules[c.idx[k]].set > max_set)
            max_set = e->rules[c.idx[k]].set;

    const rule_t *global_allow = NULL;

    for(int set = 0; set <= max_set; set++) {
        const rule_t *best[3] = {NULL, NULL, NULL};

        for(int k = 0; k < c.n; k++) {
            const rule_t *r = &e->rules[c.idx[k]];
            if(r->set != set)
                continue;
            if(q->dns_query && (r->who != 0))
                continue;
            if(better(r, best[r->who]))
                best[r->who] = r;
        }

        if(best[2])
            return verdict(best[2]);   // app
        if(best[1])
            return verdict(best[1]);   // app group

        if(!global_allow && best[0]) {
            if(best[0]->flags & F_BLOCK)
                return verdict(best[0]);
            // global allow: only app rules in lower sets can still block
            global_allow = best[0];
        }
    }

    return global_allow ? verdict(global_allow) : none;
}

/* ******************************************************* */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pw_engine_t *g_pending = NULL;
static bool g_has_pending = false;
static pw_engine_t *g_current = NULL;

int pw_fw_load(const char *path) {
    char err[128] = "";
    pw_engine_t *e = pw_engine_load(path, err, sizeof(err));
    if(!e) {
        log_e("pw: load failed: %s", err);
        return -1;
    }

    int n = e->num_rules;
    pthread_mutex_lock(&g_lock);
    if(g_pending)
        pw_engine_destroy(g_pending);
    g_pending = e;
    __atomic_store_n(&g_has_pending, true, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_lock);
    return n;
}

void pw_fw_clear(void) {
    pthread_mutex_lock(&g_lock);
    if(g_pending)
        pw_engine_destroy(g_pending);
    g_pending = NULL;
    __atomic_store_n(&g_has_pending, true, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_lock);
}

bool pw_fw_swap_pending(void) {
    if(!__atomic_load_n(&g_has_pending, __ATOMIC_ACQUIRE))
        return false;

    pthread_mutex_lock(&g_lock);
    pw_engine_t *old = g_current;
    g_current = g_pending;
    g_pending = NULL;
    __atomic_store_n(&g_has_pending, false, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_lock);

    if(old)
        pw_engine_destroy(old);
    return true;
}

const pw_engine_t* pw_fw_current(void) {
    return g_current;
}

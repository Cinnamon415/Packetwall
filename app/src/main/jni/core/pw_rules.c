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
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
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
#define MAX_HOST 256

/*
 * Lookup structures (all built at load time, read-only afterwards):
 *   literal  - hash: exact domain pattern -> chain of rules ("example.com", with or without subdomains)
 *   suffix   - hash: "x" of the patterns "*.x" (exactly one more label) and "**.x" (one or more)
 *   ipidx    - IP/CIDR/ASN rules sorted by (ipver, prefix, masked address): binary search per prefix
 *   linear   - everything else (other globs, countries, "all"): usually a handful of rules
 * so evaluating a connection costs O(labels + prefix lengths * log n + linear) instead of O(rules).
 */

typedef struct {
    int32_t ref;
    int32_t uid;
    uint32_t str;       // offset into the string pool (domain pattern / country)
    uint32_t key;       // offset of the hash key (the pattern, or its suffix after "*." / "**.")
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
    uint8_t extra;      // suffix rules: 1 = exactly one more label, 2 = one or more
    zdtun_ip_t ip;
} rule_t;

typedef struct {
    uint32_t *slots;    // rule index + 1, 0 = empty
    uint32_t cap;       // power of 2
    uint32_t used;
} htable_t;

struct pw_engine {
    rule_t *rules;
    int num_rules, rules_cap;

    char *pool;
    uint32_t pool_len, pool_cap;

    uint32_t seed;
    htable_t literal;
    htable_t suffix;

    int32_t *ipidx;     // rule indexes, sorted after loading
    int num_ip, ip_cap;
    uint8_t prefixes[2][129];   // [v4/v6][len]: 1 if some rule uses that prefix length

    int32_t *linear;
    int num_linear, linear_cap;

    int max_set;
};

/* ******************************************************* */

static uint32_t random_seed(void) {
    uint32_t seed = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(fd >= 0) {
        if(read(fd, &seed, sizeof(seed)) != sizeof(seed))
            seed = 0;
        close(fd);
    }
    if(!seed)
        seed = (uint32_t) time(NULL) ^ (uint32_t)(uintptr_t) &seed;
    return seed;
}

// FNV-1a over the key, then a seeded murmur3 finalizer: lists cannot be crafted to collide
static uint32_t key_hash(const pw_engine_t *e, const char *s) {
    uint32_t h = 2166136261u ^ e->seed;
    for(; *s; s++)
        h = (h ^ (uint8_t)*s) * 16777619u;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
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

static bool table_grow(pw_engine_t *e, htable_t *t) {
    uint32_t cap = t->cap ? t->cap * 2 : 1024;
    uint32_t *slots = calloc(cap, sizeof(uint32_t));
    if(!slots)
        return false;

    for(uint32_t i = 0; i < t->cap; i++) {
        if(t->slots[i]) {
            uint32_t j = key_hash(e, e->pool + e->rules[t->slots[i] - 1].key) & (cap - 1);
            while(slots[j])
                j = (j + 1) & (cap - 1);
            slots[j] = t->slots[i];
        }
    }
    free(t->slots);
    t->slots = slots;
    t->cap = cap;
    return true;
}

// slot holding the chain head for key, or NULL (create: an empty slot to fill)
static uint32_t* table_slot(const pw_engine_t *e, htable_t *t, const char *key, bool create) {
    if(create && ((t->used + 1) * 4 >= t->cap * 3)) {
        if(!table_grow((pw_engine_t*) e, t))
            return NULL;
    }
    if(!t->cap)
        return NULL;

    uint32_t mask = t->cap - 1;
    uint32_t i = key_hash(e, key) & mask;

    while(t->slots[i]) {
        if(strcmp(e->pool + e->rules[t->slots[i] - 1].key, key) == 0)
            return &t->slots[i];
        i = (i + 1) & mask;
    }
    return create ? &t->slots[i] : NULL;
}

static int32_t table_head(const pw_engine_t *e, const htable_t *t, const char *key) {
    uint32_t *slot = table_slot(e, (htable_t*) t, key, false);
    return slot ? (int32_t) *slot - 1 : -1;
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

static bool is_deep(const char *l, int len) {
    return (len == 2) && (l[0] == '*') && (l[1] == '*');
}

/*
 * Label-wise pattern match by dynamic programming (no backtracking, so hostile patterns like
 * "**.**.**...." cannot blow up): ok[i][j] = pattern labels i.. match host labels j.. .
 * '**' matches one or more labels. With subdomains the pattern may match any suffix of the host.
 */
bool pw_match_domain(const char *pattern, const char *host, bool subdomains) {
    const char *pl[MAX_LABELS], *hl[MAX_LABELS];
    int plen[MAX_LABELS], hlen[MAX_LABELS];
    int pn = split_labels(pattern, pl, plen);
    int hn = split_labels(host, hl, hlen);

    if((pn <= 0) || (hn <= 0))
        return false;

    // two rows are enough: row i depends only on row i + 1
    bool next[MAX_LABELS + 1], cur[MAX_LABELS + 1];
    for(int j = 0; j <= hn; j++)
        next[j] = (j == hn);   // empty pattern matches only the end of the host

    for(int i = pn - 1; i >= 0; i--) {
        bool deep = is_deep(pl[i], plen[i]);
        cur[hn] = false;
        for(int j = hn - 1; j >= 0; j--) {
            if(deep)
                cur[j] = next[j + 1] || cur[j + 1];
            else
                cur[j] = next[j + 1] && glob_label(pl[i], plen[i], hl[j], hlen[j]);
        }
        memcpy(next, cur, sizeof(bool) * (hn + 1));
    }

    if(next[0])
        return true;
    if(subdomains) {
        for(int k = 1; k < hn; k++)
            if(next[k])
                return true;
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

/* ******************************************************* */

static bool push_index(int32_t **arr, int *n, int *cap, int32_t v) {
    if(*n >= *cap) {
        int c = *cap ? *cap * 2 : 64;
        int32_t *a = realloc(*arr, c * sizeof(int32_t));
        if(!a)
            return false;
        *arr = a;
        *cap = c;
    }
    (*arr)[(*n)++] = v;
    return true;
}

// "*.x" / "**.x" with a literal x: index by x. Returns the suffix offset in value, or -1.
static int suffix_pattern(const char *value, uint8_t *extra) {
    int skip;
    if(strncmp(value, "**.", 3) == 0) {
        skip = 3;
        *extra = 2;
    } else if(strncmp(value, "*.", 2) == 0) {
        skip = 2;
        *extra = 1;
    } else
        return -1;
    if(!value[skip] || strchr(value + skip, '*'))
        return -1;
    return skip;
}

static int chain(pw_engine_t *e, htable_t *t, int idx, const char *key) {
    uint32_t *slot = table_slot(e, t, key, true);
    if(!slot)
        return -1;
    if(*slot == 0) {
        t->used++;
        *slot = idx + 1;
    } else {
        // prepend to the chain of rules with the same key
        e->rules[idx].next = (int32_t) *slot - 1;
        *slot = idx + 1;
    }
    return 0;
}

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
    if(r->who > 2)
        return 1;   // 0 = global, 1 = group, 2 = app
    enum { LINEAR, LITERAL, SUFFIX, IPIDX } where = LINEAR;

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
            where = IPIDX;
            break;
        case KIND_ASN:
            if(parse_cidr(value, &r->ip, &r->ipver, &r->prefix) < 0)
                return 1;
            r->score = final_score(200, r->proto, r->port);
            where = IPIDX;
            break;
        case KIND_DOMAIN: {
            if(!value[0] || (strlen(value) >= MAX_HOST))
                return 1;
            if(strchr(value, '*'))
                r->flags |= F_WILD;
            r->str = pool_add(e, value);
            if(r->str == UINT32_MAX)
                return -1;
            r->key = r->str;
            r->score = final_score(domain_score(value, r->flags & F_SUBS), r->proto, r->port);
            if(!(r->flags & F_WILD))
                where = LITERAL;
            else {
                int skip = suffix_pattern(value, &r->extra);
                if(skip > 0) {
                    r->key = r->str + skip;
                    if(r->flags & F_SUBS)
                        r->extra = 2;   // "*.x" plus its subdomains = one or more labels
                    where = SUFFIX;
                }
            }
            break;
        }
        default:
            return 1;
    }

    // ip rules: keep the masked address, so equal prefixes compare equal
    if(where == IPIDX) {
        uint8_t *a = (uint8_t*) &r->ip;
        int bytes = (r->ipver == 4) ? 4 : 16;
        for(int i = 0; i < bytes; i++) {
            int bits = r->prefix - i * 8;
            uint8_t mask = (bits >= 8) ? 0xFF : (bits <= 0) ? 0 : (uint8_t)(0xFF << (8 - bits));
            a[i] &= mask;
        }
        e->prefixes[r->ipver == 6][r->prefix] = 1;
    }

    int idx = e->num_rules++;
    e->rules[idx] = *r;
    if(r->set > e->max_set)
        e->max_set = r->set;

    switch(where) {
        case LITERAL:
            return chain(e, &e->literal, idx, value);
        case SUFFIX:
            return chain(e, &e->suffix, idx, e->pool + e->rules[idx].key);
        case IPIDX:
            return push_index(&e->ipidx, &e->num_ip, &e->ip_cap, idx) ? 0 : -1;
        default:
            return push_index(&e->linear, &e->num_linear, &e->linear_cap, idx) ? 0 : -1;
    }
}

static const pw_engine_t *g_sort_engine;   // qsort has no context argument; loads are serialized

static int ip_key_cmp(const rule_t *a, uint8_t ipver, uint8_t prefix, const zdtun_ip_t *ip) {
    if(a->ipver != ipver)
        return (a->ipver < ipver) ? -1 : 1;
    if(a->prefix != prefix)
        return (a->prefix < prefix) ? -1 : 1;
    return memcmp(&a->ip, ip, (ipver == 4) ? 4 : 16);
}

static int ip_rule_cmp(const void *x, const void *y) {
    const rule_t *a = &g_sort_engine->rules[*(const int32_t*)x];
    const rule_t *b = &g_sort_engine->rules[*(const int32_t*)y];
    return ip_key_cmp(a, b->ipver, b->prefix, &b->ip);
}

static pthread_mutex_t g_sort_lock = PTHREAD_MUTEX_INITIALIZER;

static void finish_index(pw_engine_t *e) {
    if(e->num_ip > 1) {
        pthread_mutex_lock(&g_sort_lock);
        g_sort_engine = e;
        qsort(e->ipidx, e->num_ip, sizeof(int32_t), ip_rule_cmp);
        g_sort_engine = NULL;
        pthread_mutex_unlock(&g_sort_lock);
    }
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
    e->seed = random_seed();

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
    finish_index(e);
    log_i("pw: loaded %d rules (%u literal, %u suffix, %d ip, %d linear)", e->num_rules, e->literal.used,
          e->suffix.used, e->num_ip, e->num_linear);
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
    free(e->literal.slots);
    free(e->suffix.slots);
    free(e->ipidx);
    free(e->linear);
    free(e);
}

int pw_engine_num_rules(const pw_engine_t *e) {
    return e ? e->num_rules : 0;
}

/* ******************************************************* */

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
        return true;   // evaluated separately, see consider()
    return r->uid == q->uid;
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

// The best matching rule per (set, who), kept while scanning: no cap on how many rules match.
typedef struct {
    const pw_engine_t *e;
    const pw_query_t *q;
    const rule_t *(*best)[3];   // [set][who]
    bool app_allows_name;       // dns query: some app/group allows the name
} scan_t;

static void consider(scan_t *s, int32_t idx) {
    const rule_t *r = &s->e->rules[idx];
    if(!refine_ok(r, s->q) || !who_ok(r, s->q))
        return;
    if(s->q->dns_query && (r->who != 0)) {
        // The query comes from netd on behalf of some app. Do not block at DNS level if any
        // app/group allows this name: the connection itself will be checked with the real uid.
        if(!(r->flags & F_BLOCK) && (r->kind == KIND_DOMAIN))
            s->app_allows_name = true;
        return;
    }
    const rule_t **slot = &s->best[r->set][r->who];
    if(better(r, *slot))
        *slot = r;
}

static void scan_ip(scan_t *s) {
    const pw_engine_t *e = s->e;
    const pw_query_t *q = s->q;
    if(!q->ip || !e->num_ip || ((q->ipver != 4) && (q->ipver != 6)))
        return;

    int v6 = (q->ipver == 6);
    int maxlen = v6 ? 128 : 32;
    for(int len = 0; len <= maxlen; len++) {
        if(!e->prefixes[v6][len])
            continue;
        zdtun_ip_t m = {0};
        memcpy(&m, q->ip, v6 ? 16 : 4);
        uint8_t *a = (uint8_t*) &m;
        for(int i = 0; i < (v6 ? 16 : 4); i++) {
            int bits = len - i * 8;
            a[i] &= (bits >= 8) ? 0xFF : (bits <= 0) ? 0 : (uint8_t)(0xFF << (8 - bits));
        }
        // lower bound of (ipver, len, m)
        int lo = 0, hi = e->num_ip;
        while(lo < hi) {
            int mid = (lo + hi) / 2;
            if(ip_key_cmp(&e->rules[e->ipidx[mid]], q->ipver, (uint8_t) len, &m) < 0)
                lo = mid + 1;
            else
                hi = mid;
        }
        for(int k = lo; k < e->num_ip; k++) {
            if(ip_key_cmp(&e->rules[e->ipidx[k]], q->ipver, (uint8_t) len, &m) != 0)
                break;
            consider(s, e->ipidx[k]);
        }
    }
}

static bool target_ok(const pw_engine_t *e, const rule_t *r, const pw_query_t *q, const char *host) {
    switch(r->kind) {
        case KIND_ALL:
            return true;
        case KIND_COUNTRY:
            return q->country && q->country[0] && (strcasecmp(e->pool + r->str, q->country) == 0);
        case KIND_DOMAIN:
            return host && pw_match_domain(e->pool + r->str, host, r->flags & F_SUBS);
    }
    return false;
}

pw_verdict_t pw_engine_eval(const pw_engine_t *e, const pw_query_t *q) {
    pw_verdict_t none = {0};
    if(!e || !e->num_rules)
        return none;

    // per-set table, reused across calls (only the capture thread evaluates; the host test is single-threaded)
    static const rule_t *(*best)[3] = NULL;
    static int best_cap = 0;
    if(e->max_set + 1 > best_cap) {
        int cap = e->max_set + 1;
        void *b = realloc(best, cap * sizeof(*best));
        if(!b)
            return none;
        best = b;
        best_cap = cap;
    }
    memset(best, 0, (e->max_set + 1) * sizeof(*best));
    scan_t s = { .e = e, .q = q, .best = best };

    // lowercase, without one trailing dot ("example.com." is the same name)
    char host_buf[MAX_HOST];
    const char *host = NULL;
    if(q->host && q->host[0]) {
        strncpy(host_buf, q->host, sizeof(host_buf) - 1);
        host_buf[sizeof(host_buf) - 1] = '\0';
        to_lower(host_buf);
        size_t n = strlen(host_buf);
        if(n && (host_buf[n - 1] == '.'))
            host_buf[n - 1] = '\0';
        if(host_buf[0])
            host = host_buf;
    }

    if(host) {
        // walk the host and its parent domains; extra = labels removed from the front
        const char *h = host;
        int extra = 0;
        while(h && *h) {
            for(int32_t i = table_head(e, &e->literal, h); i >= 0; i = e->rules[i].next) {
                if((extra == 0) || (e->rules[i].flags & F_SUBS))
                    consider(&s, i);
            }
            if(extra > 0) {
                for(int32_t i = table_head(e, &e->suffix, h); i >= 0; i = e->rules[i].next) {
                    if((e->rules[i].extra == 2) || (extra == 1))
                        consider(&s, i);
                }
            }
            h = strchr(h, '.');
            if(h)
                h++;
            extra++;
        }
    }

    scan_ip(&s);

    for(int k = 0; k < e->num_linear; k++) {
        const rule_t *r = &e->rules[e->linear[k]];
        if(refine_ok(r, q) && who_ok(r, q) && target_ok(e, r, q, host))
            consider(&s, e->linear[k]);
    }

    if(q->dns_query && s.app_allows_name)
        return none;

    // sets are numbered by priority (0 = highest)
    const rule_t *global_allow = NULL;
    for(int set = 0; set <= e->max_set; set++) {
        if(best[set][2])
            return verdict(best[set][2]);   // app
        if(best[set][1])
            return verdict(best[set][1]);   // app group

        if(!global_allow && best[set][0]) {
            if(best[set][0]->flags & F_BLOCK)
                return verdict(best[set][0]);
            // global allow: only app rules in lower sets can still block
            global_allow = best[set][0];
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

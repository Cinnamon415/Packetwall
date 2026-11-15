/*
 * This file is part of Packetwall.
 *
 * Packetwall is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Packetwall rule engine.
 *
 * Model (see docs/SPEC.md, section 2):
 *  - every rule belongs to a set; enabled sets are passed in priority order (0 = highest);
 *  - "who": global (0), app group (1), app (2). Groups are expanded to uids by the Java side;
 *  - "where": all, country, CIDR/IP, domain pattern (labels, '*' inside one label, '**' = any depth),
 *    optionally "+ subdomains"; protocol and port refine any target;
 *  - inside a set: app rules, then group rules, then global rules. The narrowest target wins,
 *    a tie blocks. The first set giving a decision wins;
 *  - a global allow only cancels global blocks: lower sets are still searched for app/group rules.
 */

#ifndef __PW_RULES_H__
#define __PW_RULES_H__

#include <stdbool.h>
#include <stdint.h>
#include "zdtun.h"

typedef struct pw_engine pw_engine_t;

typedef struct {
    bool matched;
    bool block;
    bool reject;
    int32_t ref;    // rule id (> 0) or -(set id) for blocklist entries
} pw_verdict_t;

typedef struct {
    int uid;
    uint8_t ipver;
    const zdtun_ip_t *ip;
    const char *host;      // may be NULL
    const char *country;   // may be NULL or ""
    uint8_t proto;         // IPPROTO_*
    uint16_t port;         // host order
    bool dns_query;        // a DNS query of an unattributed uid (netd/unknown)
} pw_query_t;

/* Parses a compiled rules file. Returns NULL on error. */
pw_engine_t* pw_engine_load(const char *path, char *err, int errlen);
void pw_engine_destroy(pw_engine_t *e);
int pw_engine_num_rules(const pw_engine_t *e);
pw_verdict_t pw_engine_eval(const pw_engine_t *e, const pw_query_t *q);

/* Matches a host against a pattern (exposed for tests). */
bool pw_match_domain(const char *pattern, const char *host, bool subdomains);

/* Global engine: loaded from any thread, swapped in by the capture thread. */
int pw_fw_load(const char *path);          // returns number of rules, < 0 on error
void pw_fw_clear(void);
bool pw_fw_swap_pending(void);             // capture thread only; true if the engine changed
const pw_engine_t* pw_fw_current(void);    // capture thread only

#endif

#ifndef __QUERY_GETDNS_H__
#define __QUERY_GETDNS_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "tlsardata.h"

/*
 * Flags: dns bogus or indeterminate; authenticate responses
 */

extern int dns_bogus_or_indeterminate;
extern int address_authenticated;
extern int v4_authenticated;
extern int v6_authenticated;
extern int mx_authenticated;
extern int srv_authenticated;
extern int tlsa_authenticated;

/*
 * qinfo: structure to hold query information to be passed to
 * callback functions.
 */
typedef struct qinfo {
    const char *qname;
    uint16_t qtype;
    uint16_t port;
} qinfo;


/*
 * addresses: (head of) linked list of addrinfo structures
 */

extern size_t address_count;

extern struct addrinfo *addresses;

struct addrinfo *
insert_addrinfo(struct addrinfo *current, struct addrinfo *new);


/*
 * tlsa_count: count of TLSA records.
 */

extern size_t tlsa_count;

int do_dns_queries(const char *hostname, uint16_t port);

extern tlsa_rdata *tlsa_rdata_list;

#endif /* __QUERY_GETDNS_H__ */

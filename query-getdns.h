#ifndef __QUERY_GETDNS_H__
#define __QUERY_GETDNS_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/*
 * qinfo: structure to hold query information to be passed to
 * callback functions.
 */
typedef struct qinfo {
    char *qname;
    uint16_t qtype;
    uint16_t port;
} qinfo;


/*
 * addresses: (head of) linked list of addrinfo structures
 */

struct addrinfo *addresses;

struct addrinfo *
insert_addrinfo(struct addrinfo *current, struct addrinfo *new);


/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * tlsa_rdata_list: linked list of tlsa_rdata structures.
 */

size_t tlsa_count;

typedef struct tlsa_rdata {
    uint8_t usage;
    uint8_t selector;
    uint8_t mtype;
    unsigned long data_len;
    uint8_t *data;
    struct tlsa_rdata *next;
} tlsa_rdata;

tlsa_rdata *tlsa_rdata_list;

tlsa_rdata *insert_tlsa_rdata(tlsa_rdata *current, tlsa_rdata *new);
void free_tlsa(tlsa_rdata *head);

int do_dns_queries(char *hostname, char *port);

#endif /* __QUERY_GETDNS_H__ */

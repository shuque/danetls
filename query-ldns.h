/*
 * query-ldns.h
 *
 */

#ifndef __QUERY_LDNS_H__
#define __QUERY_LDNS_H__

#include <ldns/ldns.h>


/*
 * Flags: dns bogus or indeterminate; authenticated responses 
 */

int dns_bogus_or_indeterminate;
int v4_authenticated;
int v6_authenticated;
int mx_authenticated;
int srv_authenticated;
int tlsa_authenticated;

/*
 * addresses: (head of) linked list of addrinfo structures
 */

size_t address_count;

struct addrinfo *
insert_addrinfo(struct addrinfo **headp,
		struct addrinfo *current, struct addrinfo *new);


/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * insert_tlsa_rdata(): insert node at tail of linked list of tlsa_rdata.
 * free_tlsa(): free memory in the linked list.
 */

size_t tlsa_count;
ldns_pkt_rcode tlsa_response_rcode;

typedef struct tlsa_rdata {
    uint8_t usage;
    uint8_t selector;
    uint8_t mtype;
    unsigned long data_len;
    uint8_t *data;
    struct tlsa_rdata *next;
} tlsa_rdata;

tlsa_rdata *
insert_tlsa_rdata(tlsa_rdata **headp, tlsa_rdata *current, tlsa_rdata *new);

void free_tlsa(tlsa_rdata *head);


/*
 * get_addresses_type() and get_addresses()
 */

ldns_rr_list *get_addresses_type(ldns_resolver *resolver,
                                 ldns_rr_type rrtype,
                                 ldns_rdf *host_rdf);

struct addrinfo *get_addresses(ldns_resolver *resolver,
			       const char *hostname, uint16_t port);


/*
 * get_tlsa(): get TLSA records. 
 * Populates tlsa_rdata_list linked list with TLSA record rdata.
 */

tlsa_rdata *get_tlsa(ldns_resolver *resolver, 
		     const char *hostname, uint16_t port);

ldns_resolver *get_resolver(char *conffile);

#endif /* __QUERY_LDNS_H__ */

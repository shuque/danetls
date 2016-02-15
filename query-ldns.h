/*
 * query-ldns.h
 *
 */

#ifndef __QUERY_LDNS_H__
#define __QUERY_LDNS_H__

#include <ldns/ldns.h>


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
 * get_tlsa(): get TLSA records. 
 * Populates tlsa_rdata_list linked list with TLSA record rdata.
 */

tlsa_rdata *get_tlsa(const char *hostname, const char *port);

#endif /* __QUERY_LDNS_H__ */

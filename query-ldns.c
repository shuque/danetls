/*
 * query-ldns.c
 *
 * Query DNS TLSA records with libldns
 *
 * Author: Shumon Huque <shuque@gmail.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ldns/ldns.h>
#include "query-ldns.h"

/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * insert_tlsa_rdata(): insert node at tail of linked list of tlsa_rdata.
 * free_tlsa(): free memory in the linked list.
 */

size_t tlsa_count = 0;

tlsa_rdata *
insert_tlsa_rdata(tlsa_rdata **headp, tlsa_rdata *current, tlsa_rdata *new)
{
    if (current == NULL)
        *headp = new;
    else
        current->next = new;
    return new;
}

void free_tlsa(tlsa_rdata *head)
{
    tlsa_rdata *current;

    while ((current = head) != NULL) {
	head = head->next;
	LDNS_FREE(current->data);              /* right call? */
	free(current);
    }
    return;
}


/*
 * get_tlsa(): get TLSA records. 
 * Populates tlsa_rdata_list linked list with TLSA record rdata.
 */

tlsa_rdata *get_tlsa(const char *hostname, const char *port)
{
    size_t i;
    char domainstring[512];
    ldns_resolver *resolver;
    ldns_rdf *tlsa_owner;
    ldns_pkt *ldns_p;
    ldns_rr_list *tlsa_rr_list;
    ldns_rr *tlsa_rr;
    ldns_status ldns_rc;
    tlsa_rdata *tlsa_rdata_list = NULL;

    snprintf(domainstring, 512, "_%s._tcp.%s", port, hostname);
    tlsa_owner = ldns_dname_new_frm_str(domainstring);
    ldns_rc = ldns_resolver_new_frm_file(&resolver, NULL);
    if (ldns_rc != LDNS_STATUS_OK) {
	fprintf(stderr, "ldns_resolver_new_frm_file() failed: %s\n",
		ldns_get_errorstr_by_id(ldns_rc));
	return NULL;
    }

    ldns_p = ldns_resolver_query(resolver,
				 tlsa_owner,
				 LDNS_RR_TYPE_TLSA,
				 LDNS_RR_CLASS_IN,
				 LDNS_RD | LDNS_AD);
    if (ldns_p == (ldns_pkt *) NULL) {
	fprintf(stderr, "ldns_resolver_query() failed.\n");
        return NULL;
    }

    tlsa_rr_list = ldns_pkt_rr_list_by_type(ldns_p,
					    LDNS_RR_TYPE_TLSA,
					    LDNS_SECTION_ANSWER);

    if (tlsa_rr_list == NULL) {
	return NULL;
    }

    if (! ldns_pkt_ad(ldns_p)) {
	fprintf(stderr, "Unauthenticated response for TLSA record.\n");
	return NULL;
    }

    /* Extract list of RDATA fields from TLSA rrset */
    tlsa_count = ldns_rr_list_rr_count(tlsa_rr_list);
    tlsa_rdata *current = tlsa_rdata_list;
    for (i = 0; i < tlsa_count; i++) {
	tlsa_rdata *rp = (tlsa_rdata *) malloc(sizeof(tlsa_rdata));
	tlsa_rr = ldns_rr_list_rr(tlsa_rr_list, i);
	rp->usage = ldns_rdf2native_int8(ldns_rr_rdf(tlsa_rr, 0));
	rp->selector = ldns_rdf2native_int8(ldns_rr_rdf(tlsa_rr, 1));
	rp->mtype = ldns_rdf2native_int8(ldns_rr_rdf(tlsa_rr, 2));
	rp->data_len = ldns_rdf_size(ldns_rr_rdf(tlsa_rr, 3));
	rp->data = ldns_rdf_data(ldns_rr_rdf(tlsa_rr, 3));
	rp->next = NULL;
	current = insert_tlsa_rdata(&tlsa_rdata_list, current, rp);
    }

    return tlsa_rdata_list;
}


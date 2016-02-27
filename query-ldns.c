/*
 * query-ldns.c
 *
 * Query Address and TLSA records with libldns
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
 * bogus/indeterminate flag.
 */

int dns_bogus_or_indeterminate = 0;

/*
 * Linked list of addrinfo structures and related metadata
 */

size_t address_count = 0;
int v4_authenticated = 0, v6_authenticated = 0;

struct addrinfo *
insert_addrinfo(struct addrinfo **headp,
		struct addrinfo *current, struct addrinfo *new)
{
    if (current == NULL)
        *headp = new;
    else
        current->ai_next = new;
    return new;
}


/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * insert_tlsa_rdata(): insert node at tail of linked list of tlsa_rdata.
 * free_tlsa(): free memory in the linked list.
 */

size_t tlsa_count = 0;
int tlsa_authenticated = 0;

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
	LDNS_FREE(current->data);
	free(current);
    }
    return;
}


/*
 * get_addresses_type()
 */

ldns_rr_list *get_addresses_type(ldns_resolver *resolver,
				 ldns_rr_type rrtype,
				 const char *hostname)
{
    ldns_rdf *hostname_rdf;
    ldns_pkt *ldns_p;
    ldns_pkt_rcode rcode;

    hostname_rdf = ldns_dname_new_frm_str(hostname);

    ldns_p = ldns_resolver_query(resolver, hostname_rdf, rrtype,
				 LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD);
    ldns_rdf_deep_free(hostname_rdf);

    if (ldns_p == (ldns_pkt *) NULL) {
        dns_bogus_or_indeterminate = 1;
	fprintf(stderr, "No response to address query.\n");
        return NULL;
    }

    rcode = ldns_pkt_get_rcode(ldns_p);

    switch (rcode) {
    case LDNS_RCODE_NOERROR:
    case LDNS_RCODE_NXDOMAIN:
	break;
    default:
	dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "Error: address query failed; rcode=%d.\n", rcode);
        ldns_pkt_free(ldns_p);
        return NULL;
    }

    if (ldns_pkt_ad(ldns_p)) {
	if (rrtype == LDNS_RR_TYPE_AAAA)
	    v6_authenticated = 1;
	else if (rrtype == LDNS_RR_TYPE_A)
	    v4_authenticated = 1;
    }

    return ldns_pkt_rr_list_by_type(ldns_p, rrtype, LDNS_SECTION_ANSWER);

}

/*
 * get_tlsa(): get TLSA records. 
 * Populates tlsa_rdata_list linked list with TLSA record rdata.
 */

struct addrinfo *get_addresses(ldns_resolver *resolver,
			       const char *hostname, const char *port)
{
    size_t i;
    ldns_rr_list *rr_list;
    ldns_rr *rr;
    ldns_rr_type rrtype;
    struct addrinfo *addresses = NULL, *current = NULL;

    rr_list = get_addresses_type(resolver, LDNS_RR_TYPE_AAAA, hostname);
    if (!rr_list)
	rr_list = get_addresses_type(resolver, LDNS_RR_TYPE_A, hostname);
    else
	(void) ldns_rr_list_cat(rr_list, 
				get_addresses_type(resolver, 
						   LDNS_RR_TYPE_A, hostname));

    address_count = ldns_rr_list_rr_count(rr_list);

    for (i = 0; i < address_count; i++) {
	struct addrinfo *aip = malloc(sizeof(struct addrinfo));
	aip->ai_next = NULL;
	rr = ldns_rr_list_rr(rr_list, i);
	rrtype = ldns_rr_get_type(rr);
	if (rrtype == LDNS_RR_TYPE_AAAA) {
	    struct sockaddr_in6 *sa6 = malloc(sizeof(struct sockaddr_storage));
	    aip->ai_family = sa6->sin6_family = AF_INET6;
	    sa6->sin6_port = htons(atoi(port));
	    memcpy(&(sa6->sin6_addr), 
		   ldns_rdf_data(ldns_rr_rdf(rr, 0)), 
		   ldns_rdf_size(ldns_rr_rdf(rr, 0)));
	    aip->ai_addr = (struct sockaddr *) sa6;
	    aip->ai_addrlen = sizeof(struct sockaddr_in6);
	} else if (rrtype == LDNS_RR_TYPE_A) {
	    struct sockaddr_in *sa4 = malloc(sizeof(struct sockaddr_storage));
	    aip->ai_family = sa4->sin_family = AF_INET;
	    sa4->sin_port = htons(atoi(port));
	    memcpy(&(sa4->sin_addr), 
		   ldns_rdf_data(ldns_rr_rdf(rr, 0)), 
		   ldns_rdf_size(ldns_rr_rdf(rr, 0)));
	    aip->ai_addr = (struct sockaddr *) sa4;
	    aip->ai_addrlen = sizeof(struct sockaddr_in);
	}
	current = insert_addrinfo(&addresses, current, aip);
    }

    return addresses;
}


/*
 * get_tlsa(): get TLSA records. 
 * Populates tlsa_rdata_list linked list with TLSA record rdata.
 */

tlsa_rdata *get_tlsa(ldns_resolver *resolver,
		     const char *hostname, const char *port)
{
    size_t i;
    char domainstring[512];
    ldns_rdf *tlsa_owner;
    ldns_pkt *ldns_p;
    ldns_rr_list *tlsa_rr_list;
    ldns_rr *tlsa_rr;
    ldns_pkt_rcode rcode;
    tlsa_rdata *tlsa_rdata_list = NULL, *current = NULL;

    snprintf(domainstring, sizeof(domainstring), "_%s._tcp.%s", port, hostname);
    tlsa_owner = ldns_dname_new_frm_str(domainstring);

    ldns_p = ldns_resolver_query(resolver, tlsa_owner, LDNS_RR_TYPE_TLSA,
				 LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD);
    ldns_rdf_deep_free(tlsa_owner);

    if (ldns_p == (ldns_pkt *) NULL) {
        dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "No response to TLSA query.\n");
        return NULL;
    }

    rcode = ldns_pkt_get_rcode(ldns_p);

    switch (rcode) {
    case LDNS_RCODE_NOERROR:
	break;
    case LDNS_RCODE_NXDOMAIN:
        fprintf(stderr, "No TLSA records found.\n");
        ldns_pkt_free(ldns_p);
        return NULL;
    default:
	dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "Error: TLSA query failed; rcode=%d.\n", rcode);
        ldns_pkt_free(ldns_p);
        return NULL;
    }

    tlsa_rr_list = ldns_pkt_rr_list_by_type(ldns_p,
					    LDNS_RR_TYPE_TLSA,
					    LDNS_SECTION_ANSWER);

    if (tlsa_rr_list == NULL) {
        fprintf(stderr, "No TLSA records found.\n");
        ldns_pkt_free(ldns_p);
	return NULL;
    }

    if (! ldns_pkt_ad(ldns_p)) {
	fprintf(stderr, "Unauthenticated response for TLSA record set.\n");
        ldns_pkt_free(ldns_p);
        return NULL;
    }
    tlsa_authenticated = 1;

    /* Extract list of RDATA fields from TLSA rrset */
    tlsa_count = ldns_rr_list_rr_count(tlsa_rr_list);
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

    ldns_pkt_free(ldns_p);
    return tlsa_rdata_list;
}


/*
 * get_resolver()
 */

ldns_resolver *get_resolver(void)
{
    ldns_resolver *resolver;
    ldns_status ldns_rc;

    ldns_rc = ldns_resolver_new_frm_file(&resolver, NULL);
    if (ldns_rc != LDNS_STATUS_OK) {
	fprintf(stderr, "failed to initialize DNS resolver: %s\n",
		ldns_get_errorstr_by_id(ldns_rc));
	return NULL;
    }

    return resolver;
}


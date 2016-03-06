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
#include "utils.h"


/*
 * Flags: dns bogus or indeterminate; authenticated responses
 */

int dns_bogus_or_indeterminate = 0;
int v4_authenticated = 0;
int v6_authenticated = 0;
int mx_authenticated = 0;
int srv_authenticated = 0;
int tlsa_authenticated = 0;


/*
 * Linked list of addrinfo structures and related metadata
 */

size_t address_count = 0;

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
 * print_tlsa() - print TLSA record rdata set
 */

void print_tlsa(tlsa_rdata *tlist)
{
    char *cp;
    tlsa_rdata *rp;

    if (tlist) {
        fprintf(stdout, "\nTLSA records found: %ld\n", tlsa_count);
        for (rp = tlist; rp != NULL; rp = rp->next) {
            fprintf(stdout, "TLSA: %d %d %d %s\n", rp->usage, rp->selector,
                    rp->mtype, (cp = bin2hexstring(rp->data, rp->data_len)));
            free(cp);
        }
	(void) fputc('\n', stdout);
    }

    return;
}


/*
 * rrlist_cat()
 */

void rrlist_cat(ldns_rr_list **dest, ldns_rr_list *rr_list)
{

    if (*dest == NULL)
	*dest = rr_list;
    else
        (void) ldns_rr_list_cat(*dest, rr_list);

    return;
}


/*
 * load_address()
 */

struct addrinfo *load_address(struct addrinfo **headp, struct addrinfo *cur, 
			      ldns_rr *rr, uint16_t port)
{
    ldns_rr_type rrtype = ldns_rr_get_type(rr);
    struct addrinfo *aip = malloc(sizeof(struct addrinfo));

    aip->ai_flags = 0;
    aip->ai_canonname = NULL;
    aip->ai_next = NULL;
    if (rrtype == LDNS_RR_TYPE_AAAA) {
        struct sockaddr_in6 *sa6 = malloc(sizeof(struct sockaddr_storage));
        aip->ai_family = sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        memcpy(&(sa6->sin6_addr),
               ldns_rdf_data(ldns_rr_rdf(rr, 0)),
               ldns_rdf_size(ldns_rr_rdf(rr, 0)));
        aip->ai_addr = (struct sockaddr *) sa6;
        aip->ai_addrlen = sizeof(struct sockaddr_in6);
    } else if (rrtype == LDNS_RR_TYPE_A) {
        struct sockaddr_in *sa4 = malloc(sizeof(struct sockaddr_storage));
        aip->ai_family = sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        memcpy(&(sa4->sin_addr),
               ldns_rdf_data(ldns_rr_rdf(rr, 0)),
               ldns_rdf_size(ldns_rr_rdf(rr, 0)));
        aip->ai_addr = (struct sockaddr *) sa4;
        aip->ai_addrlen = sizeof(struct sockaddr_in);
    }

    return insert_addrinfo(headp, cur, aip);
}


/*
 * load_addresses()
 * load addresses from an ldns_rr_list structure containing address RRs
 * into the addresses linked list.
 */

struct addrinfo *load_addresses(ldns_rr_list *rr_list, uint16_t port)
{
    size_t i;
    ldns_rr *rr;
    struct addrinfo *addresses = NULL, *current = NULL;

    address_count = ldns_rr_list_rr_count(rr_list);

    for (i = 0; i < address_count; i++) {
        rr = ldns_rr_list_rr(rr_list, i);
        current = load_address(&addresses, current, rr, port);
    }

    return addresses;
}


/*
 * get_addresses_type()
 */

ldns_rr_list *get_addresses_type(ldns_resolver *resolver,
				 ldns_rr_type rrtype,
				 ldns_rdf *host_rdf)
{
    ldns_pkt *ldns_p;
    ldns_pkt_rcode rcode;

    ldns_p = ldns_resolver_query(resolver, host_rdf, rrtype,
				 LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD);

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
 * get_addresses()
 * Obtain IPv4 and IPv6 addresses and populate addresses linked list.
 */

struct addrinfo *get_addresses(ldns_resolver *resolver,
			       const char *hostname, uint16_t port)
{
    ldns_rdf *host_rdf;
    ldns_rr_list *rr_list = NULL;

    host_rdf = ldns_dname_new_frm_str(hostname);

    rrlist_cat(&rr_list,
	       get_addresses_type(resolver, LDNS_RR_TYPE_AAAA, host_rdf));
    rrlist_cat(&rr_list,
	       get_addresses_type(resolver, LDNS_RR_TYPE_A, host_rdf));
    ldns_rdf_deep_free(host_rdf);

    return load_addresses(rr_list, port);
}


/*
 * get_tlsa(): get TLSA records. 
 * Populates tlsa_rdata_list linked list with TLSA record rdata.
 */

tlsa_rdata *get_tlsa(ldns_resolver *resolver,
		     const char *hostname, uint16_t port)
{
    size_t i;
    char domainstring[512];
    ldns_rdf *tlsa_owner;
    ldns_pkt *ldns_p;
    ldns_rr_list *tlsa_rr_list;
    ldns_rr *tlsa_rr;
    ldns_pkt_rcode rcode;
    tlsa_rdata *tlsa_rdata_list = NULL, *current = NULL;

    snprintf(domainstring, sizeof(domainstring), "_%d._tcp.%s", port, hostname);
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

    tlsa_rr_list = ldns_pkt_rr_list_by_type(ldns_p, LDNS_RR_TYPE_TLSA,
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
 * Initialize an ldns resolver. If conffile is NULL, then the system
 * default resolver configuration is used (typically /etc/resolv.conf).
 */

ldns_resolver *get_resolver(char *conffile)
{
    ldns_resolver *resolver;
    ldns_status ldns_rc;

    ldns_rc = ldns_resolver_new_frm_file(&resolver, conffile);
    if (ldns_rc != LDNS_STATUS_OK) {
	fprintf(stderr, "failed to initialize DNS resolver: %s\n",
		ldns_get_errorstr_by_id(ldns_rc));
	return NULL;
    }

    return resolver;
}


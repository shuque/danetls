/*
 * query_getdns.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <getdns/getdns_ext_libevent.h>
#ifdef HAVE_EVENT2_EVENT_H
    #include <event2/event.h>
#else
    #include <event.h>
#endif

#include "common.h"
#include "query-getdns.h"

extern int debug;
extern int recursion;
extern enum AUTH_MODE auth_mode;


/*
 * bogus/indeterminate flag.
 */

int dns_bogus_or_indeterminate = 0;
int address_authenticated = 0;
int v4_authenticated = 0;
int v6_authenticated = 0;
int mx_authenticated = 0;
int srv_authenticated = 0;
int tlsa_authenticated = 0;

/*
 * addresses: (head of) linked list of addrinfo structures
 */

size_t address_count = 0;
struct addrinfo *addresses = NULL;

struct addrinfo *
insert_addrinfo(struct addrinfo *current, struct addrinfo *new)
{
    if (current == NULL)
        addresses = new;
    else
        current->ai_next = new;
    return new;
}

struct addrinfo *make_addrinfo(getdns_dict *address, 
			       const char *hostname, uint16_t port)
{
    getdns_return_t rc;
    getdns_bindata *addr_type, *addr_data;
    struct addrinfo *aip = NULL;

    if ((rc = getdns_dict_get_bindata(address, "address_type",
				      &addr_type))) {
	fprintf(stderr, "FAIL: %s: getting addr_type: %s\n",
		hostname, getdns_get_errorstr_by_id(rc));
	return NULL;
    }

    if ((rc = getdns_dict_get_bindata(address, "address_data",
				      &addr_data))) {
	fprintf(stderr, "FAIL: %s: getting addr_data: %s\n",
		hostname, getdns_get_errorstr_by_id(rc));
	return NULL;
    }

    aip = malloc(sizeof(struct addrinfo));
    aip->ai_flags = 0;
    aip->ai_canonname = NULL;
    aip->ai_next = NULL;

    if (!strncmp((const char *) addr_type->data, "IPv4", 4)) {
	struct sockaddr_in *sa4 = malloc(sizeof(struct sockaddr_storage));
	aip->ai_family = sa4->sin_family = AF_INET;
	sa4->sin_port = htons(port);
	memcpy(&(sa4->sin_addr), addr_data->data, addr_data->size);
	aip->ai_addr = (struct sockaddr *) sa4;
	aip->ai_addrlen = sizeof(struct sockaddr_in);
    } else if (!strncmp((const char *) addr_type->data, "IPv6", 4)) {
	struct sockaddr_in6 *sa6 = malloc(sizeof(struct sockaddr_storage));
	aip->ai_family = sa6->sin6_family = AF_INET6;
	sa6->sin6_port = htons(port);
	memcpy(&(sa6->sin6_addr), addr_data->data, addr_data->size);
	aip->ai_addr = (struct sockaddr *) sa6;
	aip->ai_addrlen = sizeof(struct sockaddr_in6);
    } else  {
	/* shouldn't get here */
	fprintf(stderr, "FAIL: Unknown address type\n");
        free(aip);
	return NULL;
    }
    return aip;
}


/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * tlsa_rdata_list: linked list of tlsa_rdata structures.
 */

size_t tlsa_count = 0;
tlsa_rdata *tlsa_rdata_list = NULL;

tlsa_rdata *
insert_tlsa_rdata(tlsa_rdata *current, tlsa_rdata *new)
{
    if (current == NULL)
        tlsa_rdata_list = new;
    else
        current->next = new;
    return new;
}

void free_tlsa(tlsa_rdata *head)
{
    tlsa_rdata *current;

    while ((current = head) != NULL) {
        head = head->next;
        free(current->data);
        free(current);
    }
    return;
}


#define UNUSED_PARAM(x) ((void) (x))


/*
 * all_responses_secure()
 */

int all_responses_secure(getdns_dict *response)
{
    size_t i, cnt_reply = 0, cnt_secure = 0;
    uint32_t dnssec_status;
    getdns_return_t rc;
    getdns_list *replies_tree;
    getdns_dict *reply;

    if ((rc = getdns_dict_get_list(response, "replies_tree", &replies_tree))) {
        fprintf(stderr, "FAIL getting replies from responsedict: %s\n",
                getdns_get_errorstr_by_id(rc));
        return 0;
    }

    (void) getdns_list_get_length(replies_tree, &cnt_reply);
    if (cnt_reply == 0) {
	dns_bogus_or_indeterminate = 1;
	return 0;
    }

    for (i = 0; i < cnt_reply; i++) {

        if ((rc = getdns_list_get_dict(replies_tree, i, &reply))) {
            fprintf(stderr, "FAIL: getting reply from response dict: %s\n",
                    getdns_get_errorstr_by_id(rc));
            return 0;
        }

        if ((rc = getdns_dict_get_int(reply, "dnssec_status", &dnssec_status))) {
            fprintf(stderr, "FAIL: error obtaining dnssec status: %s\n",
                    getdns_get_errorstr_by_id(rc));
            return 0;
        }

	switch (dnssec_status) {
        case GETDNS_DNSSEC_SECURE:
            cnt_secure++;
            break;
        case GETDNS_DNSSEC_INSECURE:
            break;
        default:
            dns_bogus_or_indeterminate = 1;
        }

    }

    if (cnt_reply > 0 && cnt_secure == cnt_reply)
	return 1;
    else {
	if (cnt_reply == 0)
	    dns_bogus_or_indeterminate = 1;
	return 0;
    }
}


/*
 * callback function for address lookups
 */

void cb_address(getdns_context *ctx,
		getdns_callback_type_t cb_type,
		getdns_dict *response, 
		void *userarg,
		getdns_transaction_t tid)
{
    UNUSED_PARAM(ctx);
    getdns_return_t rc;
    uint32_t status=0;
    qinfo *qip = (qinfo *) userarg;
    const char *hostname = qip->qname;
    uint16_t port = qip->port;
    getdns_list    *just_addresses;
    size_t         cnt_addr;
    getdns_dict    *address;

    switch (cb_type) {
    case GETDNS_CALLBACK_COMPLETE:
	break;
    case GETDNS_CALLBACK_CANCEL:
    case GETDNS_CALLBACK_TIMEOUT:
    case GETDNS_CALLBACK_ERROR:
    default:
	fprintf(stderr, "Callback address fail: %s, tid=%"PRIu64" rc=%d\n",
		hostname, tid, cb_type);
	return;
    }

    /*
     * Check authenticated status of responses; set dns_bogus_indeterminate flag
     */
    if (all_responses_secure(response)) {
	address_authenticated = 1;
	v4_authenticated = 1;
	v6_authenticated = 1 ;
    }

    (void) getdns_dict_get_int(response, "status", &status);

    switch (status) {
    case GETDNS_RESPSTATUS_GOOD:
	break;
    case GETDNS_RESPSTATUS_NO_NAME:
	fprintf(stderr, "FAIL: %s: Non existent domain name.\n", hostname);
	goto cleanup;
    case GETDNS_RESPSTATUS_ALL_TIMEOUT:
	dns_bogus_or_indeterminate = 1;
	fprintf(stderr, "FAIL: %s: Query timed out.\n", hostname);
	goto cleanup;
    case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
	fprintf(stderr, "%s: Insecure address records.\n", hostname);
	goto cleanup;
    case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
	dns_bogus_or_indeterminate = 1;
	fprintf(stderr, "FAIL: %s: All bogus answers.\n", hostname);
	goto cleanup;	
    default:
        dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "FAIL: %s: error status code: %d.\n", hostname, status);
        goto cleanup;
    }

    if ((rc = getdns_dict_get_list(response, "just_address_answers", 
				   &just_addresses))) {
	fprintf(stderr, "FAIL: getting addresses from responsedict: %s\n",
		getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    if ((rc = getdns_list_get_length(just_addresses, &cnt_addr))) {
	fprintf(stderr, "FAIL: getting address lengths list: %s\n", 
		getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    if (cnt_addr <= 0) {
	printf("FAIL: %s: No addresses found.\n", hostname);
	goto cleanup;
    }

    size_t i;
    struct addrinfo *current = addresses;

    for (i = 0; i < cnt_addr; i++) {

	struct addrinfo *aip = NULL;
	if ((rc = getdns_list_get_dict(just_addresses, i, &address))) {
	    fprintf(stderr, "FAIL: %s: getting address dict: %s\n", 
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}
	aip = make_addrinfo(address, hostname, port);
	if (! aip)
	    continue;
	current = insert_addrinfo(current, aip);

    }

cleanup:
    free(qip);
    getdns_dict_destroy(response);
    return;
}


/*
 * callback function for tlsa lookups
 */

void cb_tlsa(getdns_context *ctx,
	     getdns_callback_type_t cb_type,
	     getdns_dict *response, 
	     void *userarg,
	     getdns_transaction_t tid)
{
    UNUSED_PARAM(ctx);
    getdns_return_t rc;
    uint32_t status=0, dstatus=0;
    qinfo *qip = (qinfo *) userarg;
    const char *hostname = qip->qname;
    getdns_list    *replies_tree, *answer;
    size_t         i, j, num_replies, num_answers;
    getdns_dict    *reply;

    switch (cb_type) {
    case GETDNS_CALLBACK_COMPLETE:
        break;
    case GETDNS_CALLBACK_CANCEL:
    case GETDNS_CALLBACK_TIMEOUT:
    case GETDNS_CALLBACK_ERROR:
    default:
        fprintf(stderr, "Callback address fail: %s/TLSA, tid=%"PRIu64" rc=%d\n",
                hostname, tid, cb_type);
	return;
    }

    (void) getdns_dict_get_int(response, "status", &status);

    switch (status) {
    case GETDNS_RESPSTATUS_GOOD:
        break;
    case GETDNS_RESPSTATUS_NO_NAME:
        fprintf(stderr, "FAIL: %s: Non existent domain name.\n", hostname);
        goto cleanup;
    case GETDNS_RESPSTATUS_ALL_TIMEOUT:
        dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "FAIL: %s: Query timed out.\n", hostname);
        goto cleanup;
    case GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
        fprintf(stderr, "%s: Insecure address records.\n", hostname);
	goto cleanup;
    case GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS:
        dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "FAIL: %s: All bogus answers.\n", hostname);
        goto cleanup;
    default:
        dns_bogus_or_indeterminate = 1;
        fprintf(stderr, "FAIL: %s: error status code: %d.\n", hostname, status);
        goto cleanup;
    }

    if ((rc = getdns_dict_get_list(response, "replies_tree", 
				   &replies_tree))) {
	fprintf(stderr, "FAIL %s/TLSA: getting replies from responsedict: %s\n",
		hostname, getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    (void) getdns_list_get_length(replies_tree, &num_replies);

    if (num_replies <= 0) {
	printf("FAIL: %s: No response to TLSA query.\n", hostname);
	dns_bogus_or_indeterminate = 1;
	goto cleanup;
    }

    tlsa_rdata *current = tlsa_rdata_list;
    size_t auth_count = 0;

    for (i = 0; i < num_replies; i++) {
	
	if ((rc = getdns_list_get_dict(replies_tree, i, &reply))) {
	    fprintf(stderr, "FAIL: %s/TLSA: getting reply: %s\n",
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}

        if ((rc = getdns_dict_get_int(reply, "dnssec_status", &dstatus))) {
            fprintf(stderr, "FAIL: %s/TLSA: error obtaining dnssec status: %s\n",
                    hostname, getdns_get_errorstr_by_id(rc));
            goto cleanup;
	}

        switch (dstatus) {
	case GETDNS_DNSSEC_SECURE:
            auth_count++;
            break;
        case GETDNS_DNSSEC_INSECURE:
            fprintf(stdout, "TLSA response %zu is insecure.\n", i);
            break;
        default:
            dns_bogus_or_indeterminate = 1;
	}

	if ((rc = getdns_dict_get_list(reply, "answer", &answer))) {
	    fprintf(stderr, "FAIL: %s/TLSA: getting answer section: %s\n",
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}

	(void) getdns_list_get_length(answer, &num_answers);

	for (j=0; j < num_answers; j++) {

	    getdns_dict *rr;
	    uint32_t rrtype, usage, selector, mtype;
	    getdns_bindata *certdata = NULL;

	    if ((rc = getdns_list_get_dict(answer, j, &rr))) {
		fprintf(stderr, "FAIL: %s/TLSA: getting rr %zu: %s\n",
			hostname, j, getdns_get_errorstr_by_id(rc));
		break;
	    }

	    if ((rc = getdns_dict_get_int(rr, "/type", &rrtype))) {
		fprintf(stderr, "FAIL: %s/TLSA: getting rrtype: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }

	    if (rrtype != GETDNS_RRTYPE_TLSA) continue;
	    
	    if ((rc = getdns_dict_get_int(rr, "/rdata/certificate_usage", 
					  &usage))) {
		fprintf(stderr, "FAIL: %s/TLSA: getting usage: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }
	    if ((rc = getdns_dict_get_int(rr, "/rdata/selector", 
					  &selector))) {
		fprintf(stderr, "FAIL: %s/TLSA: getting selector: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }
	    if ((rc = getdns_dict_get_int(rr, "/rdata/matching_type", 
					  &mtype))) {
		fprintf(stderr, "FAIL: %s/TLSA: getting mtype: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }
	    if ((rc = getdns_dict_get_bindata(rr, 
					      "/rdata/certificate_association_data", 
					      &certdata))) {
		fprintf(stderr, "FAIL: %s/TLSA: getting certdata: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }

	    tlsa_rdata *rp = (tlsa_rdata *) malloc(sizeof(tlsa_rdata));
	    rp->usage = usage;
	    rp->selector = selector;
	    rp->mtype = mtype;
	    rp->data_len = certdata->size;
	    rp->data = malloc(certdata->size);
	    memcpy(rp->data, certdata->data, certdata->size);
	    rp->next = NULL;
	    current = insert_tlsa_rdata(current, rp);
	    tlsa_count++;
	}
    }

    if (auth_count == num_replies)
        tlsa_authenticated = 1;

cleanup:
    free(qip);
    getdns_dict_destroy(response);
    return;
}



/*
 * do_dns_queries()
 * asynchronously dispatch address and TLSA queries & wait for results.
 * Response data is obtained by the associated callback functions.
 */

int do_dns_queries(const char *hostname, uint16_t port)
{

    char domainstring[512];
    getdns_context *context = NULL;
    getdns_dict *extensions = NULL;
    getdns_return_t rc;
    struct event_base *evb;

    rc = getdns_context_create(&context, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	fprintf(stderr, "FAIL: Error creating getdns context: %s\n", 
		getdns_get_errorstr_by_id(rc));
	return 0;
    }

    if (!recursion)
	getdns_context_set_resolution_type(context, GETDNS_RESOLUTION_STUB);

    if (! (extensions = getdns_dict_create())) {
	fprintf(stderr, "FAIL: Error creating extensions dict\n");
	return 0;
    }

    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_status", 
				  GETDNS_EXTENSION_TRUE))) {
	fprintf(stderr, "FAIL: Error setting dnssec_return_status: %s\n",
		getdns_get_errorstr_by_id(rc));
	return 0;
    }

    if ( (evb = event_base_new()) == NULL ) {
	fprintf(stderr, "FAIL: event base creation failed.\n");
	getdns_context_destroy(context);
	return 0;
    }

    (void) getdns_extension_set_libevent_base(context, evb);

    getdns_transaction_t tid = 0;

    /*
     * Address Records lookup
     */
    qinfo *qip = (qinfo *) malloc(sizeof(qinfo));
    qip->qname = hostname;
    qip->qtype = GETDNS_RRTYPE_A;
    qip->port = port;
    rc = getdns_address(context, hostname, extensions, 
			(void *) qip, &tid, cb_address);
    if (rc != GETDNS_RETURN_GOOD) {
	fprintf(stderr, "ERROR: %s getdns_address failed: %s\n", 
		hostname, getdns_get_errorstr_by_id(rc));
	event_base_free(evb);
	getdns_context_destroy(context);
	return 0;
    }

    /*
     * TLSA Records lookup
     */
    if (auth_mode != MODE_PKIX) {
	snprintf(domainstring, sizeof(domainstring), "_%d._tcp.%s", port, hostname);
	qip = (qinfo *) malloc(sizeof(qinfo));
	qip->qname = domainstring;
	qip->qtype = GETDNS_RRTYPE_TLSA;
	qip->port = port;
	rc = getdns_general(context, domainstring, GETDNS_RRTYPE_TLSA, extensions, 
			    (void *) qip, &tid, cb_tlsa);
	if (rc != GETDNS_RETURN_GOOD) {
	    fprintf(stderr, "ERROR: %s getdns_general TLSA failed: %s\n", 
		    domainstring, getdns_get_errorstr_by_id(rc));
	    event_base_free(evb);
	    getdns_context_destroy(context);
	    return 0;
	}
    }

    int e_rc = event_base_dispatch(evb);

    if (e_rc == -1) {
	fprintf(stderr, "Error in dispatching events.\n");
	return 0;
    }

    event_base_free(evb);
    getdns_context_destroy(context);

    return 1;
}

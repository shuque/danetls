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

#include "query-getdns.h"


/*
 * addresses: (head of) linked list of addrinfo structures
 */

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


/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * tlsa_rdata_list: linked list of tlsa_rdata structures.
 */

size_t tlsa_count = 0;
tlsa_rdata *tlsa_rdata_list = NULL;

tlsa_rdata *insert_tlsa_rdata(current, new)
     tlsa_rdata *current;
     tlsa_rdata *new;
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
    uint32_t status;
    qinfo *qip = (qinfo *) userarg;
    const char *hostname = qip->qname;
    uint16_t port = qip->port;
    getdns_list    *just_addresses;
    size_t         cnt_addr;
    getdns_dict    *address;
    getdns_bindata *addr_type, *addr_data;

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

    if ((rc = getdns_dict_get_int(response, "status", &status))) {
	fprintf(stderr, "FAIL: %s: Error obtaining status code: %s\n", 
		hostname, getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    if (status == 903) {
	fprintf(stderr, "FAIL: %s No secure responses obtained\n", 
		hostname);
	goto cleanup;
    } else if (status == 901) {
	fprintf(stderr, "FAIL: %s Non existent domain name\n", hostname);
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

	struct addrinfo *aip = malloc(sizeof(struct addrinfo));

	if ((rc = getdns_list_get_dict(just_addresses, i, &address))) {
	    fprintf(stderr, "FAIL: %s: getting address dict: %s\n", 
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}

	if ((rc = getdns_dict_get_bindata(address, "address_type", 
					  &addr_type))) {
	    fprintf(stderr, "FAIL: %s: getting addr_type: %s\n", 
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}

	if ((rc = getdns_dict_get_bindata(address, "address_data", 
					  &addr_data))) {
	    fprintf(stderr, "FAIL: %s: getting addr_data: %s\n", 
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}

	if (!strncmp((const char *) addr_type->data, "IPv4", 4)) {
	    struct sockaddr_in *sa4 = malloc(sizeof(struct sockaddr_storage));
	    aip->ai_family = AF_INET;
	    memcpy(&(sa4->sin_addr), addr_data->data, addr_data->size);
	    sa4->sin_family = AF_INET;
	    sa4->sin_port = htons(port);
	    aip->ai_addr = (struct sockaddr *) sa4;
	    aip->ai_addrlen = sizeof(struct sockaddr_in);
	} else if (!strncmp((const char *) addr_type->data, "IPv6", 4)) {
	    struct sockaddr_in6 *sa6 = malloc(sizeof(struct sockaddr_storage));
	    aip->ai_family = AF_INET6;
	    memcpy(&(sa6->sin6_addr), addr_data->data, addr_data->size);
	    sa6->sin6_family = AF_INET6;
	    sa6->sin6_port = htons(port);
	    aip->ai_addr = (struct sockaddr *) sa6;
	    aip->ai_addrlen = sizeof(struct sockaddr_in6);
	} else  {
	    /* shouldn't get here */
	    fprintf(stderr, "FAIL: Unknown address type\n");
	    break;
	}
	aip->ai_next = NULL;
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
    uint32_t status;
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
        fprintf(stderr, "Callback address fail: %s, tid=%"PRIu64" rc=%d\n",
                hostname, tid, cb_type);
	return;
    }

    if ((rc = getdns_dict_get_int(response, "status", &status))) {
	fprintf(stderr, "FAIL: %s: Error obtaining status code: %s\n", 
		hostname, getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    if (status == 903) {
	fprintf(stderr, "FAIL: %s No secure responses obtained\n", 
		hostname);
	goto cleanup;
    } else if (status == 901) {
	fprintf(stderr, "FAIL: %s Non existent domain name\n", hostname);
	goto cleanup;
    }

    if ((rc = getdns_dict_get_list(response, "replies_tree", 
				   &replies_tree))) {
	fprintf(stderr, "FAIL: getting replies from responsedict: %s\n",
		getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    if ((rc = getdns_list_get_length(replies_tree, &num_replies))) {
	fprintf(stderr, "FAIL: getting replies_tree length: %s\n", 
		getdns_get_errorstr_by_id(rc));
	goto cleanup;
    }

    if (num_replies <= 0) {
	printf("FAIL: %s: No addresses found.\n", hostname);
	goto cleanup;
    }

    tlsa_rdata *current = tlsa_rdata_list;

    for (i = 0; i < num_replies; i++) {
	
	if ((rc = getdns_list_get_dict(replies_tree, i, &reply))) {
	    fprintf(stderr, "FAIL: %s: TLSA getting reply: %s\n",
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}
	if ((rc = getdns_dict_get_list(reply, "answer", &answer))) {
	    fprintf(stderr, "FAIL: %s: TLSA getting answer sec: %s\n",
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}
	if ((rc = getdns_list_get_length(answer, &num_answers))) {
	    fprintf(stderr, "FAIL: %s: TLSA getting answer length: %s\n",
		    hostname, getdns_get_errorstr_by_id(rc));
	    break;
	}

	for (j=0; j < num_answers; j++) {

	    getdns_dict *rr;
	    uint32_t rrtype, usage, selector, mtype;
	    getdns_bindata *certdata = NULL;

	    if ((rc = getdns_list_get_dict(answer, j, &rr))) {
		fprintf(stderr, "FAIL: %s: TLSA getting rr %zu: %s\n",
			hostname, j, getdns_get_errorstr_by_id(rc));
		break;
	    }

	    if ((rc = getdns_dict_get_int(rr, "/type", &rrtype))) {
		fprintf(stderr, "FAIL: %s: TLSA getting rrtype: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }

	    if (rrtype != GETDNS_RRTYPE_TLSA) continue;
	    
	    tlsa_count++;
	    
	    if ((rc = getdns_dict_get_int(rr, "/rdata/certificate_usage", 
					  &usage))) {
		fprintf(stderr, "FAIL: %s: TLSA getting usage: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }
	    if ((rc = getdns_dict_get_int(rr, "/rdata/selector", 
					  &selector))) {
		fprintf(stderr, "FAIL: %s: TLSA getting selector: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }
	    if ((rc = getdns_dict_get_int(rr, "/rdata/matching_type", 
					  &mtype))) {
		fprintf(stderr, "FAIL: %s: TLSA getting mtype: %s\n",
			hostname, getdns_get_errorstr_by_id(rc));
		break;
	    }
	    if ((rc = getdns_dict_get_bindata(rr, 
					      "/rdata/certificate_association_data", 
					      &certdata))) {
		fprintf(stderr, "FAIL: %s: TLSA getting certdata: %s\n",
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

cleanup:
    free(qip);
    getdns_dict_destroy(response);
    return;
}



/*
 * do_dns_queries()
 * asynchronously dispatch address and TLSA queries, wait for results,
 * populate address and TLSA set data structures.
 */

int do_dns_queries(const char *hostname, const char *port)
{

    char domainstring[512];
    getdns_context    *context = NULL;
    getdns_dict       *extensions = NULL;
    getdns_return_t   rc;
    struct event_base *evb;
    int port_int;

    port_int     = atoi(port);

    rc = getdns_context_create(&context, 1);
    if (rc != GETDNS_RETURN_GOOD) {
	fprintf(stderr, "FAIL: Error creating getdns context: %s\n", 
		getdns_get_errorstr_by_id(rc));
	return 0;
    }

    getdns_context_set_resolution_type(context, GETDNS_RESOLUTION_STUB);

    if (! (extensions = getdns_dict_create())) {
	fprintf(stderr, "FAIL: Error creating extensions dict\n");
	return 0;
    }
    if ((rc = getdns_dict_set_int(extensions, "dnssec_return_only_secure", 
				  GETDNS_EXTENSION_TRUE))) {
	fprintf(stderr, "FAIL: Error setting dnssec_return_only_secure: %s\n",
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
     * Address Lookups
     */
    qinfo *qip = (qinfo *) malloc(sizeof(qinfo));
    qip->qname = hostname;
    qip->qtype = GETDNS_RRTYPE_A;
    qip->port = port_int;
    rc = getdns_address(context, hostname, NULL, 
			(void *) qip, &tid, cb_address);
    if (rc != GETDNS_RETURN_GOOD) {
	fprintf(stderr, "ERROR: %s getdns_address failed: %s\n", 
		hostname, getdns_get_errorstr_by_id(rc));
	event_base_free(evb);
	getdns_context_destroy(context);
	return 0;
    }

    /*
     * TLSA record lookup
     */
    snprintf(domainstring, 512, "_%s._tcp.%s", port, hostname);
    qip = (qinfo *) malloc(sizeof(qinfo));
    qip->qname = domainstring;
    qip->qtype = GETDNS_RRTYPE_TLSA;
    qip->port = port_int;
    rc = getdns_general(context, domainstring, GETDNS_RRTYPE_TLSA, extensions, 
			(void *) qip, &tid, cb_tlsa);
    if (rc != GETDNS_RETURN_GOOD) {
	fprintf(stderr, "ERROR: %s getdns_general TLSA failed: %s\n", 
		domainstring, getdns_get_errorstr_by_id(rc));
	event_base_free(evb);
	getdns_context_destroy(context);
	return 0;
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

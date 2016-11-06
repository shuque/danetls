/*
 * Program to test DANE TLS services.
 * Requires OpenSSL 1.1.0 or later.
 *
 * This version uses getdns to query the DNS records.
 *
 * Author: Shumon Huque <shuque@gmail.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "common.h"
#include "utils.h"
#include "tls.h"
#include "query-getdns.h"
#include "starttls.h"


/*
 * Global variables
 */

int debug = 0;
int attempt_dane = 0;
int recursion = 0;
enum AUTH_MODE auth_mode = MODE_BOTH;
char *CAfile = NULL;
char *service_name = NULL;
int dane_ee_check_name = 0;


/*
 * usage(): Print usage string and exit.
 */

void print_usage(const char *progname)
{
    fprintf(stdout, "\n%s version %s\n"
	    "\nUsage: %s [options] <hostname> <portnumber>\n\n"
	    "       -h:                    print this help message\n"
	    "       -d:                    debug mode\n"
	    "       -r:                    use getdns in full recursion mode\n"
	    "       -n <name>:             service name\n"
	    "       -c <cafile>:           CA file\n"
	    "       -m <dane|pkix>:        dane or pkix mode\n"
	    "                              (default is dane & fallback to pkix)\n"
	    "       -s <app>:              use starttls with specified application\n"
	    "                              ('smtp', 'xmpp-client', 'xmpp-server')\n"
	    "       --dane-ee-check-name:  perform name checks for DANE-EE mode\n"
	    "\n",
	    progname, PROGRAM_VERSION, progname);
    exit(3);
}


/*
 * parse_options()
 */

int parse_options(const char *progname, int argc, char **argv)
{
    int c;
    int longindex = 0;

    static struct option long_options[] = {
	{ "dane-ee-check-name", no_argument, &dane_ee_check_name, 1 },
	{ 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "hdrn:c:m:s:",
			    long_options, &longindex)) != -1) {
        switch(c) {
	case 0: break;
        case 'h': print_usage(progname); break;
        case 'd': debug = 1; break;
        case 'r': recursion = 1; break;
	case 'n':
	    service_name = optarg; break;
	case 'c':
	    CAfile = optarg; break;
        case 'm': 
	    if (strcmp(optarg, "dane") == 0)
		auth_mode = MODE_DANE;
	    else if (strcmp(optarg, "pkix") == 0)
		auth_mode = MODE_PKIX;
	    else
		print_usage(progname);
	    break;
	case 's': 
	    if (strcmp(optarg, "smtp") == 0)
	        starttls = STARTTLS_SMTP;
	    else if (strcmp(optarg, "xmpp-client") == 0)
		starttls = STARTTLS_XMPP_CLIENT;
	    else if (strcmp(optarg, "xmpp-server") == 0)
		starttls = STARTTLS_XMPP_SERVER;
	    else {
		fprintf(stdout, "Unsupported STARTTLS application: %s.\n",
			optarg);
		print_usage(progname);
	    }
	    break;
        default:
            print_usage(progname);
        }
    }
    return optind;
}


/*
 * main(): DANE TLSA test program.
 */

int main(int argc, char **argv)
{

    int rc = 2; /* default AUTH FAILED */
    const char *progname, *hostname;
    uint16_t port;
    int optcount;

    SSL_CTX *ctx = NULL;

    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];

    optcount = parse_options(progname, argc, argv);
    argc -= optcount;
    argv += optcount;

    if (argc != 2) print_usage(progname);

    hostname = argv[0];
    port = atoi(argv[1]);

    /*
     * Obtain address and TLSA records with getdns library calls
     */

    if (do_dns_queries(hostname, port) != 1) {
	fprintf(stdout, "DNS query dispatch failed.\n");
	goto cleanup;
    }

    /*
     * Bail out if responses are bogus or indeterminate, or if no
     * addresses are found.
     */

    if (dns_bogus_or_indeterminate) {
	fprintf(stdout, "DNSSEC status of responses is bogus or indeterminate.\n");
        goto cleanup;
    }

    if (addresses == NULL) {
	fprintf(stdout, "No address records found, exiting.\n");
	goto cleanup;
    }

    /*
     * Set flag to attempt DANE ("attempt_dane") only if TLSA
     * records were found and both address and TLSA record set
     * were successfully authenticated with DNSSEC.
     */

    if (auth_mode == MODE_DANE || auth_mode == MODE_BOTH) {
        if (tlsa_rdata_list == NULL) {
	    fprintf(stdout, "No TLSA records found.\n");
            if (auth_mode == MODE_DANE)
                goto cleanup;
        } else if (tlsa_authenticated == 0) {
            fprintf(stdout, "Insecure TLSA records.\n");
            if (auth_mode == MODE_DANE)
                goto cleanup;
        } else if (v4_authenticated == 0 || v6_authenticated == 0) {
            fprintf(stdout, "Insecure Address records.\n");
            if (auth_mode == MODE_DANE)
                goto cleanup;
        } else {
            attempt_dane = 1;
        }
    }

    /*
     * Print TLSA records if debug flag was provided.
     */

    if (debug && attempt_dane) {
	print_tlsa(tlsa_rdata_list);
    }

    /*
     * establish TLS sessions to server addresses
     */

    rc = do_tls(hostname, addresses, tlsa_rdata_list);

 cleanup:
    freeaddrinfo(addresses);
    free_tlsa(tlsa_rdata_list);
    if (ctx)
	SSL_CTX_free(ctx);

    return rc;
}

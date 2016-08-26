/*
 * Program to test new OpenSSL DANE verification code (2016-01).
 * Requires OpenSSL 1.1.0-pre2 or later.
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
#include "query-getdns.h"
#include "starttls.h"


/*
 * Global variables
 */

int debug = 0;
int recursion = 0;
enum AUTH_MODE auth_mode = MODE_BOTH;
char *CAfile = NULL;
char *service_name = NULL;


/*
 * usage(): Print usage string and exit.
 */

void print_usage(const char *progname)
{
    fprintf(stdout, "\n%s version %s\n"
	    "\nUsage: %s [options] <hostname> <portnumber>\n\n"
            "       -h:             print this help message\n"
            "       -d:             debug mode\n"
            "       -r:             use getdns in full recursion mode\n"
	    "       -n <name>:      service name\n"
	    "       -c <cafile>:    CA file\n"
            "       -m <dane|pkix>: dane or pkix mode\n"
	    "                       (default is dane & fallback to pkix)\n"
	    "       -s <app>:       use starttls with specified application\n"
	    "                       ('smtp', 'xmpp-client', 'xmpp-server')\n"
	    "\n",
	    progname, PROGRAM_VERSION, progname);
    exit(3);
}


/*
 * parse_options()
 */

int parse_options(const char *progname, int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "hdrn:c:m:s:")) != -1) {
        switch(opt) {
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
 * print_cert_chain()
 * Print contents of given certificate chain.
 * Only DN common names of each cert + subjectaltname DNS names of end entity.
 */

void print_cert_chain(STACK_OF(X509) *chain)
{
    int i, rc;
    char buffer[1024];
    STACK_OF(GENERAL_NAME) *subjectaltnames = NULL;

    if (chain == NULL) {
	fprintf(stdout, "No Certificate Chain.");
	return;
    }

    for (i = 0; i < sk_X509_num(chain); i++) {
	rc = X509_NAME_get_text_by_NID(X509_get_subject_name(sk_X509_value(chain, i)),
				       NID_commonName, buffer, sizeof buffer);
	fprintf(stdout, "%2d Subject CN: %s\n", i, (rc >=0 ? buffer: "(None)"));
	rc = X509_NAME_get_text_by_NID(X509_get_issuer_name(sk_X509_value(chain, i)),
				       NID_commonName, buffer, sizeof buffer);
	fprintf(stdout, "   Issuer  CN: %s\n", (rc >= 0 ? buffer: "(None)"));
    }

    subjectaltnames = X509_get_ext_d2i(sk_X509_value(chain, 0),
                                       NID_subject_alt_name, NULL, NULL);
    if (subjectaltnames) {
        int san_count = sk_GENERAL_NAME_num(subjectaltnames);
        for (i = 0; i < san_count; i++) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(subjectaltnames, i);
            if (name->type == GEN_DNS) {
                char *dns_name = (char *) ASN1_STRING_get0_data(name->d.dNSName);
                fprintf(stdout, " SAN dNSName: %s\n", dns_name);
            }
        }
    }

    /* TODO: how to free stack of certs? */
    return;
}


/*
 * print_peer_cert_chain()
 * Note: this prints the certificate chain presented by the server
 * in its Certificate handshake message, not the certificate chain
 * that was used to validate the server.
 */

void print_peer_cert_chain(SSL *ssl)
{
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    fprintf(stdout, "Peer Certificate chain:\n");
    print_cert_chain(chain);
    return;
}


/*
 * print_validated_chain()
 * Prints the verified certificate chain of the peer including the peer's
 * end entity certificate, using SSL_get0_verified_chain(). Must be called
 * after a session has been successfully established. If peer verification
 * was not successful (as indicated by SSL_get_verify_result() not
 * returning X509_V_OK) the chain may be incomplete or invalid.
 */

void print_validated_chain(SSL *ssl)
{
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    fprintf(stdout, "Validated Certificate chain:\n");
    print_cert_chain(chain);
    return;
}


/*
 * main(): DANE TLSA test program.
 */

int main(int argc, char **argv)
{

    const char *progname, *hostname;
    uint16_t port;
    struct addrinfo *gaip;
    char ipstring[INET6_ADDRSTRLEN], *cp;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    int count_success = 0, count_fail = 0, count_tlsa_usable=0;
    int rc, sock, optcount;
    long rcl;
    int attempt_dane = 0;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_CIPHER *cipher = NULL;
    BIO *sbio;

    uint8_t usage, selector, mtype;

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

    rc = do_dns_queries(hostname, port);
    if (rc != 1) {
	fprintf(stdout, "DNS query dispatch failed.\n");
	goto cleanup;
    }

    /*
     * Bail out if responses are bogus or indeterminate
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

    if (debug && attempt_dane) {
	fprintf(stdout, "TLSA records found: %ld\n", tlsa_count);
	tlsa_rdata *rp;
	for (rp = tlsa_rdata_list; rp != NULL; rp = rp->next) {
	    fprintf(stdout, "TLSA: %d %d %d %s\n", rp->usage, rp->selector,
		    rp->mtype, (cp = bin2hexstring(rp->data, rp->data_len)));
	    free(cp);
	}
	(void) fputc('\n', stdout);
    }

    /*
     * Initialize OpenSSL TLS library context, certificate authority
     * stores, and hostname verification parameters.
     */

    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());
    (void) SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

    if (!CAfile) {
	if (!SSL_CTX_set_default_verify_paths(ctx)) {
	    fprintf(stdout, "Failed to load default certificate authorities.\n");
	    ERR_print_errors_fp(stdout);
	    goto cleanup;
	}
    } else {
	if (!SSL_CTX_load_verify_locations(ctx, CAfile, NULL)) {
	    fprintf(stdout, "Failed to load certificate authority store: %s.\n",
		    CAfile);
	    ERR_print_errors_fp(stdout);
	    goto cleanup;
	}
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 10);

    /*
     * Enable DANE on the context.
     */

    if (SSL_CTX_dane_enable(ctx) <= 0) {
	fprintf(stdout, "Unable to enable DANE on SSL context.\n");
	goto cleanup;
    }

    /*
     * Loop over all addresses from getaddrinfo(), connect to each,
     * establish TLS connection, and perform DANE peer verification.
     */

    for (gaip = addresses; gaip != NULL; gaip = gaip->ai_next) {

        if (gaip->ai_family == AF_INET) {
            sa4 = (struct sockaddr_in *) gaip->ai_addr;
            inet_ntop(AF_INET, &sa4->sin_addr, ipstring, INET6_ADDRSTRLEN);
            fprintf(stdout, "Connecting to IPv4 address: %s port %d\n",
                    ipstring, ntohs(sa4->sin_port));
        } else if (gaip->ai_family == AF_INET6) {
            sa6 = (struct sockaddr_in6 *) gaip->ai_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, ipstring, INET6_ADDRSTRLEN);
            fprintf(stdout, "Connecting to IPv6 address: %s port %d\n",
                    ipstring, ntohs(sa6->sin6_port));
        }

        sock = socket(gaip->ai_family, SOCK_STREAM, 0);
        if (sock == -1) {
            fprintf(stdout, "socket setup failed: %s\n", strerror(errno));
	    count_fail++;
            continue;
        }

        if (connect(sock, gaip->ai_addr, gaip->ai_addrlen) == -1) {
            fprintf(stdout, "connect failed: %s\n", strerror(errno));
            close(sock);
	    count_fail++;
            continue;
        }

	ssl = SSL_new(ctx);
	if (! ssl) {
	    fprintf(stdout, "SSL_new() failed.\n");
	    ERR_print_errors_fp(stdout);
	    close(sock);
	    count_fail++;
	    continue;
	}

        /*
         * SSL_set1_host() for non-DANE, SSL_dane_enable() for DANE.
         * For DANE SSL_dane_enable() issues TLS SNI extension; for
         * non-DANE, we need to explicitly call SSL_set_tlsext_host_name().
         */

        if (attempt_dane) {

            if (SSL_dane_enable(ssl, hostname) <= 0) {
	    fprintf(stdout, "SSL_dane_enable() failed.\n");
	    ERR_print_errors_fp(stdout);
	    SSL_free(ssl);
	    close(sock);
	    count_fail++;
	    continue;
	}

        } else {

            if (SSL_set1_host(ssl, hostname) != 1) {
	    fprintf(stdout, "SSL_set1_host() failed.\n");
	    ERR_print_errors_fp(stdout);
	    SSL_free(ssl);
	    close(sock);
	    count_fail++;
	    continue;
	}
            /* Set TLS Server Name Indication extension */
            (void) SSL_set_tlsext_host_name(ssl, hostname);

        }

	/* No partial label wildcards */
	SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

	/* Set connect mode (client) and tie socket to TLS context */
	SSL_set_connect_state(ssl);
        sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	/* Add TLSA record set rdata to TLS connection context */
	tlsa_rdata *rp;
	for (rp = tlsa_rdata_list; rp != NULL; rp = rp->next) {
	    rc = SSL_dane_tlsa_add(ssl, rp->usage, rp->selector, rp->mtype, 
				   rp->data, rp->data_len);
	    if (rc < 0) {
		fprintf(stdout, "SSL_dane_tlsa_add() failed.\n");
		ERR_print_errors_fp(stdout);
		SSL_free(ssl);
		close(sock);
		count_fail++;
		continue;
	    } else if (rc == 0) {
		cp = bin2hexstring((uint8_t *) rp->data, rp->data_len);
                fprintf(stdout, "WARNING: Unusable TLSA record: %d %d %d %s\n",
                        rp->usage, rp->selector, rp->mtype, cp);
		free(cp);
            } else
                count_tlsa_usable++;
	}

        if (auth_mode == MODE_DANE && count_tlsa_usable == 0) {
            fprintf(stdout, "No usable TLSA records present.\n");
            SSL_free(ssl);
            close(sock);
            count_fail++;
            continue;
        }

	/* Do application specific STARTTLS conversation if requested */
	if (starttls != STARTTLS_NONE && !do_starttls(starttls, sbio, service_name, hostname)) {
	    fprintf(stdout, "STARTTLS failed.\n");
	    /* shutdown sbio here cleanly */
	    SSL_free(ssl);
	    close(sock);
	    count_fail++;
	    continue;
	}

	/* Perform TLS connection handshake & peer authentication */
	if (SSL_connect(ssl) <= 0) {
	    fprintf(stdout, "TLS connection failed.\n");
	    ERR_print_errors_fp(stderr);
	    SSL_free(ssl);
	    close(sock);
	    count_fail++;
	    continue;
	}

	fprintf(stdout, "%s handshake succeeded.\n", SSL_get_version(ssl));
	cipher = SSL_get_current_cipher(ssl);
	fprintf(stdout, "Cipher: %s %s\n",
		SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher));

	/* Print Certificate Chain information (if in debug mode) */
	if (debug)
	    print_peer_cert_chain(ssl);

	/* Report results of DANE or PKIX authentication of peer cert */
	if ((rcl = SSL_get_verify_result(ssl)) == X509_V_OK) {
	    count_success++;
	    const unsigned char *certdata;
	    size_t certdata_len;
	    const char *peername = SSL_get0_peername(ssl);
	    EVP_PKEY *mspki = NULL;
	    int depth = SSL_get0_dane_authority(ssl, NULL, &mspki);
	    if (depth >= 0) {
		(void) SSL_get0_dane_tlsa(ssl, &usage, &selector, &mtype, 
					  &certdata, &certdata_len);
		fprintf(stdout, "DANE TLSA %d %d %d [%s...] %s at depth %d\n", 
			usage, selector, mtype,
			(cp = bin2hexstring( (uint8_t *) certdata, 6)),
			(mspki != NULL) ? "TA public key verified certificate" :
			depth ? "matched TA certificate" : "matched EE certificate",
			depth);
		free(cp);
	    }
	    if (peername != NULL) {
		/* Name checks were in scope and matched the peername */
		fprintf(stdout, "Verified peername: %s\n", peername);
	    }
	    /* Print verified certificate chain (if in debug mode) */
	    if (debug)
		print_validated_chain(ssl);
	} else {
	    /* Authentication failed */
	    count_fail++;
	    fprintf(stdout, "Error: peer authentication failed. rc=%ld (%s)\n",
                    rcl, X509_verify_cert_error_string(rcl));
	    ERR_print_errors_fp(stdout);
	}

	/* Shutdown and wait for peer shutdown*/
	while (SSL_shutdown(ssl) == 0)
	    ;
	SSL_free(ssl);
	close(sock);
	(void) fputc('\n', stdout);

    }

cleanup:
    freeaddrinfo(addresses);
    free_tlsa(tlsa_rdata_list);
    if (ctx)
	SSL_CTX_free(ctx);

    /*
     * Return status:
     * 0: Authentication success for all queried peers
     * 1: Authentication success for some but not all queried peers
     * 2: Authentication failed.
     * 3: Program usage error.
     */
    if (count_success > 0 && count_fail == 0)
        return 0;
    else if (count_success > 0 && count_fail != 0)
        return 1;
    else
        return 2;
}

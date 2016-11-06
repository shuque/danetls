/*
 * tls.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "starttls.h"
#include "tls.h"
#include "utils.h"

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
 * do_tls()
 *
 */

int do_tls(const char *hostname,
	   struct addrinfo *addresses, tlsa_rdata *tlsa_rdata_list)
{
    struct addrinfo *gaip = NULL;
    char ipstring[INET6_ADDRSTRLEN], *cp;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    int count_success = 0, count_fail = 0, count_tlsa_usable=0;
    int rc, sock;
    long rcl;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_CIPHER *cipher = NULL;
    BIO *sbio;

    uint8_t usage, selector, mtype;

    /*
     * Initialize OpenSSL TLS library context, certificate authority
     * stores, and certificate verification parameters.
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
     * Disable peer name checks for DANE-EE modes, unless requested.
     */

    if (!dane_ee_check_name) {
	(void) SSL_CTX_dane_set_flags(ctx, DANE_FLAG_NO_DANE_EE_NAMECHECKS);
    }

    /*
     * Loop over all addresses, connect to each, establish TLS
     * connection, and perform peer authentication.
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

        sock = socket(gaip->ai_family, SOCK_STREAM, IPPROTO_TCP);
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
	if (!ssl) {
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
	if (attempt_dane) {
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
		    fprintf(stdout, "Unusable TLSA record: %d %d %d %s\n",
			    rp->usage, rp->selector, rp->mtype, cp);
		    free(cp);
		} else
		    count_tlsa_usable++;
	    }
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
	    ERR_print_errors_fp(stdout);
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

    /*
     * Return status:
     * 0: Authentication success for all queried peers
     * 1: Authentication success for some but not all queried peers
     * 2: Authentication failed.
     * 3: Program usage error.
     */
    if (count_success > 0 && count_fail == 0) {
	fprintf(stdout, "[0] Authentication succeeded for all (%d) peers.\n", count_success);
        return 0;
    } else if (count_success > 0 && count_fail != 0) {
	fprintf(stdout, "[1] Authentication succeeded for some but not all peers (%d of %d).\n", count_success, (count_success + count_fail));
        return 1;
    } else {
	fprintf(stdout, "[2] Authentication failed for all (%d) peers.\n", count_fail);
        return 2;
    }
}

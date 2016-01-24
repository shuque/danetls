/*
 * starttls.c
 *
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

#include <ldns/ldns.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "starttls.h"

extern int debug;

enum APP_STARTTLS starttls = STARTTLS_NONE;

/*
 * do_starttls() - 
 * Perform application specific STARTTLS conversation. This routine
 * speaks just enough of the protocol to determine whether it can
 * proceed with TLS session establishment.
 */

#define MYBUFSIZE 2048

int do_starttls(enum APP_STARTTLS starttls, BIO *sbio, 
		char *service, const char *hostname)
{
    int rc = 0;
    char buffer[MYBUFSIZE], myhostname[MYBUFSIZE], param[MYBUFSIZE], *cp;
    int read_len;
    switch (starttls) {
    case STARTTLS_SMTP: {
	int seen_starttls = 0, reply_code = -1;
	BIO *fbio = BIO_new(BIO_f_buffer());
	BIO_push(fbio, sbio);
	/* consume greeting (possibly multiline) & inspect reply code */
	while (1) {
	    read_len = BIO_gets(fbio, buffer, MYBUFSIZE);
	    (void) sscanf(buffer, "%3d", &reply_code);
	    if (debug) {
		cp = strstr(buffer, "\r\n");
		*cp = '\0';
		fprintf(stdout, "recv: %s\n", buffer);
	    }
	    if (read_len <= 3 || buffer[3] != '-')
		break;
	}
	if (reply_code != 220) {
	    fprintf(stdout, "Invalid ESMTP greeting: %s\n", buffer);
	    BIO_pop(fbio);
	    BIO_free(fbio);
	    return rc;
	}
	/* Send EHLO, read response, and look for STARTTLS parameter */
	(void) gethostname(myhostname, MYBUFSIZE);
	if (debug) {
	    fprintf(stdout, "send: EHLO %s\n", myhostname);
	}
	BIO_printf(fbio, "EHLO %s\r\n", myhostname);
	(void)BIO_flush(fbio);
	while (1) {
	    read_len = BIO_gets(fbio, buffer, MYBUFSIZE);
	    (void) sscanf(buffer, "%3d", &reply_code);
	    (void) sscanf(buffer+4, "%255s", param);
	    if (strcmp(param, "STARTTLS") == 0)
		seen_starttls = 1;
	    if (debug) {
		cp = strstr(buffer, "\r\n");
		*cp = '\0';
		fprintf(stdout, "recv: %s\n", buffer);
	    }
	    if (read_len <= 3 || buffer[3] != '-')
		break;
	}
	BIO_pop(fbio);
	BIO_free(fbio);
	if (reply_code == 250 && seen_starttls) {
	    /* send STARTTLS command and inspect reply code */
	    if (debug) {
		fprintf(stdout, "send: STARTTLS\n");
	    }
	    BIO_printf(sbio, "STARTTLS\r\n");
            BIO_read(sbio, buffer, MYBUFSIZE);
	    if (debug) {
		cp = strstr(buffer, "\r\n");
		*cp = '\0';
		fprintf(stdout, "recv: %s\n", buffer);
	    }
	    (void) sscanf(buffer, "%3d", &reply_code);
	    if (reply_code == 220)
		rc = 1;
	    else
		fprintf(stderr, "Invalid response to STARTTLS: %s\n", buffer);
	} else if (reply_code != 250) {
	    fprintf(stderr, "Invalid reply code to SMTP EHLO: %d\n", reply_code);
	} else {
	    fprintf(stderr, "Unable to find STARTTLS in SMTP EHLO response.\n");
	}
	break;
    }
    case STARTTLS_XMPP_CLIENT:
    case STARTTLS_XMPP_SERVER: {
	int readn, seen_starttls = 0;	
	snprintf(buffer, sizeof(buffer), 
		 "<?xml version='1.0'?>"
		 "<stream:stream "
		 "to='%s' "
		 "version='1.0' xml:lang='en' "
		 "xmlns='jabber:%s' "
		 "xmlns:stream='http://etherx.jabber.org/streams'>",
		 service ? service : hostname,
		 starttls == STARTTLS_XMPP_CLIENT ? "client" : "server");
	if (debug) {
	    fprintf(stdout, "send: %s\n", buffer);
	}
	BIO_printf(sbio, buffer);
	while (1) {
	    readn = BIO_read(sbio, buffer, MYBUFSIZE);
	    if (readn == 0) break;
	    buffer[readn] = '\0';
	    if (debug) {
		fprintf(stdout, "recv: %s\n", buffer);
	    }
	    if (strstr(buffer, "<starttls xmlns") &&
		strstr(buffer, "urn:ietf:params:xml:ns:xmpp-tls")) {
		seen_starttls = 1;
		break;
	    }
	}
	if (!seen_starttls)
	    fprintf(stderr, "Unable to find STARTTLS in XMPP response.\n");
	else {
	    snprintf(buffer, sizeof(buffer),
		     "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
	    if (debug) {
		fprintf(stdout, "send: %s\n", buffer);
	    }
	    BIO_printf(sbio, buffer);
	    readn = BIO_read(sbio, buffer, MYBUFSIZE);
            buffer[readn] = '\0';
	    if (debug) {
		fprintf(stdout, "recv: %s\n", buffer);
	    }
	    if (strstr(buffer, "<proceed"))
		rc = 1;
	}
	break;
    }
    default:
	fprintf(stderr, "STARTTLS application not implemented.\n");
	break;
    }
    return rc;
}


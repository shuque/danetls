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
    char buffer[MYBUFSIZE], myhostname[MYBUFSIZE], param[MYBUFSIZE];
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
	BIO_printf(fbio, "EHLO %s\r\n", myhostname);
	(void)BIO_flush(fbio);
	while (1) {
	    read_len = BIO_gets(fbio, buffer, MYBUFSIZE);
	    (void) sscanf(buffer, "%3d", &reply_code);
	    (void) sscanf(buffer+4, "%255s", param);
	    if (strcmp(param, "STARTTLS") == 0)
		seen_starttls = 1;
	    if (read_len <= 3 || buffer[3] != '-')
		break;
	}
	BIO_pop(fbio);
	BIO_free(fbio);
	if (reply_code == 250 && seen_starttls) {
	    /* send STARTTLS command and inspect reply code */
	    BIO_printf(sbio, "STARTTLS\r\n");
            BIO_read(sbio, buffer, MYBUFSIZE);
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
	BIO_printf(sbio, 
		   "<?xml version='1.0'?>"
		   "<stream:stream "
		   "to='%s' "
		   "version='1.0' xml:lang='en' "
		   "xmlns='jabber:%s' "
		   "xmlns:stream='http://etherx.jabber.org/streams'>",
		   service ? service : hostname,
		   starttls == STARTTLS_XMPP_CLIENT ? "client" : "server");
	while (1) {
	    readn = BIO_read(sbio, buffer, MYBUFSIZE);
	    if (readn == 0) break;
	    buffer[readn] = '\0';
	    if (strstr(buffer, "<starttls xmlns") &&
		strstr(buffer, "urn:ietf:params:xml:ns:xmpp-tls")) {
		seen_starttls = 1;
		break;
	    }
	}
	if (!seen_starttls)
	    fprintf(stderr, "Unable to find STARTTLS in XMPP response.\n");
	else {
	    BIO_printf(sbio,
                       "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
	    readn = BIO_read(sbio, buffer, MYBUFSIZE);
            buffer[readn] = '\0';
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


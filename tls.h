#ifndef __TLS_H__
#define __TLS_H__

#include "tlsardata.h"

void print_cert_chain(STACK_OF(X509) *chain);
void print_peer_cert_chain(SSL *ssl);
void print_validated_chain(SSL *ssl);
int do_tls(const char *hostname, struct addrinfo *addresses, tlsa_rdata *tlsa_rdata_list);

#endif /* __TLS_H__ */

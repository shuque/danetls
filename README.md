# danetls

A program to test DANE enabled TLS services.  
Author: Shumon Huque  

This program looks up address records and DANE TLSA records for the 
specified TLS server and port, connects to the server, establishes a 
TLS session, and attempts to authenticate the server certificate with 
the DANE TLSA record(s). If no TLSA records are found, it falls back 
to traditional PKIX authentication. Uses the DANE verification code 
introduced in OpenSSL 1.1.0-pre2 (released on January 2016) or later.

Command line options can specify whether to do DANE or PKIX modes,
an alternate certificate store file, and what STARTTLS application
protocol should be used (currently there is STARTTLS support for SMTP
and XMPP only - the two most widely deployed DANE STARTTLS applications).

There are two versions of this program. "danetls", which uses libdns 
to perform the DNS queries, and "danetls-getdns", which uses the 
getdns library instead. The ldns version assumes the use of validating 
DNS resolver to which we have a trusted connection, and checks the 
AD bit in responses from the resolver. The getdns version uses a 
DNSSEC-aware (but not necessarily DNSSEC-validating) resolver and 
performs its own validation.

Pre-requisites:  
- OpenSSL version 1.1.0-pre2 or later
- [ldns library](http://www.nlnetlabs.nl/projects/ldns/), for ldns version
- [getdns library](http://getdnsapi.net/), for getdns version

```
Usage: danetls [options] <hostname> <portnumber>

       -h:             print this help message
       -d:             debug mode
       -n <name>:      service name
       -c <cafile>:    CA file
       -m <dane|pkix>: dane or pkix mode
                       (default is dane & fallback to pkix)
       -s <app>:       use starttls with specified application
                       ('smtp', 'xmpp-client', 'xmpp-server')
```

Some sample output follows.

Checking the HTTPS service at www.huque.com:
```
$ danetls www.huque.com 443
Connecting to IPv6 address: 2600:3c03:e000:81::a port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
DANE TLSA 3 1 1 [b760c12119c3...] matched EE certificate at depth 0

Connecting to IPv4 address: 50.116.63.23 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
DANE TLSA 3 1 1 [b760c12119c3...] matched EE certificate at depth 0
```

Checking the HTTPS service at www.ietf.org:
```
$ danetls www.ietf.org 443
Connecting to IPv6 address: 2400:cb00:2048:1::6814:155 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256
DANE TLSA 3 1 1 [0c72ac70b745...] matched EE certificate at depth 0

Connecting to IPv6 address: 2400:cb00:2048:1::6814:55 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256
DANE TLSA 3 1 1 [0c72ac70b745...] matched EE certificate at depth 0

Connecting to IPv4 address: 104.20.0.85 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256
DANE TLSA 3 1 1 [0c72ac70b745...] matched EE certificate at depth 0

Connecting to IPv4 address: 104.20.1.85 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256
DANE TLSA 3 1 1 [0c72ac70b745...] matched EE certificate at depth 0
```

Checking HTTPS at www.huque.com with additional debugging (-d):
```
$ danetls -d www.huque.com 443
TLSA records found: 1
TLSA: 3 1 1 b760c12119c388736da724df1224d21dfd23bf03366c286de1a4125369ef7de0

Connecting to IPv6 address: 2600:3c03:e000:81::a port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Certificate chain:
 0 Subject: /C=US/CN=www.huque.com/emailAddress=postmaster@huque.com
   Issuer : /C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Class 1 Primary Intermediate Server CA
 1 Subject: /C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Class 1 Primary Intermediate Server CA
   Issuer : /C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Certification Authority
DANE TLSA 3 1 1 [b760c12119c3...] matched EE certificate at depth 0

Connecting to IPv4 address: 50.116.63.23 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Certificate chain:
 0 Subject: /C=US/CN=www.huque.com/emailAddress=postmaster@huque.com
   Issuer : /C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Class 1 Primary Intermediate Server CA
 1 Subject: /C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Class 1 Primary Intermediate Server CA
   Issuer : /C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Certification Authority
DANE TLSA 3 1 1 [b760c12119c3...] matched EE certificate at depth 0
```

Checking the HTTPS server at www.amazon.com (no TLSA records):
```
$ ./danetls www.amazon.com 443
No TLSA records found; Performing PKIX-only validation.

Connecting to IPv4 address: 54.239.25.200 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256
Verified peername: www.amazon.com
```

Checking the SMTP STARTTLS service at openssl.org. (The MX target
of this service is mta.openssl.org):
```
$ danetls -s smtp mta.openssl.org 25
Connecting to IPv6 address: 2001:608:c00:180::1:e6 port 25
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
DANE TLSA 3 1 1 [687c07fbe249...] matched EE certificate at depth 0

Connecting to IPv4 address: 194.97.150.230 port 25
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
DANE TLSA 3 1 1 [687c07fbe249...] matched EE certificate at depth 0
```

### Other modes

TBD ...



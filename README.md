# danetls

A program to test DANE enabled TLS services.  
Author: Shumon Huque  

This program looks up address records and DANE TLSA records for the 
specified TLS server and port, connects to the server, establishes a 
TLS session, and attempts to authenticate the server certificate with 
the DANE TLSA record(s). If no TLSA records are found, it falls back 
to traditional PKIX authentication. Uses the DANE verification code 
in OpenSSL 1.1.0-pre3 or later.

Command line options can specify whether to do DANE or PKIX modes,
an alternate certificate store file, and what STARTTLS application
protocol should be used (currently there is STARTTLS support for SMTP
and XMPP only - the two most widely deployed DANE STARTTLS applications).

There are two versions of this program. "danetls", which uses ldns 
to perform the DNS queries, and "danetls-getdns", which uses the 
getdns library instead. The ldns version assumes the use of validating 
DNS resolver to which we have a trusted connection, and checks the 
AD bit in responses from the resolver. The getdns version uses a 
DNSSEC-aware (but not necessarily DNSSEC-validating) resolver and 
performs its own validation.

With the -d (debug) command line option, the program prints out
additional information about the TLSA record data, server presented
certificate chain, the actually validated certificate chain, and
if STARTTLS was used, the application specific STARTTLS conversation
that took place.

Pre-requisites:  
- OpenSSL version 1.1.0 or later
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
TLSA records found: 1
TLSA: 3 1 1 b760c12119c388736da724df1224d21dfd23bf03366c286de1a4125369ef7de0

Connecting to IPv6 address: 2600:3c03:e000:81::a port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Peer Certificate chain:
 0 Subject CN: www.huque.com
   Issuer  CN: StartCom Class 1 Primary Intermediate Server CA
 1 Subject CN: StartCom Class 1 Primary Intermediate Server CA
   Issuer  CN: StartCom Certification Authority
 SAN dNSName: www.huque.com
 SAN dNSName: huque.com
DANE TLSA 3 1 1 [b760c12119c3...] matched EE certificate at depth 0
Validated Certificate chain:
 0 Subject CN: www.huque.com
   Issuer  CN: StartCom Class 1 Primary Intermediate Server CA
 SAN dNSName: www.huque.com
 SAN dNSName: huque.com

Connecting to IPv4 address: 50.116.63.23 port 443
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Peer Certificate chain:
 0 Subject CN: www.huque.com
   Issuer  CN: StartCom Class 1 Primary Intermediate Server CA
 1 Subject CN: StartCom Class 1 Primary Intermediate Server CA
   Issuer  CN: StartCom Certification Authority
 SAN dNSName: www.huque.com
 SAN dNSName: huque.com
DANE TLSA 3 1 1 [b760c12119c3...] matched EE certificate at depth 0
Validated Certificate chain:
 0 Subject CN: www.huque.com
   Issuer  CN: StartCom Class 1 Primary Intermediate Server CA
 SAN dNSName: www.huque.com
 SAN dNSName: huque.com
```

Checking the HTTPS server at www.amazon.com (no TLSA records):
```
$ danetls www.amazon.com 443
No TLSA records found.
Connecting to IPv4 address: 54.239.26.128 port 443
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

Checking the XMPP (s2s) service at debian.org:
(_xmpp-server SRV record points to the host: voler.debian.org)
```
$ danetls -s xmpp-server -n debian.org vogler.debian.org
Connecting to IPv6 address: 2001:41b8:202:deb:1b1b::92 port 5269
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
DANE TLSA 3 1 1 [bcafdcc89ec7...] matched EE certificate at depth 0

Connecting to IPv4 address: 82.195.75.92 port 5269
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
DANE TLSA 3 1 1 [bcafdcc89ec7...] matched EE certificate at depth 0
```

Checking with debugging (-d) SMTP service at mail.ietf.org
(Prints details of the SMTP conversation prior to TLS):
```
$ danetls -d -s smtp mail.ietf.org 25
TLSA records found: 1
TLSA: 3 1 1 0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6

Connecting to IPv6 address: 2001:1900:3001:11::2c port 25
recv: 220 ietfa.amsl.com ESMTP Postfix
send: EHLO cheetara.huque.com
recv: 250-ietfa.amsl.com
recv: 250-PIPELINING
recv: 250-SIZE 67108864
recv: 250-ETRN
recv: 250-STARTTLS
recv: 250-AUTH PLAIN LOGIN
recv: 250-AUTH=PLAIN LOGIN
recv: 250-ENHANCEDSTATUSCODES
recv: 250 8BITMIME
send: STARTTLS
recv: 220 2.0.0 Ready to start TLS
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Peer Certificate chain:
 0 Subject CN: *.ietf.org
   Issuer  CN: Starfield Secure Certificate Authority - G2
 1 Subject CN: Starfield Secure Certificate Authority - G2
   Issuer  CN: Starfield Root Certificate Authority - G2
 2 Subject CN: Starfield Root Certificate Authority - G2
   Issuer  CN: (Null)
 3 Subject CN: (Null)
   Issuer  CN: (Null)
 SAN dNSName: *.ietf.org
 SAN dNSName: ietf.org
 SAN dNSName: *.ietf.org
DANE TLSA 3 1 1 [0c72ac70b745...] matched EE certificate at depth 0
Validated Certificate chain:
 0 Subject CN: *.ietf.org
   Issuer  CN: Starfield Secure Certificate Authority - G2
 SAN dNSName: *.ietf.org
 SAN dNSName: ietf.org
 SAN dNSName: *.ietf.org

Connecting to IPv4 address: 4.31.198.44 port 25
recv: 220 ietfa.amsl.com ESMTP Postfix
send: EHLO cheetara.huque.com
recv: 250-ietfa.amsl.com
recv: 250-PIPELINING
recv: 250-SIZE 67108864
recv: 250-ETRN
recv: 250-STARTTLS
recv: 250-AUTH PLAIN LOGIN
recv: 250-AUTH=PLAIN LOGIN
recv: 250-ENHANCEDSTATUSCODES
recv: 250 8BITMIME
send: STARTTLS
recv: 220 2.0.0 Ready to start TLS
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Peer Certificate chain:
 0 Subject CN: *.ietf.org
   Issuer  CN: Starfield Secure Certificate Authority - G2
 1 Subject CN: Starfield Secure Certificate Authority - G2
   Issuer  CN: Starfield Root Certificate Authority - G2
 2 Subject CN: Starfield Root Certificate Authority - G2
   Issuer  CN: (Null)
 3 Subject CN: (Null)
   Issuer  CN: (Null)
 SAN dNSName: *.ietf.org
 SAN dNSName: ietf.org
 SAN dNSName: *.ietf.org
DANE TLSA 3 1 1 [0c72ac70b745...] matched EE certificate at depth 0
Validated Certificate chain:
 0 Subject CN: *.ietf.org
   Issuer  CN: Starfield Secure Certificate Authority - G2
 SAN dNSName: *.ietf.org
 SAN dNSName: ietf.org
 SAN dNSName: *.ietf.org
```

Checking with debugging (-d) XMPP s2s service at mailbox.org (xmpp.mailbox.org)
(Prints details of the SMTP conversation prior to TLS):
```
$ danetls -d -s xmpp-server -n mailbox.org xmpp.mailbox.org 5269
TLSA records found: 1
TLSA: 3 1 1 4758af6f02dfb5dc8795fa402e77a8a0486af5e85d2ca60c294476aadc40b220

Connecting to IPv4 address: 80.241.60.206 port 5269
send: <?xml version='1.0'?><stream:stream to='mailbox.org' version='1.0' xml:lang='en' xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams'>
recv: <?xml version='1.0'?><stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='mailbox.org' id='2d26a4ec-36e8-416d-9067-60e805967466' to='' xml:lang='en' xmlns='jabber:server'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>
send: <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
recv: <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
TLSv1.2 handshake succeeded.
Cipher: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
Peer Certificate chain:
 0 Subject CN: *.mailbox.org
   Issuer  CN: SwissSign Server Silver CA 2014 - G22
 1 Subject CN: SwissSign Server Silver CA 2014 - G22
   Issuer  CN: SwissSign Silver CA - G2
 2 Subject CN: SwissSign Silver CA - G2
   Issuer  CN: SwissSign Silver CA - G2
 SAN dNSName: *.mailbox.org
 SAN dNSName: mailbox.org
DANE TLSA 3 1 1 [4758af6f02df...] matched EE certificate at depth 0
Validated Certificate chain:
 0 Subject CN: *.mailbox.org
   Issuer  CN: SwissSign Server Silver CA 2014 - G22
 SAN dNSName: *.mailbox.org
 SAN dNSName: mailbox.org
```

### Other examples

TBD ...



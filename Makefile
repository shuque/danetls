PREFIX		= /usr/local
BINDIR		= $(PREFIX)/bin
SBINDIR		= $(PREFIX)/sbin
LIBDIR		= $(PREFIX)/lib
INCLUDEDIR	= $(PREFIX)/include

INSTALL		= ./install-sh
INSTALL_PROG	= $(INSTALL)
INSTALL_DATA	= $(INSTALL) -m 644

PROG    = danetls danetls-getdns

INCLUDE = -I. -I/usr/local/openssl/include -I/usr/local/include
CFLAGS  = -g -Wall -Wextra $(INCLUDE)
LDFLAGS = -L/usr/local/openssl/lib -L/usr/local/lib -Wl,-rpath -Wl,/usr/local/openssl/lib -Wl,-rpath -Wl,/usr/local/lib
LIBS_LDNS    = -lssl -lcrypto -lldns
LIBS_GETDNS  = -lssl -lcrypto -lldns -lgetdns_ext_event -lgetdns -levent_core -lunbound -lidn
CC      = cc

# For Mac OS X
#LDFLAGS = -L/usr/local/lib


all:		$(PROG)

danetls:	danetls.o query-ldns.o utils.o tls.o starttls.o tlsardata.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS_LDNS)

danetls-getdns:	danetls-getdns.o query-getdns.o utils.o tls.o starttls.o tlsardata.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS_GETDNS)

install:	$(PROG)
		$(INSTALL_PROG) $(PROG) $(BINDIR)

.PHONY:		clean count
clean:
		rm -rf *.o $(PROG)
count:
		wc -c *.[ch]

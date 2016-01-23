PROG    = danetls danetls-getdns
INCLUDE = -I. -I/usr/local/openssl/include -I/usr/local/include
# -stc=c99 won't find getaddrinfo definitions, alas
# Workaround if needed: -std=gnu99 or -D_POSIX_C_SOURCE=200112L
#CFLAGS  = -g -std=c99 -Wall -Wextra $(INCLUDE)
CFLAGS  = -g -Wall -Wextra $(INCLUDE)
LDFLAGS = -L/usr/local/openssl/lib -L/usr/local/lib -Wl,-rpath -Wl,/usr/local/openssl/lib -Wl,-rpath -Wl,/usr/local/lib
LIBS_LDNS    = -lssl -lcrypto -lldns
LIBS_GETDNS  = -lssl -lcrypto -lldns -lgetdns_ext_event -lgetdns -levent_core -lunbound -lidn
CC      = cc

# This works for Mac OS X
#LDFLAGS = -L/usr/local/openssl/lib -L/usr/local/lib
#LIBS    = -lssl -lcrypto -lldns -lgetdns_ext_event -lgetdns -levent_core -lunbound -lidn -ldl

all:		$(PROG)

danetls:	danetls.o query-ldns.o utils.o starttls.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS_LDNS)

danetls-getdns:	danetls-getdns.o query-getdns.o utils.o starttls.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS_GETDNS)

.PHONY:		clean count
clean:
		rm -rf *.o $(PROG)
count:
		wc -c *.[ch]

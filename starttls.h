#ifndef __STARTTLS_H__
#define __STARTTLS_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

enum APP_STARTTLS {
    STARTTLS_NONE=0,
    STARTTLS_SMTP,
    STARTTLS_XMPP_CLIENT,
    STARTTLS_XMPP_SERVER
};

extern enum APP_STARTTLS starttls;

int do_starttls(enum APP_STARTTLS starttls, BIO *sbio,
                char *service, const char *hostname);

#endif /* __STARTTLS_H__ */



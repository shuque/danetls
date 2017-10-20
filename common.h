#ifndef __COMMON_H__
#define __COMMON_H__

#define PROGRAM_VERSION "0.3"

enum AUTH_MODE {
    MODE_BOTH=0,
    MODE_DANE,
    MODE_PKIX
};

extern int debug;
extern int attempt_dane;
extern enum AUTH_MODE auth_mode;
extern char *CAfile;
extern char *service_name;
extern int dane_ee_check_name;
extern int smtp_any_mode;

#endif /* __COMMON_H__ */

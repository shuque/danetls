#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

char *bin2hexstring(uint8_t *data, size_t length);
char *bindata2hexstring(getdns_bindata *b);

#endif /* __UTILS_H__ */



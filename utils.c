/*
 * utils.c
 */

#include "utils.h"

/*
 * bin2hexstring(): convert binary input into a string of hex digits.
 * Caller needs to free returned memory.
 */

char *bin2hexstring(uint8_t *data, size_t length)
{
    size_t k;
    char *outstring, *p;
    outstring = (char *) malloc(2 *length + 1);
    p = outstring;
    for (k = 0; k < length; k++) {
        snprintf(p, 3, "%02x", (unsigned int) *(data+k));
        p += 2;
    }
    return outstring;
}


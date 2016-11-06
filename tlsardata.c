/*
 * tlsastruct.c
 */

#include <stdio.h>

#include "query-ldns.h"
#include "utils.h"
#include "common.h"


/*
 * tlsa_rdata: structure to hold TLSA record rdata.
 * insert_tlsa_rdata(): insert node at tail of linked list of tlsa_rdata.
 * free_tlsa(): free memory in the linked list.
 */

tlsa_rdata *
insert_tlsa_rdata(tlsa_rdata **headp, tlsa_rdata *current, tlsa_rdata *new)
{
    if (current == NULL)
        *headp = new;
    else
        current->next = new;
    return new;
}

void free_tlsa(tlsa_rdata *head)
{
    tlsa_rdata *current;

    while ((current = head) != NULL) {
	head = head->next;
	LDNS_FREE(current->data);
	free(current);
    }
    return;
}


/*
 * print_tlsa() - print TLSA record rdata set
 */

void print_tlsa(tlsa_rdata *tlist)
{
    char *cp;
    tlsa_rdata *rp;

    if (tlist) {
        fprintf(stdout, "\nTLSA records found: %ld\n", tlsa_count);
        for (rp = tlist; rp != NULL; rp = rp->next) {
            fprintf(stdout, "TLSA: %d %d %d %s\n", rp->usage, rp->selector,
                    rp->mtype, (cp = bin2hexstring(rp->data, rp->data_len)));
            free(cp);
        }
	(void) fputc('\n', stdout);
    }

    return;
}



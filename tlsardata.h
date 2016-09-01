/*
 * tlsastruct.h
 *
 */

#ifndef __TLSASTRUCT_H__
#define __TLSASTRUCT_H__

/* 
 * tlsa_rdata: structure to hold TLSA record rdata.
 * insert_tlsa_rdata(): insert node at tail of linked list of tlsa_rdata.
 * free_tlsa(): free memory in the linked list.
 */

typedef struct tlsa_rdata {
    uint8_t usage;
    uint8_t selector;
    uint8_t mtype;
    unsigned long data_len;
    uint8_t *data;
    struct tlsa_rdata *next;
} tlsa_rdata;

tlsa_rdata *
insert_tlsa_rdata(tlsa_rdata **headp, tlsa_rdata *current, tlsa_rdata *new);

void free_tlsa(tlsa_rdata *head);

void print_tlsa(tlsa_rdata *tlist);

#endif /* __TLSASTRUCT_H__ */

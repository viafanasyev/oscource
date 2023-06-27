#ifndef JOS_KERN_ALLOCATOR_H
#define JOS_KERN_ALLOCATOR_H

#include <inc/types.h>

/* block header */
struct header {
    /* next block */
    struct header *next;
    /* prev block */
    struct header *prev;
    /* size of this block */
    size_t size;
} __attribute__((packed, aligned(_Alignof(max_align_t))));

typedef struct header Header;

void
init_help_allocator();

void *
alloc(size_t nbytes);

void
free(void *ap);

#endif

#include <inc/types.h>
#include <kern/allocator.h>
#include <inc/assert.h>
#include <kern/spinlock.h>
#include <inc/memlayout.h>
#include <kern/pmap.h>
#include <inc/string.h>

#define SPACE_SIZE (1024 * PAGE_SIZE)

static uint8_t *space = NULL;
static Header base = { .next = NULL, .prev = NULL };
static Header *freep = NULL;

static struct spinlock lock;

void
init_help_allocator() {
    space = kzalloc_region(SPACE_SIZE);
    memset(space, 0, ROUNDUP(SPACE_SIZE, PAGE_SIZE));

    base.next = (Header *)space;
    base.prev = (Header *)space;
    freep = NULL;
}

static void
check_list(void) {
    Header *prevp = freep, *p = prevp->next;
    for (; p != freep; p = p->next) {
        if (prevp != p->prev) panic("Corrupted list.\n");
        prevp = p;
    }
}

/* malloc: general-purpose storage allocator */
void *
alloc(size_t nbytes) {
    size_t nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1;

    spin_lock(&lock);

    /* no free list yet */
    if (!freep) {
        Header *hd = (Header *)space;

        hd->next = (Header *)&base;
        hd->prev = (Header *)&base;
        hd->size = (SPACE_SIZE - sizeof(Header)) / sizeof(Header);

        freep = &base;
    }

    check_list();

    for (Header *p = freep->next;; p = p->next) {
        /* big enough */
        if (p->size >= nunits) {
            freep = p->prev;
            /* exactly */
            if (p->size == nunits) {
                p->prev->next = p->next;
                p->next->prev = p->prev;
            } else { /* allocate tail end */
                p->size -= nunits;
                p += p->size;
                p->size = nunits;
            }
            spin_unlock(&lock);
            return (void *)(p + 1);
        }

        /* wrapped around free list */
        if (p == freep) {
            spin_unlock(&lock);
            return NULL;
        }
    }
}

/* free: put block ap in free list */
void
free(void *ap) {
    assert(ap >= (void*) space && ap < (void*) space + SPACE_SIZE);

    /* point to block header */
    Header *bp = (Header *)ap - 1;

    spin_lock(&lock);

    /* freed block at start or end of arena */
    Header *p = freep;
    for (; !(bp > p && bp < p->next); p = p->next) {
        if (p >= p->next && (bp > p || bp < p->next)) break;
    }

    if (bp + bp->size == p->next && p + p->size == bp) /* join to both */ {
        p->size += bp->size + p->next->size;
        p->next->next->prev = p;
        p->next = p->next->next;
    } else if (bp + bp->size == p->next) /* join to upper nbr */ {
        bp->size += p->next->size;
        bp->next = p->next->next;
        bp->prev = p->next->prev;
        p->next->next->prev = bp;
        p->next = bp;
    } else if (p + p->size == bp) /* join to lower nbr */ {
        p->size += bp->size;
    } else {
        bp->next = p->next;
        bp->prev = p;
        p->next->prev = bp;
        p->next = bp;
    }
    freep = p;

    check_list();

    spin_unlock(&lock);
}

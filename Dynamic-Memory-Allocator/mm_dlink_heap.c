/*
 * 	mm_dlink_heap.c
 *
 * 	Implement doubly linked structure of heap memory
 * 	Based on the description on assignment3 and notes on piazza
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include "memlib.h"
#include "mm_heap.h"

#include <errno.h>
#include <stdbool.h>

static const size_t min_size = 4 ; // header, footer and two ptrs, so the minimum size of a block is 4

/** Header/footer information for allocated blocks */
typedef union Header {
    struct {
        size_t allocated;                 	 // allocated if the bit is "1" and is free if the bit is "0"
        size_t size: 8 * sizeof(size_t) - 1; // size of this block including header and footer
    } s;
    union Header *ptr;						 // pointer to adjacent block on free list
    max_align_t _align;              		 // force alignment to max align boundary
} Header;

/* forward declarations */
static Header *morecore(size_t);
void visualize(const char*);
static void join_freelist(Header *bp);
static Header *block_allocate(size_t nunits);

/** Start of free memory list */
static Header *freep = NULL;

/**
 * Initialize the free list to origin
 */
inline static void list_init() {
	// if memory is not big enough
	if (mem_sbrk((min_size + 1) * sizeof(Header)) == NULL) {
		return;
	}
 	// the initial set for free list and
	freep = mem_heap_lo();
	freep[0].s.size = min_size;
	freep[0].s.allocated = 1; // protected
	//copy header as footer
	freep[3].s.size = freep[0].s.size;
	freep[3].s.allocated = freep[0].s.allocated;
	freep[1].ptr = freep[2].ptr = mem_heap_lo();
	// add tail header
	freep[0+min_size].s.size = 1;
	freep[0+min_size].s.allocated = 1;
}

/**
 * Initialize memory allocator.
 */
void mm_init() {
	mem_init();
	list_init();     //initialize the list
}

/**
 * Reset memory allocator
 */
void mm_reset() {
	mem_reset_brk();
	list_init();		//initialize the list again
}

/**
* De-initialize memory allocator
*/
void mm_deinit() {
	mem_deinit();
	freep = NULL; // clean free list
}

/**
 * Allocation units for nbytes
 *
 * @param nbytes number of bytes
 * @return number of units for nbytes
 */
inline static size_t mm_units(size_t nbytes) {
    /* smallest count of Header-sized memory chunks */
    return (nbytes + sizeof(Header) - 1) / sizeof(Header) + 2;
}

/**
 * Allocation bytes for nunits.
 *
 * @param nunits number of units
 * @return number of bytes for nunits
 */
inline static size_t mm_bytes(size_t nunits) {
    return nunits * sizeof(Header);
}

/**
 * Allocates size bytes of memory and returns a pointer to the
 * allocated memory, or NULL if request storage cannot be allocated.
 * (set the global variable errno to ENOMEM if failed)
 *
 * @param nbytes the number of bytes to allocate
 * @return pointer to allocated memory or NULL if not available
 */
void *mm_malloc(size_t nbytes) {
    if (freep == NULL) {
    	mm_init();
    }

    // smallest count of Header-sized memory chunks
    // (+2 additional chunk for the Header and Footer) needed to hold nbytes */
    size_t nunits = mm_units(nbytes);
    if (nunits < min_size) nunits = min_size;

    Header *p = block_allocate(nunits);
    if (p == NULL) {
    	errno = ENOMEM;  // c specification
    	return NULL;    // none left
    }
    return (void *)(p + 1);
}

/**
 * Locate the block header using the pointer passing (can be interior)
 *
 * @param ap pointer to target block
 * @return the target block pointer
 */
static Header *locate_block(void *ap) {
	//Invalid pointer
    if (ap <= mem_heap_lo() || ap >= mem_heap_hi() || ap == NULL) {
    	return NULL;
    }

    Header *bp;

    if (((uintptr_t)ap & (sizeof(max_align_t)-1)) == 0) { // see if ap is the pointer aligned
		bp = (Header*)ap - 1;  // find the point to block header
		if (bp[0].s.allocated == 1) {
			size_t nunits = bp[0].s.size;
			if (nunits >= min_size) {
				// cheak if header and footer are the same
				if ((bp[0].s.allocated == bp[nunits-1].s.allocated) && (bp[0].s.size == bp[nunits-1].s.size)) {
					return bp;
				}
			}
		}
    }
    // search for the block contains passing pointer
    bp = mem_heap_lo();
    for (Header *next = bp + bp[0].s.size;
    		(void*)next <= ap;
    		bp = next,
    		next = next + bp[0].s.size) {
    }
    // if the block is allocated, return block pointer
    if (bp[0].s.allocated == 1) {
    	return bp;
    } else {
    	return NULL;
    }
}

/**
 * Deallocates the memory allocation pointed to by ptr.
 * if ptr is a NULL pointer, no operation is performed.
 * The function find the block using the locate_block function,
 * the pointer passing can be interior to the memory being free.
 * (set the global variable errno to EFAULT if failed).
 *
 * @param ap the allocated storage to free
 */
void mm_free(void *ap) {
	if (ap == NULL) {
		return;
	}
	// locate block using the pointer passing (can be interior)
	Header *bp = locate_block(ap);
 	if (bp == NULL) {
		errno = EFAULT;  // C specification
	} else {
		// add blocks to free list
		join_freelist(bp);
	}
}

/**
 * Reallocates size bytes of memory and returns a pointer to the
 * allocated memory, or NULL if request storage cannot be allocated.
 * The function find the block using the locate_block function,
 * the pointer passing can be interior to the memory being free.
 * (set the global variable errno to EFAULT if failed)
 *
 * @param ap the currently allocated storage
 * @param nbytes the number of bytes to allocate
 * @return pointer to allocated memory or NULL if not available.
 */
void *mm_realloc(void *ap, size_t nbytes) {
	if (ap == NULL) {
		return mm_malloc(nbytes);
	}
	// locate block using the pointer passing (can be interior)
	Header *bp = locate_block(ap);
	if (bp == NULL) {
		errno = EFAULT; // C specification
		return NULL;
	}

    size_t oldsize = bp->s.size;
    size_t nunits = mm_units(nbytes);
    if (oldsize >= nunits) {
    	return ap;
    }

    Header *newbp = block_allocate(nunits);
    if (newbp == NULL) {
    	return NULL;
    }
    void *newap = (void *)(newbp + 1);  // payload pointer
    // copy to new storage and free old storage
    size_t apbytes = mm_bytes(oldsize-2); // remove header and footer
    memcpy(newap, ap, apbytes);
    join_freelist(bp);

    return newap;
}
 /**
 * Allocate requested sized block from free list,
 * adjusting the block size to split the block
 * and increase heap memory if needed.
 *
 *
 * @param nunits the requested size of the block
 * @return pointer to free list
 */
static Header *block_allocate(size_t nunits) {
    // traverse the circular list to find a block
	// first fit algorithm
    Header *bp = freep;
    while(true) {
    	if ((bp[0].s.allocated == 0) && (bp[0].s.size >= nunits)) { // free and big enough
             if (bp->s.size < nunits + min_size) { // no need to split
            	// if is freep, move to previous block
            	if (freep == bp) {
            		freep = bp[1].ptr;
            	}
             	// remove the allocated block by connecting previous block to the next block
            	Header *next = bp[2].ptr;
            	Header *prev = bp[1].ptr;
            	prev[2].ptr = next;
            	next[1].ptr = prev;
            	// offset for next block
                size_t offset = bp[0].s.size;
                bp[0].s.allocated = bp[offset-1].s.allocated = 1;
            } else {								// split allocate tail end
            	size_t offset = bp[0].s.size - nunits;
                bp[0].s.size -= nunits;
                bp[offset-1].s.size = bp[0].s.size;
                // adjust the size to split the block and mark block allocated
                bp[offset].s.size = nunits; //header
                bp[offset+nunits-1].s.size = nunits; //footer
                bp[offset].s.allocated = 1;
                bp[offset+nunits-1].s.allocated = 1;
                // find address of header of allocated section
                bp+= offset;
            }
            // return found address to insert
            return bp;
        }
     	// loop next
    	bp = bp[2].ptr;

        if (bp == freep) {                    // wrapped around free list */
        	bp = morecore(nunits);            // need more storage
        	if (bp == NULL) {
                return NULL;                // none left
            }
        }
    }
}

/**
 * This function is for putting target block back to free list, using by free
 * and realloc, coalescing adjacent blocks and reset the freep to this block.
 *
 * @param bp the target block pointer
 */
static void join_freelist(Header *bp) {
	size_t nunits = bp->s.size;
	bp[0].s.allocated = 0; // mark header and footer free
	bp[nunits-1].s.allocated = 0;
 	if (bp[-1].s.allocated == 0) {
 		// merging below: adjust the size
		bp -= bp[-1].s.size;
		nunits+= bp[0].s.size;  // combined size
		bp[0].s.size = nunits;
		bp[nunits-1].s.size = nunits;
	} else  {
		// set the lower pointer, connect below
		Header *nextp = freep[2].ptr;
		freep[2].ptr = nextp[1].ptr = bp;
		bp[1].ptr = freep;
		bp[2].ptr = nextp;
	}

	freep = bp;

	if (bp[nunits].s.allocated == 0) {
		// merging upper: adjust the size
		// take upper adjacent block out of free list
		Header *up = bp + nunits;
		Header *next = up[2].ptr;
		Header *prev = up[1].ptr;
		prev[2].ptr = next;
		next[1].ptr = prev;
		// combined with the block
		nunits+= bp[nunits].s.size;  // set new size
		bp[0].s.size = nunits;    // header
		bp[nunits-1].s.size = nunits; // footer
	}
}

 /**
 * Request additional memory to be added to this process.
 *
 * @param nu the number of Header-chunks to be added
 * @return pointer to a block that is large enough.
 */
static Header *morecore(size_t nu) {
	// nalloc based on page size
	size_t nalloc = mm_units(mem_pagesize());
 	// get at least a page-size of chunk from the OS
    if (nu < nalloc) {
    	nu = nalloc;
    }

    size_t nbytes = mm_bytes(nu);             // number of bytes
    void *cp = (void *) mem_sbrk(nbytes);
    if (cp == (void *) -1) {                 // no space at all
        return NULL;
    }
    // initialize new block
    Header *bp = (Header*)cp - 1;
    bp[0].s.size = bp[nu-1].s.size = nu;
    bp[0].s.allocated = bp[nu-1].s.allocated = 0;
    bp[nu].s.size = 1;  // set tail header
    bp[nu].s.allocated = 1;

    join_freelist(bp); // add new space to free list
    return freep;
}

/**
 * Print the free list (educational purpose)
 *
 * @msg the initial message to print
 */
void visualize(const char* msg) {
    fprintf(stderr, "\n--- Free list after \"%s\":\n", msg);
    // does not exist
    if (freep == NULL) {
        fprintf(stderr, "    List does not exist\n\n");
        return;
    }
    // self-pointing list = empty
    if (freep == freep[1].ptr) {
        fprintf(stderr, "    List is empty\n\n");
        return;
    }
    Header *tmp = freep;
    char *str = "    ";
    // traverse the list
    do {
    	fprintf(stderr, "0x%p: %s blocks: %zu alloc: %d prev: 0x%p next: 0x%p\n", tmp, str, tmp[0].s.size, tmp[0].s.allocated, tmp[1].ptr, tmp[2].ptr);
		str = " -> ";
		tmp = tmp[2].ptr;
    }  while (tmp != freep);
    fprintf(stderr, "--- end\n\n");
}


/**
 * Calculate the total amount of available free memory,
 * excluding headers and footers.
 *
 * @return the amount of free memory in bytes
 */
size_t mm_getfree(void) {
    if (freep == NULL) {
        return 0;
    }
     Header *tmp = freep;
    size_t res = tmp[0].s.size;
     while (tmp[1].ptr != freep) {
    	if (tmp[0].s.allocated == 0) {
			res += tmp[0].s.size - 2;  // excluding headers and footers.
			tmp = tmp[1].ptr;
    	}
    }
     return mm_bytes(res);
}

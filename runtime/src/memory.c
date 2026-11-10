/*
 * Guest address space and guest heap.
 *
 * The whole 4 GiB guest space is reserved once (MAP_NORESERVE, pages are
 * committed lazily by the kernel). The first 64 KiB are PROT_NONE so guest
 * NULL dereferences fault like on a real device.
 *
 * The heap is a simple thread-safe segregated-fit allocator: sizes are
 * rounded to a class, freed blocks go to a per-class LIFO list and are reused
 * for the same class. It is not the most memory-efficient design but it is
 * fast, predictable and entirely inside guest memory.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "runtime.h"

uint8_t *g_base;

static pthread_mutex_t heap_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t heap_top = GUEST_HEAP_START;

#define HDR 16u
#define MAGIC 0x4e563348u /* 'NV3H' */
#define NCLASSES 240

typedef struct { uint32_t cap; uint32_t magic; uint32_t back; uint32_t pad; } BlockHdr;

static uint32_t free_head[NCLASSES];

int rt_mem_init(void) {
    if (g_base) return 0;
    void *p = mmap(NULL, 0x100000000ull, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        rt_log("failed to reserve 4 GiB guest window: %s", strerror(errno));
        return -1;
    }
    g_base = (uint8_t *)p;
    mprotect(g_base, GUEST_NULL_GUARD, PROT_NONE);
    return 0;
}

uint32_t H2G(const void *p) {
    uintptr_t d = (uintptr_t)p - (uintptr_t)g_base;
    if (!p) return 0;
    if (d >= 0x100000000ull) {
        rt_log("H2G: host pointer %p outside guest window", p);
        abort();
    }
    return (uint32_t)d;
}

/* size class: multiples of 16 up to 1 KiB, then 8 steps per power of two */
static int size_class(uint32_t sz, uint32_t *cap) {
    if (sz <= 1024) {
        uint32_t c = (sz + 15) / 16; if (!c) c = 1;
        *cap = c * 16; return (int)c - 1;              /* 0..63 */
    }
    int lg = 31 - __builtin_clz(sz - 1);              /* sz in (2^lg, 2^(lg+1)] */
    uint32_t step = 1u << (lg - 3);
    uint32_t c = ((sz - 1) >> (lg - 3)) & 7;           /* 0..7 */
    uint64_t capv = (1ull << lg) + (uint64_t)(c + 1) * step;
    *cap = (uint32_t)capv;
    int idx = 64 + (lg - 10) * 8 + (int)c;
    return idx < NCLASSES ? idx : -1;
}

static uint32_t bump(uint32_t total) {
    uint32_t a = heap_top;
    if ((uint64_t)a + total > GUEST_HEAP_END) return 0;
    heap_top += (total + 15u) & ~15u;
    return a;
}

uint32_t gmalloc(uint32_t size) {
    uint32_t cap;
    if (size == 0) size = 1;
    if (size > 0xC0000000u) return 0;
    int cls = size_class(size, &cap);
    pthread_mutex_lock(&heap_lock);
    uint32_t blk = 0;
    if (cls >= 0 && free_head[cls]) {
        blk = free_head[cls];
        free_head[cls] = LD32(blk + HDR);
    } else {
        blk = bump(cap + HDR);
    }
    pthread_mutex_unlock(&heap_lock);
    if (!blk) return 0;
    BlockHdr h = { cap, MAGIC, 0, 0 };
    memcpy(G2H(blk), &h, sizeof h);
    return blk + HDR;
}

static uint32_t real_block(uint32_t p, BlockHdr *h) {
    memcpy(h, G2H(p - HDR), sizeof *h);
    if (h->magic == MAGIC + 1) {          /* aligned block: points back */
        uint32_t blk = h->back;
        memcpy(h, G2H(blk), sizeof *h);
        return blk;
    }
    return p - HDR;
}

void gfree(uint32_t p) {
    if (!p) return;
    BlockHdr h;
    uint32_t blk = real_block(p, &h);
    if (h.magic != MAGIC) {
        rt_log("gfree: invalid pointer 0x%08x", p);
        return;
    }
    uint32_t cap;
    int cls = size_class(h.cap, &cap);
    if (cls < 0) return;
    if (h.cap >= (256u << 10)) {          /* return big blocks' pages to the OS */
        uint32_t s = (blk + HDR + 32 + 0xFFFu) & ~0xFFFu, e = (blk + HDR + h.cap) & ~0xFFFu;
        if (e > s) madvise(G2H(s), e - s, MADV_DONTNEED);
    }
    pthread_mutex_lock(&heap_lock);
    ST32(blk + HDR, free_head[cls]);
    free_head[cls] = blk;
    pthread_mutex_unlock(&heap_lock);
}

uint32_t gusable(uint32_t p) {
    BlockHdr h;
    uint32_t blk = real_block(p, &h);
    return h.cap - (p - blk - HDR);
}

uint32_t gcalloc(uint32_t n, uint32_t size) {
    uint64_t t = (uint64_t)n * size;
    if (t > 0xC0000000u) return 0;
    uint32_t p = gmalloc((uint32_t)t);
    if (p) memset(G2H(p), 0, (size_t)t);
    return p;
}

uint32_t grealloc(uint32_t p, uint32_t size) {
    if (!p) return gmalloc(size);
    if (!size) { gfree(p); return 0; }
    uint32_t old = gusable(p);
    if (size <= old && size > old / 2) return p;
    uint32_t q = gmalloc(size);
    if (!q) return 0;
    memcpy(G2H(q), G2H(p), old < size ? old : size);
    gfree(p);
    return q;
}

uint32_t gmemalign(uint32_t align, uint32_t size) {
    if (align <= 16) return gmalloc(size);
    uint32_t raw = gmalloc(size + align + HDR);
    if (!raw) return 0;
    uint32_t a = (raw + HDR + align - 1) & ~(align - 1);
    if (a == raw) return raw;
    BlockHdr h = { 0, MAGIC + 1, raw - HDR, 0 };
    memcpy(G2H(a - HDR), &h, sizeof h);
    return a;
}

uint32_t gstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    uint32_t p = gmalloc((uint32_t)n);
    if (p) memcpy(G2H(p), s, n);
    return p;
}

/* anonymous mappings (mmap from guest) come from the same bump area */
uint32_t gmap_anon(uint32_t size) {
    size = (size + 0xFFFu) & ~0xFFFu;
    pthread_mutex_lock(&heap_lock);
    heap_top = (heap_top + 0xFFFu) & ~0xFFFu;
    uint32_t a = bump(size);
    pthread_mutex_unlock(&heap_lock);
    if (a) memset(G2H(a), 0, size);
    return a;
}

void gunmap(uint32_t addr, uint32_t size) {
    /* give the pages back to the kernel; the range itself is not reused */
    size = (size + 0xFFFu) & ~0xFFFu;
    if (addr >= GUEST_HEAP_START && addr + size <= GUEST_HEAP_END)
        madvise(G2H(addr & ~0xFFFu), size, MADV_DONTNEED);
}

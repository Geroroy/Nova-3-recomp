/* Tiny thread-safe uint32 -> pointer hash map (guest object -> host object). */
#ifndef NOVA3_HMAP_H
#define NOVA3_HMAP_H
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { uint32_t key; void *val; } HEntry;
typedef struct {
    HEntry *e; uint32_t cap, n;
    pthread_mutex_t lock;
} HMap;

#define HMAP_INIT { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER }

static inline uint32_t hm_hash(uint32_t k) { k ^= k >> 16; k *= 0x7feb352du; k ^= k >> 15; k *= 0x846ca68bu; k ^= k >> 16; return k; }

static void hm_grow(HMap *m);
static inline void *hm_get_locked(HMap *m, uint32_t k) {
    if (!m->cap) return NULL;
    for (uint32_t i = hm_hash(k) & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
        if (m->e[i].key == k) return m->e[i].val;
        if (!m->e[i].key) return NULL;
    }
}
static inline void hm_put_locked(HMap *m, uint32_t k, void *v) {
    if ((m->n + 1) * 2 > m->cap) hm_grow(m);
    for (uint32_t i = hm_hash(k) & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
        if (m->e[i].key == k) { m->e[i].val = v; return; }
        if (!m->e[i].key) { m->e[i].key = k; m->e[i].val = v; m->n++; return; }
    }
}
static void hm_grow(HMap *m) {
    HEntry *old = m->e; uint32_t oc = m->cap;
    m->cap = oc ? oc * 2 : 64; m->e = calloc(m->cap, sizeof(HEntry)); m->n = 0;
    for (uint32_t i = 0; i < oc; i++) if (old[i].key && old[i].val) hm_put_locked(m, old[i].key, old[i].val);
    free(old);
}
static inline void *hm_get(HMap *m, uint32_t k) { pthread_mutex_lock(&m->lock); void *v = hm_get_locked(m, k); pthread_mutex_unlock(&m->lock); return v; }
static inline void hm_put(HMap *m, uint32_t k, void *v) { pthread_mutex_lock(&m->lock); hm_put_locked(m, k, v); pthread_mutex_unlock(&m->lock); }
/* deletion marks the value NULL (tombstone keeps probing chains intact) */
static inline void *hm_del(HMap *m, uint32_t k) {
    pthread_mutex_lock(&m->lock);
    void *v = NULL;
    if (m->cap) for (uint32_t i = hm_hash(k) & (m->cap - 1);; i = (i + 1) & (m->cap - 1)) {
        if (m->e[i].key == k) { v = m->e[i].val; m->e[i].val = NULL; break; }
        if (!m->e[i].key) break;
    }
    pthread_mutex_unlock(&m->lock);
    return v;
}
#endif

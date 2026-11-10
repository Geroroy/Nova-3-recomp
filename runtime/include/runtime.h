/* Host-side runtime API. */
#ifndef NOVA3_RUNTIME_H
#define NOVA3_RUNTIME_H
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include "recomp.h"
#include "module.h"

#ifdef __cplusplus
extern "C" {
#endif

/* guest address-space layout */
#define GUEST_NULL_GUARD   0x00010000u
#define GUEST_HEAP_START   0x40000000u
#define GUEST_HEAP_END     0xF0000000u
#define GUEST_THUNK_BASE   0xFF000000u   /* host function thunks (4 bytes each) */
#define GUEST_THUNK_MAX    0x00100000u

/* ---- init / modules */
int  rt_init(void);
int  rt_load_module(const ModuleInfo *m, const void *file, size_t size);
int  rt_load_module_file(const ModuleInfo *m, const char *path);
void rt_run_initializers(const ModuleInfo *m);
uint32_t rt_module_symbol(const ModuleInfo *m, const char *name);   /* guest addr or 0 */
uint32_t rt_lookup_symbol(const char *name);                        /* all modules + host */

/* ---- logging */
void rt_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern int rt_trace_imports;
extern int rt_abort_on_unimplemented;

/* ---- threads / CPU */
CPU *rt_cpu(void);                   /* CPU of the calling host thread (created on demand) */
uint32_t rt_errno_addr(CPU *c);

/* call a guest function from host code (AAPCS softfp), returns r0 (r1 in *hi) */
uint32_t guest_call(uint32_t addr, int nargs, const uint32_t *args);
uint64_t guest_call64(uint32_t addr, int nargs, const uint32_t *args);
uint32_t guest_call0(uint32_t addr);
uint32_t guest_call1(uint32_t addr, uint32_t a0);
uint32_t guest_call2(uint32_t addr, uint32_t a0, uint32_t a1);
uint32_t guest_call3(uint32_t addr, uint32_t a0, uint32_t a1, uint32_t a2);
uint32_t guest_call4(uint32_t addr, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);

/* ---- host functions callable by guest code */
typedef struct { const char *name; guest_fn fn; } HostFunc;
typedef struct { const char *name; uint32_t size; void (*init)(uint32_t gaddr); } HostData;
void rt_register_host_funcs(const HostFunc *tab);
void rt_register_host_data(const HostData *tab);
guest_fn rt_find_host_func(const char *name);
uint32_t rt_host_thunk(const char *name, guest_fn fn);  /* guest-callable address */

/* ---- guest heap */
uint32_t gmalloc(uint32_t size);
uint32_t gcalloc(uint32_t n, uint32_t size);
uint32_t grealloc(uint32_t p, uint32_t size);
uint32_t gmemalign(uint32_t align, uint32_t size);
void     gfree(uint32_t p);
uint32_t gusable(uint32_t p);
uint32_t gstrdup(const char *s);                 /* copy a host string into guest heap */
uint32_t gmap_anon(uint32_t size);               /* page-aligned zeroed region */
void     gunmap(uint32_t addr, uint32_t size);
uint32_t H2G(const void *p);                     /* host pointer inside window -> guest */

/* ---- argument helpers for host functions */
static inline uint32_t ARG(CPU *c, int n) { return n < 4 ? c->r[n] : LD32(c->r[13] + 4u * (uint32_t)(n - 4)); }
static inline const char *ARGS(CPU *c, int n) { uint32_t p = ARG(c, n); return p ? (const char *)G2H(p) : NULL; }
static inline void *ARGP(CPU *c, int n) { return G2HN(ARG(c, n)); }
static inline void RET32(CPU *c, uint32_t v) { c->r[0] = v; }
static inline void RET64(CPU *c, uint64_t v) { c->r[0] = (uint32_t)v; c->r[1] = (uint32_t)(v >> 32); }
static inline void RETF(CPU *c, float f) { uint32_t v; memcpy(&v, &f, 4); c->r[0] = v; }
static inline void RETD(CPU *c, double d) { uint64_t v; memcpy(&v, &d, 8); RET64(c, v); }
static inline float ARGF(CPU *c, int n) { uint32_t v = ARG(c, n); float f; memcpy(&f, &v, 4); return f; }
/* 64-bit argument starting at register/slot n (caller passes the aligned index) */
static inline uint64_t ARG64(CPU *c, int n) { return (uint64_t)ARG(c, n) | ((uint64_t)ARG(c, n + 1) << 32); }
static inline double ARGD(CPU *c, int n) { uint64_t v = ARG64(c, n); double d; memcpy(&d, &v, 8); return d; }

/* variadic argument reader (AAPCS): either live registers+stack or a va_list pointer */
typedef struct { CPU *c; int reg; uint32_t mem; int use_mem; } GVa;
static inline void gva_start(GVa *va, CPU *c, int first) {
    va->c = c; va->reg = first; va->use_mem = 0; va->mem = c->r[13];
    if (first >= 4) { va->use_mem = 1; va->mem = c->r[13] + 4u * (uint32_t)(first - 4); }
}
static inline void gva_from_list(GVa *va, uint32_t ap) { va->c = NULL; va->use_mem = 1; va->mem = ap; va->reg = 4; }
static inline uint32_t gva_u32(GVa *va) {
    if (!va->use_mem) { uint32_t v = va->c->r[va->reg++]; if (va->reg == 4) va->use_mem = 1; return v; }
    uint32_t v = LD32(va->mem); va->mem += 4; return v;
}
static inline uint64_t gva_u64(GVa *va) {
    if (!va->use_mem) {
        if (va->reg & 1) va->reg++;
        if (va->reg <= 2) { uint64_t v = (uint64_t)va->c->r[va->reg] | ((uint64_t)va->c->r[va->reg + 1] << 32);
                            va->reg += 2; if (va->reg == 4) va->use_mem = 1; return v; }
        va->use_mem = 1;
    }
    va->mem = (va->mem + 7u) & ~7u; uint64_t v = LD64(va->mem); va->mem += 8; return v;
}
/* guest printf-style formatting into a host buffer; returns length that would have been written */
int gfmt(char *out, size_t cap, const char *fmt, GVa *va);

#ifdef __cplusplus
}
#endif
#endif

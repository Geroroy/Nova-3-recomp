/* bionic libc bridge: memory, strings, ctype, stdlib, AEABI helpers. */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "runtime.h"

#define H(n) static void n(CPU *c)
#define S(n) ((char *)ARGP(c, n))
#define P(n) ARG(c, n)

void rt_set_errno(CPU *c, int e);

/* ---------------------------------------------------------------- memory */
H(h_memcpy)  { memmove(G2H(P(0)), G2H(P(1)), P(2)); }            /* r0 preserved */
H(h_memmove) { memmove(G2H(P(0)), G2H(P(1)), P(2)); }
H(h_memset)  { memset(G2H(P(0)), (int)P(1), P(2)); }
H(h_aeabi_memset) { memset(G2H(P(0)), (int)P(2), P(1)); }        /* (dest, n, c) */
H(h_aeabi_memclr) { memset(G2H(P(0)), 0, P(1)); }
H(h_bzero)   { memset(G2H(P(0)), 0, P(1)); }
H(h_memcmp)  { RET32(c, (uint32_t)memcmp(G2H(P(0)), G2H(P(1)), P(2))); }
H(h_memchr)  { void *r = memchr(G2H(P(0)), (int)P(1), P(2)); RET32(c, r ? H2G(r) : 0); }
H(h_memrchr) { void *r = memrchr(G2H(P(0)), (int)P(1), P(2)); RET32(c, r ? H2G(r) : 0); }
H(h_strlen)  { RET32(c, (uint32_t)strlen(S(0))); }
H(h_strnlen) { RET32(c, (uint32_t)strnlen(S(0), P(1))); }
H(h_strcpy)  { strcpy(S(0), S(1)); }
H(h_strncpy) { strncpy(S(0), S(1), P(2)); }
H(h_strlcpy) { const char *s = S(1); size_t n = strlen(s), m = P(2);
               if (m) { size_t k = n < m - 1 ? n : m - 1; memcpy(S(0), s, k); S(0)[k] = 0; } RET32(c, (uint32_t)n); }
H(h_strlcat) { char *d = S(0); const char *s = S(1); size_t m = P(2), dl = strnlen(d, m), sl = strlen(s);
               if (dl < m) { size_t k = sl < m - dl - 1 ? sl : m - dl - 1; memcpy(d + dl, s, k); d[dl + k] = 0; }
               RET32(c, (uint32_t)(dl + sl)); }
H(h_strcat)  { strcat(S(0), S(1)); }
H(h_strncat) { strncat(S(0), S(1), P(2)); }
H(h_strcmp)  { RET32(c, (uint32_t)strcmp(S(0), S(1))); }
H(h_strncmp) { RET32(c, (uint32_t)strncmp(S(0), S(1), P(2))); }
H(h_strcasecmp)  { RET32(c, (uint32_t)strcasecmp(S(0), S(1))); }
H(h_strncasecmp) { RET32(c, (uint32_t)strncasecmp(S(0), S(1), P(2))); }
H(h_strcoll) { RET32(c, (uint32_t)strcmp(S(0), S(1))); }
H(h_strchr)  { char *r = strchr(S(0), (int)P(1)); RET32(c, r ? H2G(r) : 0); }
H(h_strrchr) { char *r = strrchr(S(0), (int)P(1)); RET32(c, r ? H2G(r) : 0); }
H(h_strstr)  { char *r = strstr(S(0), S(1)); RET32(c, r ? H2G(r) : 0); }
H(h_strcasestr) { char *r = strcasestr(S(0), S(1)); RET32(c, r ? H2G(r) : 0); }
H(h_strpbrk) { char *r = strpbrk(S(0), S(1)); RET32(c, r ? H2G(r) : 0); }
H(h_strspn)  { RET32(c, (uint32_t)strspn(S(0), S(1))); }
H(h_strcspn) { RET32(c, (uint32_t)strcspn(S(0), S(1))); }
H(h_strdup)  { RET32(c, gstrdup(S(0))); }
H(h_strndup) { const char *s = S(0); size_t n = strnlen(s, P(1)); uint32_t p = gmalloc((uint32_t)n + 1);
               memcpy(G2H(p), s, n); ST8(p + (uint32_t)n, 0); RET32(c, p); }
H(h_strtok_r) {
    uint32_t s = P(0), delim = P(1), save = P(2);
    if (!s) s = LD32(save);
    if (!s) { RET32(c, 0); return; }
    char *p = (char *)G2H(s) + strspn((char *)G2H(s), (char *)G2H(delim));
    if (!*p) { ST32(save, 0); RET32(c, 0); return; }
    char *e = p + strcspn(p, (char *)G2H(delim));
    if (*e) { *e = 0; ST32(save, H2G(e + 1)); } else ST32(save, 0);
    RET32(c, H2G(p));
}
static uint32_t strtok_state;
H(h_strtok) {
    if (!strtok_state) strtok_state = gcalloc(1, 4);
    c->r[2] = strtok_state; h_strtok_r(c);
}
H(h_strsep) {
    uint32_t sp = P(0), s = LD32(sp);
    if (!s) { RET32(c, 0); return; }
    char *p = (char *)G2H(s), *e = p + strcspn(p, S(1));
    if (*e) { *e = 0; ST32(sp, H2G(e + 1)); } else ST32(sp, 0);
    RET32(c, s);
}
static uint32_t strerror_buf;
H(h_strerror) {
    if (!strerror_buf) strerror_buf = gmalloc(256);
    strncpy((char *)G2H(strerror_buf), strerror((int)P(0)), 255);
    RET32(c, strerror_buf);
}
H(h_strerror_r) { strncpy(S(1), strerror((int)P(0)), P(2)); RET32(c, 0); }

/* ----------------------------------------------------------------- ctype */
H(h_isalpha)  { RET32(c, (uint32_t)!!isalpha((int)P(0))); }
H(h_isdigit)  { RET32(c, (uint32_t)!!isdigit((int)P(0))); }
H(h_isalnum)  { RET32(c, (uint32_t)!!isalnum((int)P(0))); }
H(h_isspace)  { RET32(c, (uint32_t)!!isspace((int)P(0))); }
H(h_isupper)  { RET32(c, (uint32_t)!!isupper((int)P(0))); }
H(h_islower)  { RET32(c, (uint32_t)!!islower((int)P(0))); }
H(h_isxdigit) { RET32(c, (uint32_t)!!isxdigit((int)P(0))); }
H(h_isprint)  { RET32(c, (uint32_t)!!isprint((int)P(0))); }
H(h_ispunct)  { RET32(c, (uint32_t)!!ispunct((int)P(0))); }
H(h_iscntrl)  { RET32(c, (uint32_t)!!iscntrl((int)P(0))); }
H(h_isgraph)  { RET32(c, (uint32_t)!!isgraph((int)P(0))); }
H(h_toupper)  { RET32(c, (uint32_t)toupper((int)P(0))); }
H(h_tolower)  { RET32(c, (uint32_t)tolower((int)P(0))); }

static void init_ctype(uint32_t a) {   /* bionic _ctype_: 1 + 256 entries */
    for (int i = 0; i < 256; i++) {
        uint8_t v = 0;
        if (i < 128) {
            if (isupper(i)) v |= 0x01;
            if (islower(i)) v |= 0x02;
            if (isdigit(i)) v |= 0x04;
            if (isspace(i)) v |= 0x08;
            if (ispunct(i)) v |= 0x10;
            if (iscntrl(i)) v |= 0x20;
            if (isxdigit(i)) v |= 0x40;
            if (i == ' ') v |= 0x80;
        }
        ST8(a + 1 + (uint32_t)i, v);
    }
}
static void init_tolower(uint32_t a) { ST16(a, 0xFFFF); for (int i = 0; i < 256; i++) ST16(a + 2 + 2u * (uint32_t)i, (uint32_t)(i < 128 ? tolower(i) : i)); }
static void init_toupper(uint32_t a) { ST16(a, 0xFFFF); for (int i = 0; i < 256; i++) ST16(a + 2 + 2u * (uint32_t)i, (uint32_t)(i < 128 ? toupper(i) : i)); }
/* _ctype_ etc. are pointers in newer bionic headers? No: arrays. Keep arrays. */

/* ---------------------------------------------------------------- stdlib */
H(h_malloc)  { RET32(c, gmalloc(P(0))); }
H(h_free)    { gfree(P(0)); }
H(h_calloc)  { RET32(c, gcalloc(P(0), P(1))); }
H(h_realloc) { RET32(c, grealloc(P(0), P(1))); }
H(h_memalign){ RET32(c, gmemalign(P(0), P(1))); }
H(h_valloc)  { RET32(c, gmemalign(4096, P(0))); }
H(h_posix_memalign) { uint32_t p = gmemalign(P(1), P(2)); ST32(P(0), p); RET32(c, p ? 0 : ENOMEM); }
H(h_malloc_usable_size) { RET32(c, P(0) ? gusable(P(0)) : 0); }
H(h_op_new)  { uint32_t p = gmalloc(P(0)); if (!p) { rt_log("operator new: out of memory"); abort(); } RET32(c, p); }

H(h_atoi)  { RET32(c, (uint32_t)atoi(S(0))); }
H(h_atol)  { RET32(c, (uint32_t)atol(S(0))); }
H(h_atoll) { RET64(c, (uint64_t)atoll(S(0))); }
H(h_atof)  { RETD(c, atof(S(0))); }
static void set_end(CPU *c, uint32_t endp, const char *base, char *end) {
    if (endp) ST32(endp, P(0) + (uint32_t)(end - base));
}
H(h_strtol)  { char *e; const char *s = S(0); errno = 0; long v = strtol(s, &e, (int)P(2));
               if (v > INT32_MAX) { v = INT32_MAX; errno = ERANGE; } else if (v < INT32_MIN) { v = INT32_MIN; errno = ERANGE; }
               set_end(c, P(1), s, e); rt_set_errno(c, errno); RET32(c, (uint32_t)v); }
H(h_strtoul) { char *e; const char *s = S(0); errno = 0; unsigned long v = strtoul(s, &e, (int)P(2));
               if (v > UINT32_MAX && (long)v > 0) { v = UINT32_MAX; errno = ERANGE; }
               set_end(c, P(1), s, e); rt_set_errno(c, errno); RET32(c, (uint32_t)v); }
H(h_strtoll) { char *e; const char *s = S(0); long long v = strtoll(s, &e, (int)P(2)); set_end(c, P(1), s, e); RET64(c, (uint64_t)v); }
H(h_strtoull){ char *e; const char *s = S(0); unsigned long long v = strtoull(s, &e, (int)P(2)); set_end(c, P(1), s, e); RET64(c, v); }
H(h_strtod)  { char *e; const char *s = S(0); double v = strtod(s, &e); set_end(c, P(1), s, e); RETD(c, v); }
H(h_strtof)  { char *e; const char *s = S(0); float v = strtof(s, &e); set_end(c, P(1), s, e); RETF(c, v); }
H(h_abs)     { int32_t v = (int32_t)P(0); RET32(c, (uint32_t)(v < 0 ? -v : v)); }

static uint32_t rand_state = 1;
H(h_srand)   { rand_state = P(0); }
H(h_rand)    { rand_state = rand_state * 1103515245u + 12345u; RET32(c, (rand_state >> 1) & 0x7fffffff); }
H(h_lrand48) { rand_state = rand_state * 1103515245u + 12345u; RET32(c, (rand_state >> 1) & 0x7fffffff); }
H(h_srand48) { rand_state = P(0); }
H(h_rand_r)  { uint32_t s = LD32(P(0)) * 1103515245u + 12345u; ST32(P(0), s); RET32(c, (s >> 1) & 0x7fffffff); }
H(h_arc4random) { RET32(c, (uint32_t)random() ^ ((uint32_t)random() << 16)); }

/* qsort / bsearch call back into guest code */
static void gsort(uint32_t base, uint32_t n, uint32_t sz, uint32_t cmp) {
    /* insertion sort for tiny arrays, otherwise heap-free merge via guest temp */
    if (n < 2) return;
    uint32_t tmp = gmalloc(sz);
    /* simple shell sort: no recursion, stable enough for game use */
    for (uint32_t gap = n / 2; gap > 0; gap /= 2) {
        for (uint32_t i = gap; i < n; i++) {
            memcpy(G2H(tmp), G2H(base + i * sz), sz);
            uint32_t j = i;
            while (j >= gap && (int32_t)guest_call2(cmp, base + (j - gap) * sz, tmp) > 0) {
                memcpy(G2H(base + j * sz), G2H(base + (j - gap) * sz), sz);
                j -= gap;
            }
            memcpy(G2H(base + j * sz), G2H(tmp), sz);
        }
    }
    gfree(tmp);
}
H(h_qsort) { gsort(P(0), P(1), P(2), P(3)); }
H(h_bsearch) {
    uint32_t key = P(0), base = P(1), n = P(2), sz = P(3), cmp = ARG(c, 4);
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        int32_t r = (int32_t)guest_call2(cmp, key, base + mid * sz);
        if (r == 0) { RET32(c, base + mid * sz); return; }
        if (r < 0) hi = mid; else lo = mid + 1;
    }
    RET32(c, 0);
}

static uint32_t env_cache[64];
static int nenv;
H(h_getenv) {
    const char *v = getenv(S(0));
    if (!v) { RET32(c, 0); return; }
    if (nenv < 64) { env_cache[nenv] = gstrdup(v); RET32(c, env_cache[nenv++]); }
    else RET32(c, gstrdup(v));
}
H(h_setenv)   { RET32(c, (uint32_t)setenv(S(0), S(1), (int)P(2))); }
H(h_unsetenv) { RET32(c, (uint32_t)unsetenv(S(0))); }

/* atexit handlers: run on exit() */
static struct { uint32_t fn, arg; } atexit_tab[256];
static int natexit;
H(h_cxa_atexit) { if (natexit < 256) { atexit_tab[natexit].fn = P(0); atexit_tab[natexit].arg = P(1); natexit++; } RET32(c, 0); }
H(h_atexit)     { if (natexit < 256) { atexit_tab[natexit].fn = P(0); atexit_tab[natexit].arg = 0; natexit++; } RET32(c, 0); }
H(h_cxa_finalize) { (void)c; }
H(h_exit) {
    int code = (int)P(0);
    while (natexit > 0) { natexit--; guest_call1(atexit_tab[natexit].fn, atexit_tab[natexit].arg); }
    fflush(stdout);
    exit(code);
}
H(h__exit) { _exit((int)P(0)); }
H(h_abort) { rt_log("guest called abort() (lr=0x%08x)", c->r[14]); abort(); }
H(h_stack_chk_fail) { rt_log("guest stack corruption detected (lr=0x%08x)", c->r[14]); abort(); }
H(h_assert2) { rt_log("assertion failed: %s:%d %s: %s", S(0), (int)P(1), S(2), S(3)); abort(); }
H(h_assert)  { rt_log("assertion failed: %s:%d %s", S(0), (int)P(1), S(2)); abort(); }
H(h_cxa_pure_virtual) { rt_log("pure virtual call"); abort(); }

/* ------------------------------------------------- AEABI integer helpers */
H(h_aeabi_idiv)  { RET32(c, sdiv32((int32_t)P(0), (int32_t)P(1))); }
H(h_aeabi_uidiv) { RET32(c, udiv32(P(0), P(1))); }
H(h_aeabi_idivmod)  { int32_t a = (int32_t)P(0), b = (int32_t)P(1);
                      c->r[0] = sdiv32(a, b); c->r[1] = b ? (uint32_t)(a - (int32_t)c->r[0] * b) : (uint32_t)a; }
H(h_aeabi_uidivmod) { uint32_t a = P(0), b = P(1); c->r[0] = b ? a / b : 0; c->r[1] = b ? a % b : a; }
H(h_aeabi_ldivmod)  { int64_t a = (int64_t)ARG64(c, 0), b = (int64_t)ARG64(c, 2);
                      int64_t q = b ? a / b : 0, r = b ? a % b : a;
                      c->r[0] = (uint32_t)q; c->r[1] = (uint32_t)((uint64_t)q >> 32);
                      c->r[2] = (uint32_t)r; c->r[3] = (uint32_t)((uint64_t)r >> 32); }
H(h_aeabi_uldivmod) { uint64_t a = ARG64(c, 0), b = ARG64(c, 2);
                      uint64_t q = b ? a / b : 0, r = b ? a % b : a;
                      c->r[0] = (uint32_t)q; c->r[1] = (uint32_t)(q >> 32);
                      c->r[2] = (uint32_t)r; c->r[3] = (uint32_t)(r >> 32); }
H(h_aeabi_lmul) { RET64(c, ARG64(c, 0) * ARG64(c, 2)); }
H(h_aeabi_llsl) { uint32_t n = P(2); RET64(c, n >= 64 ? 0 : ARG64(c, 0) << n); }
H(h_aeabi_llsr) { uint32_t n = P(2); RET64(c, n >= 64 ? 0 : ARG64(c, 0) >> n); }
H(h_aeabi_lasr) { uint32_t n = P(2); RET64(c, (uint64_t)((int64_t)ARG64(c, 0) >> (n >= 64 ? 63 : n))); }
H(h_aeabi_lcmp) { int64_t a = (int64_t)ARG64(c, 0), b = (int64_t)ARG64(c, 2); RET32(c, (uint32_t)(a < b ? -1 : a > b)); }
H(h_aeabi_ulcmp){ uint64_t a = ARG64(c, 0), b = ARG64(c, 2); RET32(c, (uint32_t)(a < b ? -1 : a > b)); }

static const HostFunc string_funcs[] = {
    {"memcpy", h_memcpy}, {"memmove", h_memmove}, {"memset", h_memset}, {"memcmp", h_memcmp},
    {"bcmp", h_memcmp}, {"memchr", h_memchr}, {"memrchr", h_memrchr}, {"bzero", h_bzero},
    {"__memcpy_chk", h_memcpy}, {"__memmove_chk", h_memmove}, {"__memset_chk", h_memset},
    {"__aeabi_memcpy", h_memcpy}, {"__aeabi_memcpy4", h_memcpy}, {"__aeabi_memcpy8", h_memcpy},
    {"__aeabi_memmove", h_memmove}, {"__aeabi_memmove4", h_memmove}, {"__aeabi_memmove8", h_memmove},
    {"__aeabi_memset", h_aeabi_memset}, {"__aeabi_memset4", h_aeabi_memset}, {"__aeabi_memset8", h_aeabi_memset},
    {"__aeabi_memclr", h_aeabi_memclr}, {"__aeabi_memclr4", h_aeabi_memclr}, {"__aeabi_memclr8", h_aeabi_memclr},
    {"strlen", h_strlen}, {"__strlen_chk", h_strlen}, {"strnlen", h_strnlen}, {"strcpy", h_strcpy},
    {"__strcpy_chk", h_strcpy}, {"strncpy", h_strncpy}, {"__strncpy_chk", h_strncpy},
    {"strlcpy", h_strlcpy}, {"strlcat", h_strlcat}, {"strcat", h_strcat}, {"__strcat_chk", h_strcat},
    {"strncat", h_strncat}, {"strcmp", h_strcmp}, {"strncmp", h_strncmp}, {"strcasecmp", h_strcasecmp},
    {"strncasecmp", h_strncasecmp}, {"strcoll", h_strcoll}, {"strchr", h_strchr}, {"__strchr_chk", h_strchr},
    {"strrchr", h_strrchr}, {"__strrchr_chk", h_strrchr}, {"strstr", h_strstr}, {"strcasestr", h_strcasestr},
    {"strpbrk", h_strpbrk}, {"strspn", h_strspn}, {"strcspn", h_strcspn}, {"strdup", h_strdup},
    {"strndup", h_strndup}, {"strtok", h_strtok}, {"strtok_r", h_strtok_r}, {"strsep", h_strsep},
    {"strerror", h_strerror}, {"strerror_r", h_strerror_r}, {"index", h_strchr}, {"rindex", h_strrchr},
    {"isalpha", h_isalpha}, {"isdigit", h_isdigit}, {"isalnum", h_isalnum}, {"isspace", h_isspace},
    {"isupper", h_isupper}, {"islower", h_islower}, {"isxdigit", h_isxdigit}, {"isprint", h_isprint},
    {"ispunct", h_ispunct}, {"iscntrl", h_iscntrl}, {"isgraph", h_isgraph}, {"toupper", h_toupper},
    {"tolower", h_tolower},
    {"malloc", h_malloc}, {"free", h_free}, {"calloc", h_calloc}, {"realloc", h_realloc},
    {"memalign", h_memalign}, {"valloc", h_valloc}, {"posix_memalign", h_posix_memalign},
    {"malloc_usable_size", h_malloc_usable_size}, {"dlmalloc", h_malloc}, {"dlfree", h_free},
    {"_Znwj", h_op_new}, {"_Znaj", h_op_new}, {"_ZdlPv", h_free}, {"_ZdaPv", h_free},
    {"_ZnwjRKSt9nothrow_t", h_malloc}, {"_ZnajRKSt9nothrow_t", h_malloc},
    {"_ZdlPvRKSt9nothrow_t", h_free}, {"_ZdaPvRKSt9nothrow_t", h_free},
    {"atoi", h_atoi}, {"atol", h_atol}, {"atoll", h_atoll}, {"atof", h_atof}, {"strtol", h_strtol},
    {"strtoul", h_strtoul}, {"strtoll", h_strtoll}, {"strtoull", h_strtoull}, {"strtoimax", h_strtoll},
    {"strtoumax", h_strtoull}, {"strtod", h_strtod}, {"strtof", h_strtof}, {"strtold", h_strtod},
    {"abs", h_abs}, {"labs", h_abs}, {"rand", h_rand}, {"srand", h_srand}, {"rand_r", h_rand_r},
    {"lrand48", h_lrand48}, {"srand48", h_srand48}, {"random", h_rand}, {"srandom", h_srand},
    {"arc4random", h_arc4random},
    {"qsort", h_qsort}, {"bsearch", h_bsearch}, {"getenv", h_getenv}, {"setenv", h_setenv},
    {"unsetenv", h_unsetenv}, {"__cxa_atexit", h_cxa_atexit}, {"atexit", h_atexit},
    {"__cxa_finalize", h_cxa_finalize}, {"exit", h_exit}, {"_exit", h__exit}, {"_Exit", h__exit},
    {"abort", h_abort}, {"__stack_chk_fail", h_stack_chk_fail}, {"__assert2", h_assert2},
    {"__assert", h_assert}, {"__cxa_pure_virtual", h_cxa_pure_virtual},
    {"__aeabi_idiv", h_aeabi_idiv}, {"__aeabi_uidiv", h_aeabi_uidiv}, {"__aeabi_idivmod", h_aeabi_idivmod},
    {"__aeabi_uidivmod", h_aeabi_uidivmod}, {"__aeabi_ldivmod", h_aeabi_ldivmod},
    {"__aeabi_uldivmod", h_aeabi_uldivmod}, {"__aeabi_lmul", h_aeabi_lmul}, {"__aeabi_llsl", h_aeabi_llsl},
    {"__aeabi_llsr", h_aeabi_llsr}, {"__aeabi_lasr", h_aeabi_lasr}, {"__aeabi_lcmp", h_aeabi_lcmp},
    {"__aeabi_ulcmp", h_aeabi_ulcmp}, {"__divsi3", h_aeabi_idiv}, {"__udivsi3", h_aeabi_uidiv},
    {NULL, NULL}
};

static void init_guard(uint32_t a) { ST32(a, 0x4e563321u); }

static const HostData string_data[] = {
    {"_ctype_", 260, init_ctype},
    {"_tolower_tab_", 520, init_tolower},
    {"_toupper_tab_", 520, init_toupper},
    {"__stack_chk_guard", 4, init_guard},
    {NULL, 0, NULL}
};

void rt_libc_string_init(void) {
    rt_register_host_funcs(string_funcs);
    rt_register_host_data(string_data);
}

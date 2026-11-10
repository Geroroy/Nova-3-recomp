/*
 * Runtime core: module loading, symbol resolution, indirect-call dispatch,
 * host<->guest calls and per-thread CPU state.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "runtime.h"

int rt_mem_init(void);
void rt_libc_init(void);

int rt_trace_imports = 0;
int rt_abort_on_unimplemented = 1;

/* ------------------------------------------------------------------ log */
void rt_log(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
#ifdef __ANDROID__
    __android_log_write(ANDROID_LOG_INFO, "nova3recomp", buf);
#else
    fprintf(stderr, "[rt] %s\n", buf);
#endif
}

/* ------------------------------------------------------- function table */
typedef struct { uint32_t addr; guest_fn fn; } FnSlot;
static FnSlot *fn_table;
static size_t fn_count, fn_cap;
static pthread_rwlock_t fn_lock = PTHREAD_RWLOCK_INITIALIZER;

static int fn_cmp(const void *a, const void *b) {
    uint32_t x = ((const FnSlot *)a)->addr, y = ((const FnSlot *)b)->addr;
    return x < y ? -1 : x > y;
}

static void fn_add_many(const FuncEntry *e, size_t n) {
    pthread_rwlock_wrlock(&fn_lock);
    if (fn_count + n > fn_cap) {
        fn_cap = (fn_count + n) * 2;
        fn_table = realloc(fn_table, fn_cap * sizeof *fn_table);
    }
    for (size_t i = 0; i < n; i++) {
        fn_table[fn_count].addr = e[i].addr & ~1u;
        fn_table[fn_count].fn = e[i].fn;
        fn_count++;
    }
    qsort(fn_table, fn_count, sizeof *fn_table, fn_cmp);
    pthread_rwlock_unlock(&fn_lock);
}

static guest_fn fn_find(uint32_t addr) {
    addr &= ~1u;
    pthread_rwlock_rdlock(&fn_lock);
    size_t lo = 0, hi = fn_count;
    guest_fn r = NULL;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (fn_table[mid].addr < addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo < fn_count && fn_table[lo].addr == addr) r = fn_table[lo].fn;
    pthread_rwlock_unlock(&fn_lock);
    return r;
}

/* ---------------------------------------------------------- host thunks */
typedef struct { const char *name; guest_fn fn; } Thunk;
static Thunk *thunks;
static uint32_t nthunks, cap_thunks;
static pthread_mutex_t thunk_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t rt_host_thunk(const char *name, guest_fn fn) {
    pthread_mutex_lock(&thunk_lock);
    for (uint32_t i = 0; i < nthunks; i++)
        if (thunks[i].fn == fn && (!name || !thunks[i].name || !strcmp(thunks[i].name, name))) {
            pthread_mutex_unlock(&thunk_lock);
            return GUEST_THUNK_BASE + 4 * i;
        }
    if (nthunks == cap_thunks) {
        cap_thunks = cap_thunks ? cap_thunks * 2 : 1024;
        thunks = realloc(thunks, cap_thunks * sizeof *thunks);
    }
    thunks[nthunks].name = name;
    thunks[nthunks].fn = fn;
    uint32_t a = GUEST_THUNK_BASE + 4 * nthunks++;
    pthread_mutex_unlock(&thunk_lock);
    return a;
}

/* ------------------------------------------------------- host registry */
#define MAX_TABLES 64
static const HostFunc *func_tabs[MAX_TABLES];
static int nfunc_tabs;
static const HostData *data_tabs[MAX_TABLES];
static int ndata_tabs;

void rt_register_host_funcs(const HostFunc *tab) { if (nfunc_tabs < MAX_TABLES) func_tabs[nfunc_tabs++] = tab; }
void rt_register_host_data(const HostData *tab) { if (ndata_tabs < MAX_TABLES) data_tabs[ndata_tabs++] = tab; }

guest_fn rt_find_host_func(const char *name) {
    for (int t = nfunc_tabs - 1; t >= 0; t--)
        for (const HostFunc *f = func_tabs[t]; f->name; f++)
            if (!strcmp(f->name, name)) return f->fn;
    return NULL;
}

static const HostData *find_host_data(const char *name) {
    for (int t = ndata_tabs - 1; t >= 0; t--)
        for (const HostData *d = data_tabs[t]; d->name; d++)
            if (!strcmp(d->name, name)) return d;
    return NULL;
}

/* data imports are allocated once and shared between modules */
typedef struct { const char *name; uint32_t addr; } DataSym;
static DataSym data_syms[1024];
static int ndata_syms;

static uint32_t host_data_addr(const char *name) {
    for (int i = 0; i < ndata_syms; i++)
        if (!strcmp(data_syms[i].name, name)) return data_syms[i].addr;
    const HostData *d = find_host_data(name);
    if (!d) return 0;
    uint32_t a = gcalloc(1, d->size ? d->size : 4);
    if (d->init) d->init(a);
    if (ndata_syms < 1024) { data_syms[ndata_syms].name = d->name; data_syms[ndata_syms].addr = a; ndata_syms++; }
    return a;
}

/* ------------------------------------------------------ missing imports */
typedef struct { const char *name; int warned; } Missing;
static Missing missing[4096];
static int nmissing;
static __thread const char *t_missing_name;

static void missing_import(CPU *c) {
    rt_log("call to unimplemented import '%s' (lr=0x%08x) -> returning 0",
           t_missing_name ? t_missing_name : "?", c->r[14]);
    c->r[0] = 0;
    c->r[1] = 0;
}

/* each missing import gets its own small trampoline so we know its name */
#define MISSING_SLOTS 512
static const char *missing_names[MISSING_SLOTS];
#define MS(n) static void ms_##n(CPU *c) { t_missing_name = missing_names[n]; missing_import(c); }
#define MS8(n) MS(n##0) MS(n##1) MS(n##2) MS(n##3) MS(n##4) MS(n##5) MS(n##6) MS(n##7)
#define MS64(n) MS8(n##0) MS8(n##1) MS8(n##2) MS8(n##3) MS8(n##4) MS8(n##5) MS8(n##6) MS8(n##7)
MS64(00) MS64(01) MS64(02) MS64(03) MS64(04) MS64(05) MS64(06) MS64(07)
#define MR(n) ms_##n,
#define MR8(n) MR(n##0) MR(n##1) MR(n##2) MR(n##3) MR(n##4) MR(n##5) MR(n##6) MR(n##7)
#define MR64(n) MR8(n##0) MR8(n##1) MR8(n##2) MR8(n##3) MR8(n##4) MR8(n##5) MR8(n##6) MR8(n##7)
static const guest_fn missing_fns[MISSING_SLOTS] = { MR64(00) MR64(01) MR64(02) MR64(03) MR64(04) MR64(05) MR64(06) MR64(07) };
static int nmissing_slots;

static guest_fn missing_stub(const char *name) {
    (void)missing; (void)nmissing;
    if (nmissing_slots < MISSING_SLOTS) {
        missing_names[nmissing_slots] = name;
        return missing_fns[nmissing_slots++];
    }
    return missing_import;
}

/* ----------------------------------------------------------- modules */
#define MAX_MODULES 16
static const ModuleInfo *modules[MAX_MODULES];
static int nmodules;

uint32_t rt_module_symbol(const ModuleInfo *m, const char *name) {
    for (uint32_t i = 0; i < m->nexports; i++)
        if (!strcmp(m->exports[i].name, name))
            return m->base + m->exports[i].value;
    return 0;
}

uint32_t rt_lookup_symbol(const char *name) {
    for (int i = 0; i < nmodules; i++) {
        uint32_t a = rt_module_symbol(modules[i], name);
        if (a) return a;
    }
    guest_fn f = rt_find_host_func(name);
    if (f) return rt_host_thunk(name, f);
    return host_data_addr(name);
}

static int initialized;

int rt_init(void) {
    if (initialized) return 0;
    if (rt_mem_init()) return -1;
    rt_libc_init();
    initialized = 1;
    return 0;
}

int rt_load_module(const ModuleInfo *m, const void *file, size_t size) {
    if (rt_init()) return -1;
    rt_log("loading module %s (%s), %u functions, %u imports at 0x%08x",
           m->module, m->filename, m->nfuncs, m->nimports, m->base);
    /* 1. segments */
    for (uint32_t i = 0; i < m->nsegs; i++) {
        const SegmentInfo *s = &m->segs[i];
        if ((uint64_t)s->offset + s->filesz > size) {
            rt_log("segment %u outside file (file too small: wrong %s?)", i, m->filename);
            return -1;
        }
        memcpy(G2H(m->base + s->vaddr), (const uint8_t *)file + s->offset, s->filesz);
        memset(G2H(m->base + s->vaddr + s->filesz), 0, s->memsz - s->filesz);
    }
    /* 2. imports */
    uint32_t *imp_addr = calloc(m->nimports + 1, sizeof(uint32_t));
    int nmiss = 0;
    for (uint32_t i = 0; i < m->nimports; i++) {
        const ImportInfo *im = &m->imports[i];
        uint32_t a = 0;
        guest_fn hf = NULL;
        for (int k = 0; k < nmodules && !a; k++) a = rt_module_symbol(modules[k], im->name);
        if (a) {
            guest_fn gf = fn_find(a);
            m->import_fns[i] = gf;   /* direct call into the other module */
        } else if (im->is_func && (hf = rt_find_host_func(im->name))) {
            a = rt_host_thunk(im->name, hf);
            m->import_fns[i] = hf;
        } else if ((a = host_data_addr(im->name)) != 0) {
            m->import_fns[i] = missing_stub(im->name);
        } else {
            m->import_fns[i] = missing_stub(im->name);
            if (im->is_func) a = rt_host_thunk(im->name, m->import_fns[i]);
            rt_log("  unresolved import: %s%s", im->name, im->is_func ? "" : " (data)");
            nmiss++;
        }
        imp_addr[i] = a;
        if (!m->import_fns[i]) m->import_fns[i] = missing_stub(im->name);
    }
    if (nmiss) rt_log("  %d unresolved imports", nmiss);
    /* 3. relocations */
    for (uint32_t i = 0; i < m->nrelocs; i++) {
        const RelocInfo *r = &m->relocs[i];
        uint32_t P = m->base + r->offset;
        uint32_t S = r->import_id >= 0 ? imp_addr[r->import_id] : (r->symval ? m->base + r->symval : 0);
        switch (r->type) {
        case 23: /* RELATIVE */ ST32(P, LD32(P) + m->base); break;
        case 2:  /* ABS32 */    ST32(P, LD32(P) + S + (uint32_t)r->addend); break;
        case 3:  /* REL32 */    ST32(P, LD32(P) + S - P); break;
        case 21: /* GLOB_DAT */
        case 22: /* JUMP_SLOT */ ST32(P, S); break;
        case 0: break;
        default: rt_log("  unsupported relocation type %u at 0x%x", r->type, r->offset);
        }
    }
    free(imp_addr);
    /* 4. functions */
    fn_add_many(m->funcs, m->nfuncs);
    if (nmodules < MAX_MODULES) modules[nmodules++] = m;
    return 0;
}

int rt_load_module_file(const ModuleInfo *m, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { rt_log("cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    fstat(fd, &st);
    void *buf = malloc((size_t)st.st_size);
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, (char *)buf + got, (size_t)st.st_size - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    int r = rt_load_module(m, buf, got);
    free(buf);
    return r;
}

void rt_run_initializers(const ModuleInfo *m) {
    if (m->dt_init) guest_call0(m->base + m->dt_init);
    for (uint32_t i = 0; i < m->ninit; i++)
        guest_call0(m->base + m->init_array[i]);
}

/* ------------------------------------------------------------ dispatch */
void call_addr(CPU *c, uint32_t addr) {
    if (addr >= GUEST_THUNK_BASE && addr < GUEST_THUNK_BASE + 4 * nthunks) {
        Thunk *t = &thunks[(addr - GUEST_THUNK_BASE) / 4];
        if (rt_trace_imports) rt_log("-> %s", t->name ? t->name : "?");
        t->fn(c);
        return;
    }
    guest_fn f = fn_find(addr);
    if (!f) {
        rt_bad_jump(c, c->r[14], addr);
        return;
    }
    f(c);
}

void import_call(CPU *c, uint32_t id) { (void)c; (void)id; }

void rt_bad_jump(CPU *c, uint32_t from, uint32_t target) {
    rt_log("FATAL: jump/call to unknown guest address 0x%08x (lr=0x%08x, sp=0x%08x)",
           target, from, c->r[13]);
    rt_log("       re-run the recompiler with --entry 0x%x%s", target & ~1u, (target & 1) ? "t" : "");
    FILE *f = fopen("missing_entries.txt", "a");
    if (f) { fprintf(f, "0x%x%s\n", target & ~1u, (target & 1) ? "t" : ""); fclose(f); }
    abort();
}

void rt_unimplemented(CPU *c, uint32_t pc, const char *what) {
    rt_log("unimplemented instruction at 0x%08x: %s (lr=0x%08x)", pc, what, c->r[14]);
    if (rt_abort_on_unimplemented) abort();
}

void rt_svc(CPU *c, uint32_t pc, uint32_t imm) {
    rt_log("svc #%u at 0x%08x (r7=%u) not supported", imm, pc, c->r[7]);
    c->r[0] = (uint32_t)-38; /* -ENOSYS */
}

void rt_mcr_mrc(CPU *c, uint32_t pc, int is_read, uint32_t cp, uint32_t opc1,
                uint32_t crn, uint32_t crm, uint32_t opc2, uint32_t *reg) {
    (void)c;
    rt_log("%s p%u, %u, c%u, c%u, %u at 0x%08x ignored", is_read ? "mrc" : "mcr", cp, opc1, crn, crm, opc2, pc);
    if (is_read) *reg = 0;
}

/* ------------------------------------------------------------- threads */
#define MAIN_STACK_SIZE (8u << 20)
#define THREAD_STACK_SIZE (1u << 20)
#define TLS_SLOTS 64

static pthread_key_t cpu_key;
static pthread_once_t cpu_once = PTHREAD_ONCE_INIT;
static __thread CPU *t_cpu;

static void cpu_destroy(void *p) {
    CPU *c = p;
    (void)c; /* stacks are leaked on purpose: other threads may still reference them */
}
static void cpu_key_init(void) { pthread_key_create(&cpu_key, cpu_destroy); }

CPU *rt_cpu_new(uint32_t stack_size) {
    pthread_once(&cpu_once, cpu_key_init);
    CPU *c = calloc(1, sizeof(CPU));
    uint32_t stack = gmap_anon(stack_size);
    c->r[13] = (stack + stack_size - 64) & ~15u;
    c->tls = gcalloc(TLS_SLOTS, 4);
    ST32(c->tls, c->tls);                       /* TLS_SLOT_SELF */
    ST32(c->tls + 4, (uint32_t)gettid());       /* TLS_SLOT_THREAD_ID */
    ST32(c->tls + 8, gcalloc(1, 4));            /* errno */
    ST32(c->tls + 20, 0xdeadbeefu);             /* stack guard */
    return c;
}

CPU *rt_cpu(void) {
    if (!t_cpu) {
        static int have_main;
        t_cpu = rt_cpu_new(have_main ? THREAD_STACK_SIZE : MAIN_STACK_SIZE);
        have_main = 1;
        pthread_once(&cpu_once, cpu_key_init);
        pthread_setspecific(cpu_key, t_cpu);
    }
    return t_cpu;
}

void rt_cpu_set(CPU *c) { t_cpu = c; pthread_setspecific(cpu_key, c); }

uint32_t rt_errno_addr(CPU *c) { return LD32(c->tls + 8); }

/* -------------------------------------------------------- guest calls */
static uint64_t do_call(uint32_t addr, int nargs, const uint32_t *args) {
    CPU *c = rt_cpu();
    uint32_t saved[16];
    memcpy(saved, c->r, sizeof saved);
    uint32_t sp = c->r[13];
    int nstack = nargs > 4 ? nargs - 4 : 0;
    sp -= 16;                                    /* red zone between frames */
    sp = (sp - 4u * (uint32_t)nstack) & ~7u;
    for (int i = 0; i < nstack; i++) ST32(sp + 4u * (uint32_t)i, args[4 + i]);
    for (int i = 0; i < 4; i++) c->r[i] = i < nargs ? args[i] : 0;
    c->r[13] = sp;
    c->r[14] = 0xFFFFFFFEu;                     /* never used: returns are C returns */
    c->call_depth++;
    call_addr(c, addr);
    c->call_depth--;
    uint64_t r = (uint64_t)c->r[0] | ((uint64_t)c->r[1] << 32);
    /* restore callee-visible state of an outer guest frame */
    for (int i = 4; i < 16; i++) c->r[i] = saved[i];
    c->r[2] = saved[2]; c->r[3] = saved[3];
    c->r[0] = saved[0]; c->r[1] = saved[1];
    return r;
}

uint32_t guest_call(uint32_t addr, int nargs, const uint32_t *args) { return (uint32_t)do_call(addr, nargs, args); }
uint64_t guest_call64(uint32_t addr, int nargs, const uint32_t *args) { return do_call(addr, nargs, args); }
uint32_t guest_call0(uint32_t a) { return guest_call(a, 0, NULL); }
uint32_t guest_call1(uint32_t a, uint32_t x) { return guest_call(a, 1, &x); }
uint32_t guest_call2(uint32_t a, uint32_t x, uint32_t y) { uint32_t v[2] = {x, y}; return guest_call(a, 2, v); }
uint32_t guest_call3(uint32_t a, uint32_t x, uint32_t y, uint32_t z) { uint32_t v[3] = {x, y, z}; return guest_call(a, 3, v); }
uint32_t guest_call4(uint32_t a, uint32_t x, uint32_t y, uint32_t z, uint32_t w) { uint32_t v[4] = {x, y, z, w}; return guest_call(a, 4, v); }

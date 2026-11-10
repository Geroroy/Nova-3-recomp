/*
 * bionic pthread bridge. 32-bit bionic mutexes/conds are 4-byte words; we
 * keep the real host objects in side tables keyed by guest address.
 */
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hmap.h"
#include "runtime.h"

#define H(n) static void n(CPU *c)
#define P(n) ARG(c, n)

CPU *rt_cpu_new(uint32_t stack_size);
void rt_cpu_set(CPU *c);

/* ---------------------------------------------------------------- mutex */
static HMap mutexes = HMAP_INIT;
static pthread_mutex_t create_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t *get_mutex(uint32_t g) {
    pthread_mutex_t *m = hm_get(&mutexes, g);
    if (m) return m;
    pthread_mutex_lock(&create_lock);
    m = hm_get(&mutexes, g);
    if (!m) {
        uint32_t v = LD32(g);
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        /* bionic: bits 14-15 = type (0 normal, 1 recursive, 2 errorcheck) */
        uint32_t type = (v >> 14) & 3;
        pthread_mutexattr_settype(&a, type == 1 ? PTHREAD_MUTEX_RECURSIVE :
                                      type == 2 ? PTHREAD_MUTEX_ERRORCHECK : PTHREAD_MUTEX_NORMAL);
        m = malloc(sizeof *m);
        pthread_mutex_init(m, &a);
        pthread_mutexattr_destroy(&a);
        hm_put(&mutexes, g, m);
    }
    pthread_mutex_unlock(&create_lock);
    return m;
}

H(h_mutex_init) {
    uint32_t g = P(0), attr = P(1);
    uint32_t type = attr ? LD32(attr) & 3 : 0;
    pthread_mutex_t *old = hm_del(&mutexes, g);
    if (old) { pthread_mutex_destroy(old); free(old); }
    ST32(g, type << 14);
    get_mutex(g);
    RET32(c, 0);
}
H(h_mutex_destroy) { pthread_mutex_t *m = hm_del(&mutexes, P(0)); if (m) { pthread_mutex_destroy(m); free(m); } RET32(c, 0); }
H(h_mutex_lock)    { RET32(c, (uint32_t)pthread_mutex_lock(get_mutex(P(0)))); }
H(h_mutex_unlock)  { RET32(c, (uint32_t)pthread_mutex_unlock(get_mutex(P(0)))); }
H(h_mutex_trylock) { RET32(c, (uint32_t)pthread_mutex_trylock(get_mutex(P(0)))); }
H(h_mutexattr_init)    { ST32(P(0), 0); RET32(c, 0); }
H(h_mutexattr_settype) { ST32(P(0), P(1)); RET32(c, 0); }
H(h_mutexattr_gettype) { ST32(P(1), LD32(P(0))); RET32(c, 0); }
H(h_mutexattr_destroy) { RET32(c, 0); }
H(h_mutexattr_setpshared) { RET32(c, 0); }

/* ----------------------------------------------------------------- cond */
static HMap conds = HMAP_INIT;
static pthread_cond_t *get_cond(uint32_t g) {
    pthread_cond_t *cv = hm_get(&conds, g);
    if (cv) return cv;
    pthread_mutex_lock(&create_lock);
    cv = hm_get(&conds, g);
    if (!cv) { cv = malloc(sizeof *cv); pthread_cond_init(cv, NULL); hm_put(&conds, g, cv); }
    pthread_mutex_unlock(&create_lock);
    return cv;
}
H(h_cond_init)      { pthread_cond_t *o = hm_del(&conds, P(0)); if (o) { pthread_cond_destroy(o); free(o); } get_cond(P(0)); RET32(c, 0); }
H(h_cond_destroy)   { pthread_cond_t *o = hm_del(&conds, P(0)); if (o) { pthread_cond_destroy(o); free(o); } RET32(c, 0); }
H(h_cond_signal)    { RET32(c, (uint32_t)pthread_cond_signal(get_cond(P(0)))); }
H(h_cond_broadcast) { RET32(c, (uint32_t)pthread_cond_broadcast(get_cond(P(0)))); }
H(h_cond_wait)      { RET32(c, (uint32_t)pthread_cond_wait(get_cond(P(0)), get_mutex(P(1)))); }
H(h_cond_timedwait) {
    struct timespec ts = { (time_t)(int32_t)LD32(P(2)), (long)(int32_t)LD32(P(2) + 4) };
    RET32(c, (uint32_t)pthread_cond_timedwait(get_cond(P(0)), get_mutex(P(1)), &ts));
}
H(h_cond_timedwait_relative) {
    struct timespec now, rel = { (time_t)(int32_t)LD32(P(2)), (long)(int32_t)LD32(P(2) + 4) };
    clock_gettime(CLOCK_REALTIME, &now);
    now.tv_sec += rel.tv_sec; now.tv_nsec += rel.tv_nsec;
    if (now.tv_nsec >= 1000000000L) { now.tv_sec++; now.tv_nsec -= 1000000000L; }
    RET32(c, (uint32_t)pthread_cond_timedwait(get_cond(P(0)), get_mutex(P(1)), &now));
}
H(h_condattr) { RET32(c, 0); }

/* -------------------------------------------------------------- threads */
typedef struct GThread {
    pthread_t host;
    uint32_t id;           /* guest pthread_t */
    uint32_t start, arg;
    uint32_t result;
    uint32_t stack_size;
    int detached;
} GThread;

static HMap threads = HMAP_INIT;
static __thread GThread *t_self;

/* thread-specific keys: our own table so guest destructors can run */
#define MAX_KEYS 256
static uint32_t key_dtor[MAX_KEYS];
static uint8_t key_used[MAX_KEYS];
static pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread uint32_t key_val[MAX_KEYS];

static void run_key_dtors(void) {
    for (int round = 0; round < 4; round++) {
        int any = 0;
        for (int k = 0; k < MAX_KEYS; k++) {
            if (key_used[k] && key_dtor[k] && key_val[k]) {
                uint32_t v = key_val[k];
                key_val[k] = 0;
                guest_call1(key_dtor[k], v);
                any = 1;
            }
        }
        if (!any) break;
    }
}

static GThread *self_thread(void) {
    if (!t_self) {
        t_self = calloc(1, sizeof *t_self);
        t_self->host = pthread_self();
        t_self->id = gcalloc(1, 64);
        hm_put(&threads, t_self->id, t_self);
    }
    return t_self;
}

static void *thread_main(void *p) {
    GThread *t = p;
    t_self = t;
    CPU *c = rt_cpu_new(t->stack_size);
    rt_cpu_set(c);
    t->result = guest_call1(t->start, t->arg);
    run_key_dtors();
    return NULL;
}

H(h_pthread_create) {
    uint32_t out = P(0), attr = P(1);
    GThread *t = calloc(1, sizeof *t);
    t->start = P(2);
    t->arg = P(3);
    t->id = gcalloc(1, 64);
    t->stack_size = 1u << 20;
    if (attr) {
        /* bionic pthread_attr_t: flags, stack_base, stack_size, guard_size, sched_policy, sched_priority */
        uint32_t ss = LD32(attr + 8);
        if (ss >= (64u << 10) && ss <= (64u << 20)) t->stack_size = ss;
        t->detached = LD32(attr) & 1;
    }
    hm_put(&threads, t->id, t);
    pthread_attr_t ha;
    pthread_attr_init(&ha);
    pthread_attr_setstacksize(&ha, 1u << 20);    /* host stack for the recompiled C */
    if (t->detached) pthread_attr_setdetachstate(&ha, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&t->host, &ha, thread_main, t);
    pthread_attr_destroy(&ha);
    if (r) { RET32(c, (uint32_t)r); return; }
    ST32(out, t->id);
    RET32(c, 0);
}
H(h_pthread_join) {
    GThread *t = hm_get(&threads, P(0));
    if (!t) { RET32(c, ESRCH); return; }
    pthread_join(t->host, NULL);
    if (P(1)) ST32(P(1), t->result);
    RET32(c, 0);
}
H(h_pthread_detach) {
    GThread *t = hm_get(&threads, P(0));
    if (t) pthread_detach(t->host);
    RET32(c, 0);
}
H(h_pthread_self)  { RET32(c, self_thread()->id); }
H(h_pthread_equal) { RET32(c, P(0) == P(1)); }
H(h_pthread_exit)  { rt_log("pthread_exit from guest"); run_key_dtors(); pthread_exit(NULL); }
H(h_pthread_kill)  { RET32(c, 0); }
H(h_pthread_setname_np) { RET32(c, 0); }
H(h_pthread_getschedparam) { ST32(P(1), 0); ST32(P(2), 0); RET32(c, 0); }
H(h_pthread_setschedparam) { RET32(c, 0); }

H(h_attr_init) { memset(G2H(P(0)), 0, 24); ST32(P(0) + 8, 1u << 20); RET32(c, 0); }
H(h_attr_destroy) { RET32(c, 0); }
H(h_attr_setdetachstate) { ST32(P(0), (LD32(P(0)) & ~1u) | (P(1) & 1)); RET32(c, 0); }
H(h_attr_getdetachstate) { ST32(P(1), LD32(P(0)) & 1); RET32(c, 0); }
H(h_attr_setstacksize) { ST32(P(0) + 8, P(1)); RET32(c, 0); }
H(h_attr_getstacksize) { ST32(P(1), LD32(P(0) + 8)); RET32(c, 0); }
H(h_attr_ok) { RET32(c, 0); }

H(h_key_create) {
    pthread_mutex_lock(&key_lock);
    int k;
    for (k = 1; k < MAX_KEYS && key_used[k]; k++) {}
    if (k == MAX_KEYS) { pthread_mutex_unlock(&key_lock); RET32(c, EAGAIN); return; }
    key_used[k] = 1;
    key_dtor[k] = P(1);
    pthread_mutex_unlock(&key_lock);
    ST32(P(0), (uint32_t)k);
    RET32(c, 0);
}
H(h_key_delete) { uint32_t k = P(0); if (k < MAX_KEYS) key_used[k] = 0; RET32(c, 0); }
H(h_getspecific) { uint32_t k = P(0); RET32(c, k < MAX_KEYS ? key_val[k] : 0); }
H(h_setspecific) { uint32_t k = P(0); if (k < MAX_KEYS) key_val[k] = P(1); RET32(c, 0); }

static pthread_mutex_t once_lock;
static pthread_once_t once_lock_once = PTHREAD_ONCE_INIT;
static void once_lock_init(void) {
    pthread_mutexattr_t a; pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&once_lock, &a);
}
H(h_pthread_once) {
    uint32_t ctl = P(0), fn = P(1);
    if (__atomic_load_n((uint32_t *)G2H(ctl), __ATOMIC_ACQUIRE) == 2) { RET32(c, 0); return; }
    pthread_once(&once_lock_once, once_lock_init);
    pthread_mutex_lock(&once_lock);
    if (LD32(ctl) == 0) {
        ST32(ctl, 1);
        guest_call0(fn);
        __atomic_store_n((uint32_t *)G2H(ctl), 2, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&once_lock);
    RET32(c, 0);
}

/* ------------------------------------------------------------ semaphores */
static HMap sems = HMAP_INIT;
static sem_t *get_sem(uint32_t g) { return hm_get(&sems, g); }
H(h_sem_init) { sem_t *s = malloc(sizeof *s); sem_init(s, 0, P(2)); hm_put(&sems, P(0), s); RET32(c, 0); }
H(h_sem_destroy) { sem_t *s = hm_del(&sems, P(0)); if (s) { sem_destroy(s); free(s); } RET32(c, 0); }
H(h_sem_wait) { sem_t *s = get_sem(P(0)); RET32(c, s ? (uint32_t)sem_wait(s) : (uint32_t)-1); }
H(h_sem_trywait) { sem_t *s = get_sem(P(0)); RET32(c, s ? (uint32_t)sem_trywait(s) : (uint32_t)-1); }
H(h_sem_post) { sem_t *s = get_sem(P(0)); RET32(c, s ? (uint32_t)sem_post(s) : (uint32_t)-1); }
H(h_sem_timedwait) {
    sem_t *s = get_sem(P(0));
    struct timespec ts = { (time_t)(int32_t)LD32(P(1)), (long)(int32_t)LD32(P(1) + 4) };
    RET32(c, s ? (uint32_t)sem_timedwait(s, &ts) : (uint32_t)-1);
}
H(h_sem_getvalue) { sem_t *s = get_sem(P(0)); int v = 0; if (s) sem_getvalue(s, &v); ST32(P(1), (uint32_t)v); RET32(c, 0); }

static const HostFunc pthread_funcs[] = {
    {"pthread_mutex_init", h_mutex_init}, {"pthread_mutex_destroy", h_mutex_destroy},
    {"pthread_mutex_lock", h_mutex_lock}, {"pthread_mutex_unlock", h_mutex_unlock},
    {"pthread_mutex_trylock", h_mutex_trylock}, {"pthread_mutexattr_init", h_mutexattr_init},
    {"pthread_mutexattr_settype", h_mutexattr_settype}, {"pthread_mutexattr_gettype", h_mutexattr_gettype},
    {"pthread_mutexattr_destroy", h_mutexattr_destroy}, {"pthread_mutexattr_setpshared", h_mutexattr_setpshared},
    {"pthread_cond_init", h_cond_init}, {"pthread_cond_destroy", h_cond_destroy},
    {"pthread_cond_signal", h_cond_signal}, {"pthread_cond_broadcast", h_cond_broadcast},
    {"pthread_cond_wait", h_cond_wait}, {"pthread_cond_timedwait", h_cond_timedwait},
    {"pthread_cond_timedwait_relative_np", h_cond_timedwait_relative},
    {"pthread_cond_timeout_np", h_cond_timedwait_relative},
    {"pthread_condattr_init", h_condattr}, {"pthread_condattr_destroy", h_condattr},
    {"pthread_condattr_setpshared", h_condattr},
    {"pthread_create", h_pthread_create}, {"pthread_join", h_pthread_join},
    {"pthread_detach", h_pthread_detach}, {"pthread_self", h_pthread_self},
    {"pthread_equal", h_pthread_equal}, {"pthread_exit", h_pthread_exit}, {"pthread_kill", h_pthread_kill},
    {"pthread_setname_np", h_pthread_setname_np}, {"pthread_getschedparam", h_pthread_getschedparam},
    {"pthread_setschedparam", h_pthread_setschedparam},
    {"pthread_attr_init", h_attr_init}, {"pthread_attr_destroy", h_attr_destroy},
    {"pthread_attr_setdetachstate", h_attr_setdetachstate}, {"pthread_attr_getdetachstate", h_attr_getdetachstate},
    {"pthread_attr_setstacksize", h_attr_setstacksize}, {"pthread_attr_getstacksize", h_attr_getstacksize},
    {"pthread_attr_setschedparam", h_attr_ok}, {"pthread_attr_getschedparam", h_attr_ok},
    {"pthread_attr_setschedpolicy", h_attr_ok}, {"pthread_attr_setscope", h_attr_ok},
    {"pthread_attr_setguardsize", h_attr_ok},
    {"pthread_key_create", h_key_create}, {"pthread_key_delete", h_key_delete},
    {"pthread_getspecific", h_getspecific}, {"pthread_setspecific", h_setspecific},
    {"pthread_once", h_pthread_once},
    {"sem_init", h_sem_init}, {"sem_destroy", h_sem_destroy}, {"sem_wait", h_sem_wait},
    {"sem_trywait", h_sem_trywait}, {"sem_post", h_sem_post}, {"sem_timedwait", h_sem_timedwait},
    {"sem_getvalue", h_sem_getvalue},
    {NULL, NULL}
};

void rt_libc_pthread_init(void) { rt_register_host_funcs(pthread_funcs); }

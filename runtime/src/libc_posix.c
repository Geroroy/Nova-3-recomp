/* bionic libc bridge: errno, file descriptors, stat, dirs, time, mmap, dl*, log, misc. */
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "hmap.h"
#include "runtime.h"

#define H(n) static void n(CPU *c)
#define S(n) ((char *)ARGP(c, n))
#define P(n) ARG(c, n)

/* --------------------------------------------------------------- errno */
void rt_set_errno(CPU *c, int e) { if (e) ST32(rt_errno_addr(c), (uint32_t)e); }
H(h_errno) { RET32(c, rt_errno_addr(c)); }
#define RET_ERR(c, r) do { long _r = (long)(r); if (_r < 0) rt_set_errno(c, errno); RET32(c, (uint32_t)_r); } while (0)

/* ----------------------------------------------------------- path maps */
static struct { char from[256]; char to[512]; } path_maps[32];
static int npath_maps;

void rt_add_path_map(const char *from, const char *to) {
    if (npath_maps >= 32) return;
    strncpy(path_maps[npath_maps].from, from, 255);
    strncpy(path_maps[npath_maps].to, to, 511);
    npath_maps++;
}

const char *rt_map_path(const char *p, char *buf, size_t n) {
    if (!p) return p;
    for (int i = npath_maps - 1; i >= 0; i--) {
        size_t l = strlen(path_maps[i].from);
        if (!strncmp(p, path_maps[i].from, l)) {
            snprintf(buf, n, "%s%s", path_maps[i].to, p + l);
            return buf;
        }
    }
    return p;
}
#define PATH(n, buf) rt_map_path(S(n), buf, sizeof buf)

/* -------------------------------------------------------------- fd I/O */
static int map_oflags(uint32_t f) {
    /* arm32 Linux flags: O_DIRECTORY=040000, O_NOFOLLOW=0100000, O_DIRECT=0200000, O_LARGEFILE=0400000 */
    int r = (int)(f & 03) | ((f & 0100) ? O_CREAT : 0) | ((f & 0200) ? O_EXCL : 0) |
            ((f & 01000) ? O_TRUNC : 0) | ((f & 02000) ? O_APPEND : 0) | ((f & 04000) ? O_NONBLOCK : 0) |
            ((f & 040000) ? O_DIRECTORY : 0) | ((f & 0100000) ? O_NOFOLLOW : 0) | ((f & 02000000) ? O_CLOEXEC : 0);
    return r;
}
H(h_open)  { char b[1024]; RET_ERR(c, open(PATH(0, b), map_oflags(P(1)), (mode_t)P(2))); }
H(h_close) { RET_ERR(c, close((int)P(0))); }
H(h_read)  { RET_ERR(c, read((int)P(0), G2H(P(1)), P(2))); }
H(h_write) { RET_ERR(c, write((int)P(0), G2H(P(1)), P(2))); }
H(h_pread) { RET_ERR(c, pread((int)P(0), G2H(P(1)), P(2), (off_t)(int32_t)P(3))); }
H(h_pread64){ RET_ERR(c, pread((int)P(0), G2H(P(1)), P(2), (off_t)(int64_t)ARG64(c, 4))); }
H(h_lseek) { RET_ERR(c, lseek((int)P(0), (off_t)(int32_t)P(1), (int)P(2))); }
H(h_lseek64) { off_t r = lseek((int)P(0), (off_t)(int64_t)ARG64(c, 2), (int)ARG(c, 4));
               if (r < 0) rt_set_errno(c, errno); RET64(c, (uint64_t)r); }
H(h_access){ char b[1024]; RET_ERR(c, access(PATH(0, b), (int)P(1))); }
H(h_unlink){ char b[1024]; RET_ERR(c, unlink(PATH(0, b))); }
H(h_mkdir) { char b[1024]; RET_ERR(c, mkdir(PATH(0, b), (mode_t)P(1))); }
H(h_rmdir) { char b[1024]; RET_ERR(c, rmdir(PATH(0, b))); }
H(h_chdir) { char b[1024]; RET_ERR(c, chdir(PATH(0, b))); }
H(h_getcwd){ char *r = getcwd(S(0), P(1)); RET32(c, r ? P(0) : 0); }
H(h_fsync) { RET_ERR(c, fsync((int)P(0))); }
H(h_dup)   { RET_ERR(c, dup((int)P(0))); }
H(h_dup2)  { RET_ERR(c, dup2((int)P(0), (int)P(1))); }
H(h_pipe)  { int fds[2]; int r = pipe(fds); if (!r) { ST32(P(0), (uint32_t)fds[0]); ST32(P(0) + 4, (uint32_t)fds[1]); } RET_ERR(c, r); }
H(h_ftruncate) { RET_ERR(c, ftruncate((int)P(0), (off_t)(int32_t)P(1))); }
H(h_fcntl) {
    int cmd = (int)P(1);
    if (cmd == 1 || cmd == 2 || cmd == 3 || cmd == 4) RET_ERR(c, fcntl((int)P(0), cmd, (int)P(2)));
    else RET32(c, 0);
}
H(h_isatty) { RET32(c, (uint32_t)isatty((int)P(0))); }

/* bionic 32-bit struct stat (== kernel stat64), 104 bytes */
static void put_stat(uint32_t g, const struct stat *st) {
    memset(G2H(g), 0, 104);
    ST64(g + 0, (uint64_t)st->st_dev);
    ST32(g + 12, (uint32_t)st->st_ino);
    ST32(g + 16, st->st_mode);
    ST32(g + 20, (uint32_t)st->st_nlink);
    ST32(g + 24, st->st_uid);
    ST32(g + 28, st->st_gid);
    ST64(g + 32, (uint64_t)st->st_rdev);
    ST64(g + 48, (uint64_t)st->st_size);
    ST32(g + 56, (uint32_t)st->st_blksize);
    ST64(g + 64, (uint64_t)st->st_blocks);
    ST32(g + 72, (uint32_t)st->st_atime);
    ST32(g + 80, (uint32_t)st->st_mtime);
    ST32(g + 88, (uint32_t)st->st_ctime);
    ST64(g + 96, (uint64_t)st->st_ino);
}
H(h_stat)  { char b[1024]; struct stat st; int r = stat(PATH(0, b), &st); if (!r) put_stat(P(1), &st); RET_ERR(c, r); }
H(h_lstat) { char b[1024]; struct stat st; int r = lstat(PATH(0, b), &st); if (!r) put_stat(P(1), &st); RET_ERR(c, r); }
H(h_fstat) { struct stat st; int r = fstat((int)P(0), &st); if (!r) put_stat(P(1), &st); RET_ERR(c, r); }

/* ---------------------------------------------------------------- dirs */
typedef struct { DIR *d; uint32_t ent; } GDir;
static HMap dirs = HMAP_INIT;
H(h_opendir) {
    char b[1024];
    DIR *d = opendir(PATH(0, b));
    if (!d) { rt_set_errno(c, errno); RET32(c, 0); return; }
    GDir *gd = malloc(sizeof *gd);
    gd->d = d;
    gd->ent = gcalloc(1, 280);
    uint32_t handle = gcalloc(1, 16);
    hm_put(&dirs, handle, gd);
    RET32(c, handle);
}
H(h_readdir) {
    GDir *gd = hm_get(&dirs, P(0));
    struct dirent *e = gd ? readdir(gd->d) : NULL;
    if (!e) { RET32(c, 0); return; }
    ST64(gd->ent, (uint64_t)e->d_ino);
    ST64(gd->ent + 8, 0);
    ST16(gd->ent + 16, 280);
    ST8(gd->ent + 18, e->d_type);
    strncpy((char *)G2H(gd->ent + 19), e->d_name, 255);
    RET32(c, gd->ent);
}
H(h_closedir) {
    GDir *gd = hm_del(&dirs, P(0));
    if (!gd) { RET32(c, (uint32_t)-1); return; }
    closedir(gd->d); gfree(gd->ent); gfree(P(0)); free(gd);
    RET32(c, 0);
}

/* ---------------------------------------------------------------- time */
H(h_time) { time_t t = time(NULL); if (P(0)) ST32(P(0), (uint32_t)t); RET32(c, (uint32_t)t); }
H(h_gettimeofday) {
    struct timeval tv; gettimeofday(&tv, NULL);
    if (P(0)) { ST32(P(0), (uint32_t)tv.tv_sec); ST32(P(0) + 4, (uint32_t)tv.tv_usec); }
    RET32(c, 0);
}
H(h_clock_gettime) {
    struct timespec ts; int r = clock_gettime((clockid_t)P(0), &ts);
    if (!r) { ST32(P(1), (uint32_t)ts.tv_sec); ST32(P(1) + 4, (uint32_t)ts.tv_nsec); }
    RET_ERR(c, r);
}
H(h_clock) { RET32(c, (uint32_t)clock()); }
H(h_usleep) { RET32(c, (uint32_t)usleep(P(0))); }
H(h_sleep)  { RET32(c, sleep(P(0))); }
H(h_nanosleep) {
    struct timespec ts = { (time_t)(int32_t)LD32(P(0)), (long)(int32_t)LD32(P(0) + 4) };
    RET32(c, (uint32_t)nanosleep(&ts, NULL));
}
/* struct tm is 44 bytes on 32-bit bionic (9 ints + long gmtoff + char *zone) */
static uint32_t tm_buf;
static void put_tm(uint32_t g, const struct tm *t) {
    ST32(g, (uint32_t)t->tm_sec); ST32(g + 4, (uint32_t)t->tm_min); ST32(g + 8, (uint32_t)t->tm_hour);
    ST32(g + 12, (uint32_t)t->tm_mday); ST32(g + 16, (uint32_t)t->tm_mon); ST32(g + 20, (uint32_t)t->tm_year);
    ST32(g + 24, (uint32_t)t->tm_wday); ST32(g + 28, (uint32_t)t->tm_yday); ST32(g + 32, (uint32_t)t->tm_isdst);
    ST32(g + 36, (uint32_t)t->tm_gmtoff); ST32(g + 40, 0);
}
static void get_tm(uint32_t g, struct tm *t) {
    memset(t, 0, sizeof *t);
    t->tm_sec = (int)LD32(g); t->tm_min = (int)LD32(g + 4); t->tm_hour = (int)LD32(g + 8);
    t->tm_mday = (int)LD32(g + 12); t->tm_mon = (int)LD32(g + 16); t->tm_year = (int)LD32(g + 20);
    t->tm_wday = (int)LD32(g + 24); t->tm_yday = (int)LD32(g + 28); t->tm_isdst = (int)LD32(g + 32);
}
H(h_localtime_r) { time_t t = (time_t)(int32_t)LD32(P(0)); struct tm tm; localtime_r(&t, &tm); put_tm(P(1), &tm); RET32(c, P(1)); }
H(h_gmtime_r)    { time_t t = (time_t)(int32_t)LD32(P(0)); struct tm tm; gmtime_r(&t, &tm); put_tm(P(1), &tm); RET32(c, P(1)); }
H(h_localtime)   { if (!tm_buf) tm_buf = gcalloc(1, 44); c->r[1] = tm_buf; h_localtime_r(c); }
H(h_gmtime)      { if (!tm_buf) tm_buf = gcalloc(1, 44); c->r[1] = tm_buf; h_gmtime_r(c); }
H(h_mktime)      { struct tm tm; get_tm(P(0), &tm); time_t t = mktime(&tm); put_tm(P(0), &tm); RET32(c, (uint32_t)t); }
H(h_strftime)    { struct tm tm; get_tm(ARG(c, 3), &tm); RET32(c, (uint32_t)strftime(S(0), P(1), S(2), &tm)); }
H(h_difftime)    { RETD(c, (double)(int32_t)P(0) - (double)(int32_t)P(1)); }

/* --------------------------------------------------------------- mmap */
H(h_mmap) {
    uint32_t len = P(1), flags = P(3);
    int fd = (int)P(3 + 1);
    uint32_t off = ARG(c, 5);
    uint32_t a = gmap_anon(len);
    if (!a) { RET32(c, 0xFFFFFFFFu); return; }
    if (!(flags & 0x20) && fd >= 0) {        /* file mapping: copy contents */
        ssize_t n = pread(fd, G2H(a), len, (off_t)off);
        (void)n;
    }
    RET32(c, a);
}
H(h_munmap)   { gunmap(P(0), P(1)); RET32(c, 0); }
H(h_mprotect) { RET32(c, 0); }
H(h_madvise)  { RET32(c, 0); }

/* -------------------------------------------------------------- dl*() */
static uint32_t dl_error;
H(h_dlopen) {
    const char *n = S(0);
    rt_log("dlopen(%s)", n ? n : "NULL");
    RET32(c, 0x1u);                           /* pseudo handle: global namespace */
}
H(h_dlsym) {
    const char *n = S(1);
    uint32_t a = rt_lookup_symbol(n);
    if (!a) rt_log("dlsym(%s) -> not found", n);
    RET32(c, a);
}
H(h_dlclose) { RET32(c, 0); }
H(h_dlerror) { if (!dl_error) dl_error = gstrdup("symbol not found"); RET32(c, 0); }

/* ----------------------------------------------------------- android log */
static const char *prio_name(int p) { static const char *n[] = {"?", "?", "V", "D", "I", "W", "E", "F"}; return p >= 0 && p < 8 ? n[p] : "?"; }
static void alog(int prio, const char *tag, const char *msg) {
#ifdef __ANDROID__
    __android_log_write(prio, tag ? tag : "guest", msg);
#else
    fprintf(stderr, "%s/%s: %s\n", prio_name(prio), tag ? tag : "guest", msg);
#endif
}
H(h_log_write) { alog((int)P(0), S(1), S(2)); RET32(c, 1); }
H(h_log_print) { GVa va; gva_start(&va, c, 3); char buf[4096]; gfmt(buf, sizeof buf, S(2), &va); alog((int)P(0), S(1), buf); RET32(c, 1); }
H(h_log_vprint){ GVa va; gva_from_list(&va, P(3)); char buf[4096]; gfmt(buf, sizeof buf, S(2), &va); alog((int)P(0), S(1), buf); RET32(c, 1); }
H(h_log_assert){ GVa va; gva_start(&va, c, 3); char buf[4096]; gfmt(buf, sizeof buf, S(2) ? S(2) : "", &va); alog(7, S(1), buf); abort(); }

/* ------------------------------------------------------------------ misc */
H(h_getpid)  { RET32(c, (uint32_t)getpid()); }
H(h_gettid)  { RET32(c, (uint32_t)gettid()); }
H(h_getuid)  { RET32(c, (uint32_t)getuid()); }
H(h_sysconf) {
    int n = (int)P(0);
    /* bionic: _SC_PAGESIZE=0x27, _SC_NPROCESSORS_CONF=0x60, _SC_NPROCESSORS_ONLN=0x61, _SC_CLK_TCK=6 */
    switch (n) {
    case 0x27: case 0x28: RET32(c, 4096); break;
    case 0x60: RET32(c, (uint32_t)sysconf(_SC_NPROCESSORS_CONF)); break;
    case 0x61: RET32(c, (uint32_t)sysconf(_SC_NPROCESSORS_ONLN)); break;
    case 6: RET32(c, 100); break;
    default: RET32(c, (uint32_t)-1);
    }
}
H(h_getpagesize) { RET32(c, 4096); }
H(h_sched_yield) { RET32(c, (uint32_t)sched_yield()); }
H(h_system_property_get) {
    const char *name = S(0);
    char *v = S(1);
    const char *val = "";
    if (!strcmp(name, "ro.product.model")) val = "Recomp";
    else if (!strcmp(name, "ro.product.manufacturer")) val = "nova3recomp";
    else if (!strcmp(name, "ro.build.version.sdk")) val = "19";
    else if (!strcmp(name, "ro.build.version.release")) val = "4.4.4";
    else if (!strcmp(name, "ro.product.cpu.abi")) val = "armeabi-v7a";
    strcpy(v, val);
    RET32(c, (uint32_t)strlen(val));
}
H(h_signal) { RET32(c, 0); }
H(h_sigaction) { RET32(c, 0); }
H(h_raise) { rt_log("guest raise(%u)", P(0)); RET32(c, 0); }
H(h_prctl) { RET32(c, 0); }
H(h_uname) {
    uint32_t u = P(0);
    memset(G2H(u), 0, 65 * 6);
    strcpy((char *)G2H(u), "Linux"); strcpy((char *)G2H(u + 65), "android");
    strcpy((char *)G2H(u + 130), "3.4.0"); strcpy((char *)G2H(u + 195), "#1");
    strcpy((char *)G2H(u + 260), "armv7l");
    RET32(c, 0);
}

/* old bionic atomics (exported by libc before 4.4 headers inlined them) */
H(h_atomic_cmpxchg) { uint32_t exp = P(0); RET32(c, __atomic_compare_exchange_n((uint32_t *)G2H(P(2)), &exp, P(1), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST) ? 0 : 1); }
H(h_atomic_swap)    { RET32(c, __atomic_exchange_n((uint32_t *)G2H(P(1)), P(0), __ATOMIC_SEQ_CST)); }
H(h_atomic_inc)     { RET32(c, __atomic_fetch_add((uint32_t *)G2H(P(0)), 1, __ATOMIC_SEQ_CST)); }
H(h_atomic_dec)     { RET32(c, __atomic_fetch_sub((uint32_t *)G2H(P(0)), 1, __ATOMIC_SEQ_CST)); }

static uint32_t environ_ptr;
static void init_environ(uint32_t a) { if (!environ_ptr) environ_ptr = gcalloc(1, 8); ST32(a, environ_ptr); }

static const HostFunc posix_funcs[] = {
    {"__errno", h_errno}, {"open", h_open}, {"open64", h_open}, {"__open_2", h_open}, {"close", h_close},
    {"read", h_read}, {"write", h_write}, {"pread", h_pread}, {"pread64", h_pread64}, {"lseek", h_lseek},
    {"lseek64", h_lseek64}, {"access", h_access}, {"unlink", h_unlink}, {"mkdir", h_mkdir},
    {"rmdir", h_rmdir}, {"chdir", h_chdir}, {"getcwd", h_getcwd}, {"fsync", h_fsync}, {"dup", h_dup},
    {"dup2", h_dup2}, {"pipe", h_pipe}, {"ftruncate", h_ftruncate}, {"fcntl", h_fcntl}, {"isatty", h_isatty},
    {"stat", h_stat}, {"stat64", h_stat}, {"lstat", h_lstat}, {"lstat64", h_lstat}, {"fstat", h_fstat},
    {"fstat64", h_fstat}, {"opendir", h_opendir}, {"readdir", h_readdir}, {"closedir", h_closedir},
    {"time", h_time}, {"gettimeofday", h_gettimeofday}, {"clock_gettime", h_clock_gettime},
    {"clock", h_clock}, {"usleep", h_usleep}, {"sleep", h_sleep}, {"nanosleep", h_nanosleep},
    {"localtime", h_localtime}, {"localtime_r", h_localtime_r}, {"gmtime", h_gmtime},
    {"gmtime_r", h_gmtime_r}, {"mktime", h_mktime}, {"strftime", h_strftime}, {"difftime", h_difftime},
    {"mmap", h_mmap}, {"munmap", h_munmap}, {"mprotect", h_mprotect}, {"madvise", h_madvise},
    {"dlopen", h_dlopen}, {"dlsym", h_dlsym}, {"dlclose", h_dlclose}, {"dlerror", h_dlerror},
    {"__android_log_write", h_log_write}, {"__android_log_print", h_log_print},
    {"__android_log_vprint", h_log_vprint}, {"__android_log_assert", h_log_assert},
    {"getpid", h_getpid}, {"gettid", h_gettid}, {"getuid", h_getuid}, {"sysconf", h_sysconf},
    {"getpagesize", h_getpagesize}, {"sched_yield", h_sched_yield},
    {"__system_property_get", h_system_property_get}, {"signal", h_signal}, {"bsd_signal", h_signal},
    {"sigaction", h_sigaction}, {"raise", h_raise}, {"prctl", h_prctl}, {"uname", h_uname},
    {"__atomic_cmpxchg", h_atomic_cmpxchg}, {"__atomic_swap", h_atomic_swap},
    {"__atomic_inc", h_atomic_inc}, {"__atomic_dec", h_atomic_dec},
    {NULL, NULL}
};

static const HostData posix_data[] = {
    {"environ", 4, init_environ},
    {NULL, 0, NULL}
};

void rt_libc_posix_init(void) {
    rt_register_host_funcs(posix_funcs);
    rt_register_host_data(posix_data);
}

/* bionic libc bridge: printf/scanf family and FILE streams. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hmap.h"
#include "runtime.h"

#define H(n) static void n(CPU *c)
#define S(n) ((char *)ARGP(c, n))
#define P(n) ARG(c, n)

void rt_set_errno(CPU *c, int e);
const char *rt_map_path(const char *guest_path, char *buf, size_t n);

/* ------------------------------------------------------------ formatting */
/* argument source: sequential (GVa) or positional (%n$, pre-fetched array) */
typedef struct { GVa *va; uint64_t *pos; int next; } ASrc;
static uint32_t a32(ASrc *a, int p) { if (a->pos) return (uint32_t)a->pos[p > 0 ? p - 1 : a->next++]; return gva_u32(a->va); }
static uint64_t a64(ASrc *a, int p) { if (a->pos) return a->pos[p > 0 ? p - 1 : a->next++]; return gva_u64(a->va); }

static int parse_pos(const char **f) {      /* "12$" -> 12, else 0 (pointer untouched) */
    const char *p = *f; int n = 0;
    while (isdigit((unsigned char)*p)) n = n * 10 + (*p++ - '0');
    if (n && *p == '$') { *f = p + 1; return n; }
    return 0;
}

/* pre-scan for positional arguments: record the width (4/8) of each slot */
static int prescan(const char *fmt, uint8_t *sz, int max) {
    int maxpos = 0, any = 0;
    while (*fmt) {
        if (*fmt++ != '%') continue;
        if (*fmt == '%') { fmt++; continue; }
        int p = parse_pos(&fmt);
        if (!p) return 0;
        any = 1;
        while (*fmt && strchr("-+ #0'", *fmt)) fmt++;
        if (*fmt == '*') { fmt++; int q = parse_pos(&fmt); if (q && q <= max) { sz[q - 1] = 4; if (q > maxpos) maxpos = q; } }
        else while (isdigit((unsigned char)*fmt)) fmt++;
        if (*fmt == '.') { fmt++; if (*fmt == '*') { fmt++; int q = parse_pos(&fmt); if (q && q <= max) { sz[q - 1] = 4; if (q > maxpos) maxpos = q; } }
                           else while (isdigit((unsigned char)*fmt)) fmt++; }
        int l64 = 0;
        for (;;) {
            if (*fmt == 'l' && fmt[1] == 'l') { l64 = 1; fmt += 2; }
            else if (*fmt == 'q' || *fmt == 'j') { l64 = 1; fmt++; }
            else if (strchr("hlLzt", *fmt) && *fmt) fmt++;
            else break;
        }
        char cv = *fmt ? *fmt++ : 0;
        if (strchr("fFeEgGaA", cv) && cv) l64 = 1;
        if (p <= max) { sz[p - 1] = l64 ? 8 : 4; if (p > maxpos) maxpos = p; }
    }
    return any ? maxpos : 0;
}

int gfmt(char *out, size_t cap, const char *fmt, GVa *va) {
    size_t len = 0;
    uint8_t sz[64] = {0};
    uint64_t posv[64];
    ASrc A = { va, NULL, 0 };
    int np = prescan(fmt, sz, 64);
    if (np) {
        for (int i = 0; i < np; i++) posv[i] = sz[i] == 8 ? gva_u64(va) : gva_u32(va);
        A.pos = posv;
    }
#define ROOM (len < cap ? cap - len : 0)
#define DST (out ? out + (len < cap ? len : cap) : NULL)
    while (*fmt) {
        if (*fmt != '%') {
            if (len + 1 < cap) out[len] = *fmt;
            len++; fmt++;
            continue;
        }
        const char *st = fmt++;
        if (*fmt == '%') { if (len + 1 < cap) out[len] = '%'; len++; fmt++; continue; }
        int ap = parse_pos(&fmt);
        char spec[64]; int sp = 0;
        spec[sp++] = '%';
        while (*fmt && strchr("-+ #0'", *fmt)) { if (sp < 40) spec[sp++] = *fmt; fmt++; }
        if (*fmt == '*') { fmt++; int q = parse_pos(&fmt); sp += snprintf(spec + sp, sizeof spec - (size_t)sp, "%d", (int32_t)a32(&A, q)); }
        else while (isdigit((unsigned char)*fmt)) { if (sp < 50) spec[sp++] = *fmt; fmt++; }
        if (*fmt == '.') {
            spec[sp++] = '.'; fmt++;
            if (*fmt == '*') { fmt++; int q = parse_pos(&fmt); sp += snprintf(spec + sp, sizeof spec - (size_t)sp, "%d", (int32_t)a32(&A, q)); }
            else while (isdigit((unsigned char)*fmt)) { if (sp < 58) spec[sp++] = *fmt; fmt++; }
        }
        int lng = 0; /* 0 int, 1 h, 2 hh, 3 l(32), 4 ll(64), 5 L */
        for (;;) {
            if (*fmt == 'h') { lng = lng == 1 ? 2 : 1; fmt++; }
            else if (*fmt == 'l') { lng = lng == 3 ? 4 : 3; fmt++; }
            else if (*fmt == 'q' || *fmt == 'j') { lng = 4; fmt++; }
            else if (*fmt == 'L') { lng = 5; fmt++; }
            else if (*fmt == 'z' || *fmt == 't') { lng = 3; fmt++; }
            else break;
        }
        char conv = *fmt ? *fmt++ : 0;
        int n = 0;
        switch (conv) {
        case 'd': case 'i': {
            if (lng == 4) { spec[sp++] = 'l'; spec[sp++] = 'l'; spec[sp++] = conv; spec[sp] = 0;
                            n = snprintf(DST, ROOM, spec, (long long)(int64_t)a64(&A, ap)); }
            else { if (lng == 1) spec[sp++] = 'h'; if (lng == 2) { spec[sp++] = 'h'; spec[sp++] = 'h'; }
                   spec[sp++] = conv; spec[sp] = 0; n = snprintf(DST, ROOM, spec, (int)(int32_t)a32(&A, ap)); }
            break;
        }
        case 'u': case 'o': case 'x': case 'X': {
            if (lng == 4) { spec[sp++] = 'l'; spec[sp++] = 'l'; spec[sp++] = conv; spec[sp] = 0;
                            n = snprintf(DST, ROOM, spec, (unsigned long long)a64(&A, ap)); }
            else { if (lng == 1) spec[sp++] = 'h'; if (lng == 2) { spec[sp++] = 'h'; spec[sp++] = 'h'; }
                   spec[sp++] = conv; spec[sp] = 0; n = snprintf(DST, ROOM, spec, (unsigned)a32(&A, ap)); }
            break;
        }
        case 'c': spec[sp++] = 'c'; spec[sp] = 0; n = snprintf(DST, ROOM, spec, (int)a32(&A, ap)); break;
        case 's': {
            uint32_t p = a32(&A, ap);
            spec[sp++] = 's'; spec[sp] = 0;
            n = snprintf(DST, ROOM, spec, p ? (const char *)G2H(p) : "(null)");
            break;
        }
        case 'p': n = snprintf(DST, ROOM, "0x%x", a32(&A, ap)); break;
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
            uint64_t bits = a64(&A, ap); double d; memcpy(&d, &bits, 8);
            spec[sp++] = conv; spec[sp] = 0; n = snprintf(DST, ROOM, spec, d);
            break;
        }
        case 'n': { uint32_t p = a32(&A, ap); if (p) ST32(p, (uint32_t)len); break; }
        default:
            n = snprintf(DST, ROOM, "%.*s", (int)(fmt - st), st);
        }
        if (n > 0) len += (size_t)n;
    }
    if (cap) out[len < cap ? len : cap - 1] = 0;
    return (int)len;
#undef ROOM
#undef DST
}

static char *gfmt_alloc(const char *fmt, GVa *va, int *outlen) {
    GVa save = *va;
    char small[1024];
    int n = gfmt(small, sizeof small, fmt, va);
    char *buf = malloc((size_t)n + 1);
    if ((size_t)n < sizeof small) memcpy(buf, small, (size_t)n + 1);
    else { *va = save; gfmt(buf, (size_t)n + 1, fmt, va); }
    *outlen = n;
    return buf;
}

/* ----------------------------------------------------------------- FILE */
#define GFILE_SIZE 84u    /* sizeof(FILE) in 32-bit bionic */
static HMap files = HMAP_INIT;
static uint32_t g_sF;

static void sync_flags(uint32_t gf, FILE *f) {
    uint16_t fl = LD16(gf + 12) & ~0x60u;
    if (feof(f)) fl |= 0x20;
    if (ferror(f)) fl |= 0x40;
    ST16(gf + 12, fl);
    ST32(gf + 4, 0); ST32(gf + 8, 0);         /* _r = _w = 0: macros fall back to calls */
}

FILE *rt_host_file(uint32_t gf) {
    if (g_sF && gf >= g_sF && gf < g_sF + 3 * GFILE_SIZE) {
        int idx = (int)((gf - g_sF) / GFILE_SIZE);
        return idx == 0 ? stdin : idx == 1 ? stdout : stderr;
    }
    return hm_get(&files, gf);
}

static uint32_t wrap_file(FILE *f) {
    if (!f) return 0;
    uint32_t gf = gcalloc(1, GFILE_SIZE);
    ST16(gf + 14, (uint32_t)fileno(f));
    hm_put(&files, gf, f);
    return gf;
}

static void init_sF(uint32_t a) {
    g_sF = a;
    for (int i = 0; i < 3; i++) ST16(a + GFILE_SIZE * (uint32_t)i + 14, (uint32_t)i);
}

#define GF(n) rt_host_file(ARG(c, n))

H(h_fopen) {
    char buf[1024];
    const char *path = rt_map_path(S(0), buf, sizeof buf);
    FILE *f = fopen(path, S(1));
    if (!f) rt_set_errno(c, errno);
    RET32(c, wrap_file(f));
}
H(h_fdopen) { RET32(c, wrap_file(fdopen((int)P(0), S(1)))); }
H(h_fclose) {
    FILE *f = hm_del(&files, P(0));
    if (!f) { RET32(c, (uint32_t)-1); return; }
    int r = fclose(f);
    gfree(P(0));
    RET32(c, (uint32_t)r);
}
H(h_fread)  { FILE *f = GF(3); size_t r = f ? fread(G2H(P(0)), P(1), P(2), f) : 0; if (f) sync_flags(P(3), f); RET32(c, (uint32_t)r); }
H(h_fwrite) { FILE *f = GF(3); size_t r = f ? fwrite(G2H(P(0)), P(1), P(2), f) : 0; RET32(c, (uint32_t)r); }
H(h_fseek)  { FILE *f = GF(0); RET32(c, f ? (uint32_t)fseek(f, (int32_t)P(1), (int)P(2)) : (uint32_t)-1); if (f) sync_flags(P(0), f); }
H(h_fseeko64) { FILE *f = GF(0); RET32(c, f ? (uint32_t)fseeko(f, (off_t)(int64_t)ARG64(c, 2), (int)ARG(c, 4)) : (uint32_t)-1); }
H(h_ftell)  { FILE *f = GF(0); RET32(c, f ? (uint32_t)ftell(f) : (uint32_t)-1); }
H(h_ftello64) { FILE *f = GF(0); RET64(c, f ? (uint64_t)ftello(f) : (uint64_t)-1); }
H(h_rewind) { FILE *f = GF(0); if (f) { rewind(f); sync_flags(P(0), f); } }
H(h_fflush) { FILE *f = P(0) ? GF(0) : NULL; RET32(c, (uint32_t)fflush(f)); }
H(h_feof)   { FILE *f = GF(0); RET32(c, f ? (uint32_t)!!feof(f) : 1); }
H(h_ferror) { FILE *f = GF(0); RET32(c, f ? (uint32_t)!!ferror(f) : 1); }
H(h_clearerr) { FILE *f = GF(0); if (f) { clearerr(f); sync_flags(P(0), f); } }
H(h_fileno) { FILE *f = GF(0); RET32(c, f ? (uint32_t)fileno(f) : (uint32_t)-1); }
H(h_fgetc)  { FILE *f = GF(0); int r = f ? fgetc(f) : EOF; if (f) sync_flags(P(0), f); RET32(c, (uint32_t)r); }
H(h_ungetc) { FILE *f = GF(1); RET32(c, f ? (uint32_t)ungetc((int)P(0), f) : (uint32_t)EOF); }
H(h_fgets)  { FILE *f = GF(2); char *r = f ? fgets(S(0), (int)P(1), f) : NULL; if (f) sync_flags(P(2), f); RET32(c, r ? P(0) : 0); }
H(h_fputc)  { FILE *f = GF(1); RET32(c, f ? (uint32_t)fputc((int)P(0), f) : (uint32_t)EOF); }
H(h_fputs)  { FILE *f = GF(1); RET32(c, f ? (uint32_t)fputs(S(0), f) : (uint32_t)EOF); }
H(h_puts)   { RET32(c, (uint32_t)puts(S(0))); }
H(h_putchar){ RET32(c, (uint32_t)putchar((int)P(0))); }
H(h_getchar){ RET32(c, (uint32_t)getchar()); }
H(h_setvbuf){ RET32(c, 0); }
H(h_setbuf) { (void)c; }
H(h_srget)  { FILE *f = GF(0); int r = f ? fgetc(f) : EOF; if (f) sync_flags(P(0), f); RET32(c, (uint32_t)r); }
H(h_swbuf)  { FILE *f = GF(1); int r = f ? fputc((int)P(0), f) : EOF; if (f) sync_flags(P(1), f); RET32(c, (uint32_t)r); }
H(h_remove) { char b[1024]; RET32(c, (uint32_t)remove(rt_map_path(S(0), b, sizeof b))); }
H(h_rename) { char b1[1024], b2[1024]; RET32(c, (uint32_t)rename(rt_map_path(S(0), b1, sizeof b1), rt_map_path(S(1), b2, sizeof b2))); }
H(h_tmpfile){ RET32(c, wrap_file(tmpfile())); }

/* ------------------------------------------------------------- printf */
static void out_file(CPU *c, FILE *f, const char *fmt, GVa *va) {
    int n;
    char *s = gfmt_alloc(fmt, va, &n);
    if (f) fwrite(s, 1, (size_t)n, f);
    free(s);
    RET32(c, (uint32_t)n);
}
H(h_printf)   { GVa va; gva_start(&va, c, 1); out_file(c, stdout, S(0), &va); }
H(h_vprintf)  { GVa va; gva_from_list(&va, P(1)); out_file(c, stdout, S(0), &va); }
H(h_fprintf)  { GVa va; gva_start(&va, c, 2); FILE *f = GF(0); out_file(c, f, S(1), &va); }
H(h_vfprintf) { GVa va; gva_from_list(&va, P(2)); FILE *f = GF(0); out_file(c, f, S(1), &va); }
H(h_sprintf)  { GVa va; gva_start(&va, c, 2); RET32(c, (uint32_t)gfmt(S(0), 0x7fffffff, S(1), &va)); }
H(h_vsprintf) { GVa va; gva_from_list(&va, P(2)); RET32(c, (uint32_t)gfmt(S(0), 0x7fffffff, S(1), &va)); }
H(h_snprintf) { GVa va; gva_start(&va, c, 3); RET32(c, (uint32_t)gfmt(P(1) ? S(0) : NULL, P(1), S(2), &va)); }
H(h_vsnprintf){ GVa va; gva_from_list(&va, P(3)); RET32(c, (uint32_t)gfmt(P(1) ? S(0) : NULL, P(1), S(2), &va)); }
H(h_sprintf_chk)  { GVa va; gva_start(&va, c, 4); RET32(c, (uint32_t)gfmt(S(0), P(2), ARGS(c, 3), &va)); }
H(h_snprintf_chk) { GVa va; gva_start(&va, c, 5); RET32(c, (uint32_t)gfmt(S(0), P(1), ARGS(c, 4), &va)); }
H(h_vsprintf_chk) { GVa va; gva_from_list(&va, ARG(c, 4)); RET32(c, (uint32_t)gfmt(S(0), P(2), S(3), &va)); }
H(h_vsnprintf_chk){ GVa va; gva_from_list(&va, ARG(c, 5)); RET32(c, (uint32_t)gfmt(S(0), P(1), ARGS(c, 4), &va)); }
H(h_asprintf) { GVa va; gva_start(&va, c, 2); int n; char *s = gfmt_alloc(S(1), &va, &n);
                uint32_t g = gmalloc((uint32_t)n + 1); memcpy(G2H(g), s, (size_t)n + 1); free(s);
                ST32(P(0), g); RET32(c, (uint32_t)n); }
H(h_vasprintf){ GVa va; gva_from_list(&va, P(2)); int n; char *s = gfmt_alloc(S(1), &va, &n);
                uint32_t g = gmalloc((uint32_t)n + 1); memcpy(G2H(g), s, (size_t)n + 1); free(s);
                ST32(P(0), g); RET32(c, (uint32_t)n); }

/* -------------------------------------------------------------- scanf */
static int gscan(const char *in, const char *fmt, GVa *va) {
    const char *s = in;
    int count = 0;
    if (!*s) return -1;
    while (*fmt) {
        if (isspace((unsigned char)*fmt)) { while (isspace((unsigned char)*s)) s++; fmt++; continue; }
        if (*fmt != '%') { if (*s != *fmt) break; s++; fmt++; continue; }
        fmt++;
        if (*fmt == '%') { while (isspace((unsigned char)*s)) s++; if (*s != '%') break; s++; fmt++; continue; }
        int suppress = 0, width = 0, lng = 0;
        if (*fmt == '*') { suppress = 1; fmt++; }
        while (isdigit((unsigned char)*fmt)) width = width * 10 + (*fmt++ - '0');
        for (;;) {
            if (*fmt == 'h') { lng = lng == 1 ? 2 : 1; fmt++; }
            else if (*fmt == 'l') { lng = lng == 3 ? 4 : 3; fmt++; }
            else if (*fmt == 'L' || *fmt == 'q' || *fmt == 'j') { lng = 4; fmt++; }
            else if (*fmt == 'z' || *fmt == 't') { lng = 3; fmt++; }
            else break;
        }
        char conv = *fmt++;
        char spec[300]; int consumed = 0;
        char set[260] = "";
        if (conv == '[') {
            int k = 0;
            set[k++] = '[';
            if (*fmt == '^') set[k++] = *fmt++;
            if (*fmt == ']') set[k++] = *fmt++;
            while (*fmt && *fmt != ']' && k < 250) set[k++] = *fmt++;
            if (*fmt == ']') fmt++;
            set[k++] = ']'; set[k] = 0;
        }
        if (conv == 'n') { if (!suppress) ST32(gva_u32(va), (uint32_t)(s - in)); continue; }
        char wbuf[16] = "";
        if (width) snprintf(wbuf, sizeof wbuf, "%d", width);
        if (conv == 'd' || conv == 'i' || conv == 'u' || conv == 'x' || conv == 'X' || conv == 'o') {
            long long v; unsigned long long uv;
            int ok;
            if (conv == 'd' || conv == 'i') { snprintf(spec, sizeof spec, "%%%sll%c%%n", wbuf, conv); ok = sscanf(s, spec, &v, &consumed); uv = (unsigned long long)v; }
            else { snprintf(spec, sizeof spec, "%%%sll%c%%n", wbuf, conv); ok = sscanf(s, spec, &uv, &consumed); }
            if (ok != 1) break;
            s += consumed;
            if (!suppress) {
                uint32_t p = gva_u32(va);
                if (lng == 4) ST64(p, uv); else if (lng == 2) ST8(p, (uint32_t)uv); else if (lng == 1) ST16(p, (uint32_t)uv); else ST32(p, (uint32_t)uv);
                count++;
            }
        } else if (strchr("feEgGaA", conv)) {
            double d;
            snprintf(spec, sizeof spec, "%%%slf%%n", wbuf);
            if (sscanf(s, spec, &d, &consumed) != 1) break;
            s += consumed;
            if (!suppress) {
                uint32_t p = gva_u32(va);
                if (lng >= 3) STD(p, d); else STF(p, (float)d);
                count++;
            }
        } else if (conv == 's' || conv == 'c' || conv == '[') {
            size_t L = strlen(s) + 2;
            char *tmp = malloc(L);
            if (conv == 's') snprintf(spec, sizeof spec, "%%%ss%%n", wbuf);
            else if (conv == 'c') snprintf(spec, sizeof spec, "%%%sc%%n", width ? wbuf : "1");
            else snprintf(spec, sizeof spec, "%%%s%s%%n", wbuf, set);
            int ok = sscanf(s, spec, tmp, &consumed);
            if (ok != 1) { free(tmp); break; }
            if (!suppress) {
                uint32_t p = gva_u32(va);
                if (conv == 'c') memcpy(G2H(p), tmp, (size_t)(width ? width : 1));
                else strcpy((char *)G2H(p), tmp);
                count++;
            }
            s += consumed;
            free(tmp);
        } else {
            break;
        }
    }
    return count;
}
H(h_sscanf)  { GVa va; gva_start(&va, c, 2); RET32(c, (uint32_t)gscan(S(0), S(1), &va)); }
H(h_vsscanf) { GVa va; gva_from_list(&va, P(2)); RET32(c, (uint32_t)gscan(S(0), S(1), &va)); }
H(h_fscanf) {
    /* line-based approximation: read one line and scan it */
    FILE *f = GF(0); char line[4096];
    if (!f || !fgets(line, sizeof line, f)) { RET32(c, (uint32_t)-1); return; }
    GVa va; gva_start(&va, c, 2); RET32(c, (uint32_t)gscan(line, S(1), &va));
}

static const HostFunc stdio_funcs[] = {
    {"fopen", h_fopen}, {"fopen64", h_fopen}, {"fdopen", h_fdopen}, {"fclose", h_fclose},
    {"fread", h_fread}, {"fwrite", h_fwrite}, {"fseek", h_fseek}, {"fseeko", h_fseek},
    {"fseeko64", h_fseeko64}, {"ftell", h_ftell}, {"ftello", h_ftell}, {"ftello64", h_ftello64},
    {"rewind", h_rewind}, {"fflush", h_fflush}, {"feof", h_feof}, {"ferror", h_ferror},
    {"clearerr", h_clearerr}, {"fileno", h_fileno}, {"fgetc", h_fgetc}, {"getc", h_fgetc},
    {"ungetc", h_ungetc}, {"fgets", h_fgets}, {"fputc", h_fputc}, {"putc", h_fputc},
    {"fputs", h_fputs}, {"puts", h_puts}, {"putchar", h_putchar}, {"getchar", h_getchar},
    {"setvbuf", h_setvbuf}, {"setbuf", h_setbuf}, {"__srget", h_srget}, {"__swbuf", h_swbuf},
    {"remove", h_remove}, {"rename", h_rename}, {"tmpfile", h_tmpfile},
    {"printf", h_printf}, {"vprintf", h_vprintf}, {"fprintf", h_fprintf}, {"vfprintf", h_vfprintf},
    {"sprintf", h_sprintf}, {"vsprintf", h_vsprintf}, {"snprintf", h_snprintf}, {"vsnprintf", h_vsnprintf},
    {"__sprintf_chk", h_sprintf_chk}, {"__snprintf_chk", h_snprintf_chk},
    {"__vsprintf_chk", h_vsprintf_chk}, {"__vsnprintf_chk", h_vsnprintf_chk},
    {"asprintf", h_asprintf}, {"vasprintf", h_vasprintf},
    {"sscanf", h_sscanf}, {"vsscanf", h_vsscanf}, {"fscanf", h_fscanf},
    {NULL, NULL}
};

static const HostData stdio_data[] = {
    {"__sF", 3 * GFILE_SIZE, init_sF},
    {NULL, 0, NULL}
};

void rt_libc_stdio_init(void) {
    rt_register_host_funcs(stdio_funcs);
    rt_register_host_data(stdio_data);
}

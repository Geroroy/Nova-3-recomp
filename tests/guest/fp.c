#include <stdio.h>
#include <math.h>
#include <stdint.h>

typedef struct { float m[16]; } Mat4;
typedef struct { float x, y, z, w; } Vec4;

__attribute__((noinline)) void matmul(Mat4 *r, const Mat4 *a, const Mat4 *b) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            float s = 0;
            for (int k = 0; k < 4; k++) s += a->m[i * 4 + k] * b->m[k * 4 + j];
            r->m[i * 4 + j] = s;
        }
}

__attribute__((noinline)) Vec4 xform(const Mat4 *m, Vec4 v) {
    Vec4 r;
    r.x = m->m[0] * v.x + m->m[4] * v.y + m->m[8] * v.z + m->m[12] * v.w;
    r.y = m->m[1] * v.x + m->m[5] * v.y + m->m[9] * v.z + m->m[13] * v.w;
    r.z = m->m[2] * v.x + m->m[6] * v.y + m->m[10] * v.z + m->m[14] * v.w;
    r.w = m->m[3] * v.x + m->m[7] * v.y + m->m[11] * v.z + m->m[15] * v.w;
    return r;
}

__attribute__((noinline)) void saxpy(float *y, const float *x, float a, int n) {
    for (int i = 0; i < n; i++) y[i] = a * x[i] + y[i];
}

__attribute__((noinline)) int to_int(float f) { return (int)f; }
__attribute__((noinline)) unsigned to_uint(double d) { return (unsigned)d; }
__attribute__((noinline)) double from_ll(long long x) { return (double)x; }
__attribute__((noinline)) float fminmax(float a, float b) { return (a < b ? a : b) * 2.0f - (a > b ? a : b); }
__attribute__((noinline)) int fcmp(double a, double b) { return (a < b) * 1 + (a <= b) * 2 + (a == b) * 4 + (a > b) * 8 + (a != b) * 16; }

int16_t samples[64];
__attribute__((noinline)) void mixaudio(int16_t *out, const int16_t *a, const int16_t *b, int n, int vol) {
    for (int i = 0; i < n; i++) {
        int s = (a[i] * vol >> 8) + (b[i] * (256 - vol) >> 8);
        out[i] = (int16_t)(s > 32767 ? 32767 : s < -32768 ? -32768 : s);
    }
}

int test_main(void) {
    Mat4 a, b, r;
    for (int i = 0; i < 16; i++) { a.m[i] = (float)(i + 1) * 0.5f; b.m[i] = (float)(16 - i) * 0.25f - 1.0f; }
    matmul(&r, &a, &b);
    for (int i = 0; i < 16; i++) printf("%.3f%c", r.m[i], i == 15 ? '\n' : ' ');
    Vec4 v = { 1.0f, -2.0f, 0.5f, 1.0f };
    Vec4 t = xform(&r, v);
    printf("xform=%.4f %.4f %.4f %.4f\n", t.x, t.y, t.z, t.w);
    float x[37], y[37];
    for (int i = 0; i < 37; i++) { x[i] = i * 0.1f; y[i] = 1.0f - i * 0.01f; }
    saxpy(y, x, 2.5f, 37);
    double s = 0;
    for (int i = 0; i < 37; i++) s += y[i];
    printf("saxpy=%.6f\n", s);
    printf("conv=%d %d %u %u %.1f\n", to_int(-3.99f), to_int(1e9f), to_uint(4e9), to_uint(5.75), from_ll(-9007199254740993ll));
    printf("minmax=%.3f cmp=%d %d %d\n", fminmax(1.5f, -2.25f), fcmp(1, 2), fcmp(2, 2), fcmp(NAN, 1));
    printf("math=%.6f %.6f %.6f %.6f %.6f\n", sin(0.5), cos(1.25), sqrt(2.0), pow(2.0, 0.5), atan2(1.0, -1.0));
    printf("mathf=%.5f %.5f %.5f %.5f\n", sinf(0.5f), sqrtf(3.0f), floorf(-2.5f), fabsf(-7.25f));
    int16_t a1[64], b1[64];
    for (int i = 0; i < 64; i++) { a1[i] = (int16_t)(i * 1000 - 30000); b1[i] = (int16_t)(32000 - i * 900); }
    mixaudio(samples, a1, b1, 64, 200);
    int cs = 0;
    for (int i = 0; i < 64; i++) cs = cs * 3 + samples[i];
    printf("mix=%d\n", cs);
    double acc = 1.0;
    for (int i = 1; i < 20; i++) acc = acc * 1.0001 + 1.0 / i;
    printf("acc=%.10f\n", acc);
    return 0;
}

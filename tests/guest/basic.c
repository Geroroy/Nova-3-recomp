#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct { int a; short b; char c; long long d; } S;

__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

__attribute__((noinline)) int classify(int x) {
    switch (x) {
    case 0: return 11; case 1: return 23; case 2: return 37; case 3: return 41;
    case 4: return 53; case 5: return 67; case 6: return 71; case 7: return 89;
    case 8: return 97; case 9: return 101; case 10: return 113; case 12: return 7;
    default: return -1;
    }
}

__attribute__((noinline)) const char *bigswitch(unsigned x) {
    switch (x) {
    case 0: return "zero"; case 1: return "one"; case 2: return "two"; case 3: return "three";
    case 4: return "four"; case 5: return "five"; case 6: return "six"; case 7: return "seven";
    case 8: return "eight"; case 9: return "nine"; case 10: return "ten"; case 11: return "eleven";
    case 12: return "twelve"; case 13: return "thirteen"; case 14: return "fourteen";
    case 15: return "fifteen"; case 16: return "sixteen"; case 17: return "seventeen";
    case 300: return "threehundred";
    default: return "many";
    }
}

static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static int divi(int a, int b) { return b ? a / b : 0; }
int (*volatile ops[4])(int, int) = { add, sub, mul, divi };

__attribute__((noinline)) uint64_t mix64(uint64_t x, uint64_t y) {
    x ^= y >> 7; x *= 0x9E3779B97F4A7C15ull; x ^= x >> 29; return x + (y << 13) - (x / (y | 1)) + (x % 1000003);
}

__attribute__((noinline)) int64_t sdiv64(int64_t a, int64_t b) { return a / b + a % b; }

__attribute__((noinline)) unsigned bits(unsigned x) {
    return __builtin_clz(x | 1) + __builtin_popcount(x) * 3 + (__builtin_bswap32(x) & 0xff) + __builtin_ctz(x | 0x80000000u);
}

__attribute__((noinline)) int sat_sum(const signed char *p, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) { s += p[i] * (i & 3 ? -1 : 2); if (s > 1000) s = 1000; if (s < -1000) s = -1000; }
    return s;
}

__attribute__((noinline)) void bubble(int *a, int n) {
    for (int i = 0; i < n; i++) for (int j = 0; j + 1 < n - i; j++) if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }
}

unsigned char gbuf[256];

int test_main(void) {
    printf("fib(20)=%d\n", fib(20));
    for (int i = -1; i < 14; i++) printf("classify(%d)=%d %s\n", i, classify(i), bigswitch((unsigned)i));
    printf("bigswitch(300)=%s\n", bigswitch(300));
    for (int i = 0; i < 4; i++) printf("op%d=%d\n", i, ops[i](1234567, -89));
    uint64_t h = 1;
    for (int i = 0; i < 50; i++) h = mix64(h, (uint64_t)i * 0x12345678ull + 7);
    printf("mix=%llu %llx\n", (unsigned long long)h, (unsigned long long)h);
    printf("sdiv64=%lld %lld\n", (long long)sdiv64(-123456789012345ll, 9876543), (long long)sdiv64(1ll << 62, -3));
    unsigned acc = 0;
    for (unsigned i = 0; i < 1000; i++) acc += bits(i * 2654435761u);
    printf("bits=%u\n", acc);
    signed char sc[100];
    for (int i = 0; i < 100; i++) sc[i] = (signed char)(i * 37 - 50);
    printf("sat=%d\n", sat_sum(sc, 100));
    int arr[32];
    for (int i = 0; i < 32; i++) arr[i] = (i * 7919) % 101 - 50;
    bubble(arr, 32);
    for (int i = 0; i < 32; i++) printf("%d%c", arr[i], i == 31 ? '\n' : ',');
    S s1 = { 1, -2, 'x', -1234567890123ll }, s2;
    memcpy(&s2, &s1, sizeof s1);
    s2.b = (short)(s2.b * 300);
    printf("S=%d %d %c %lld\n", s2.a, s2.b, s2.c, s2.d);
    char buf[128];
    snprintf(buf, sizeof buf, "[%5d|%-5s|%05.1f|%x|%c|%%]", 42, "ab", 3.14159, 255u, 'Z');
    printf("%s len=%d\n", buf, (int)strlen(buf));
    snprintf(buf, sizeof buf, "%2$s-%1$d-%3$.2f-%2$s", 77, "pos", 0.125);
    printf("%s\n", buf);
    for (int i = 0; i < 256; i++) gbuf[i] = (unsigned char)(i ^ 0x5a);
    unsigned sum = 0;
    for (int i = 0; i < 256; i++) sum = sum * 31 + gbuf[i];
    printf("gbuf=%u\n", sum);
    char *dup = strdup("hello recompiled world");
    for (char *p = dup; *p; p++) if (*p == 'o') *p = '0';
    printf("%s %d %s\n", dup, (int)strlen(dup), strstr(dup, "rec"));
    free(dup);
    long v = strtol("-0x7fff", NULL, 16);
    printf("strtol=%ld atoi=%d\n", v, atoi("  987xyz"));
    int a, b; char w[16];
    int n = sscanf("12 34 word", "%d %d %15s", &a, &b, w);
    printf("sscanf=%d %d %d %s\n", n, a, b, w);
    return 0;
}

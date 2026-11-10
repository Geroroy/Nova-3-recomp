/* libm bridge (softfp ABI: doubles in core register pairs). */
#include <math.h>
#include <stdlib.h>

#include "runtime.h"

#define D1(n) static void h_##n(CPU *c) { RETD(c, n(ARGD(c, 0))); }
#define D2(n) static void h_##n(CPU *c) { RETD(c, n(ARGD(c, 0), ARGD(c, 2))); }
#define F1(n) static void h_##n(CPU *c) { RETF(c, n(ARGF(c, 0))); }
#define F2(n) static void h_##n(CPU *c) { RETF(c, n(ARGF(c, 0), ARGF(c, 1))); }
#define MATH_D1(X) X(sin) X(cos) X(tan) X(asin) X(acos) X(atan) X(sinh) X(cosh) X(tanh) X(exp) X(exp2) \
    X(log) X(log10) X(log2) X(log1p) X(expm1) X(sqrt) X(ceil) X(floor) X(fabs) X(round) X(trunc) X(rint) X(nearbyint) X(cbrt)
#define MATH_D2(X) X(atan2) X(pow) X(fmod) X(hypot) X(fmin) X(fmax) X(copysign) X(remainder)
#define MATH_F1(X) X(sinf) X(cosf) X(tanf) X(asinf) X(acosf) X(atanf) X(sinhf) X(coshf) X(tanhf) X(expf) X(exp2f) \
    X(logf) X(log10f) X(log2f) X(sqrtf) X(ceilf) X(floorf) X(fabsf) X(roundf) X(truncf) X(rintf) X(nearbyintf) X(cbrtf)
#define MATH_F2(X) X(atan2f) X(powf) X(fmodf) X(hypotf) X(fminf) X(fmaxf) X(copysignf)
MATH_D1(D1) MATH_D2(D2) MATH_F1(F1) MATH_F2(F2)

static void h_ldexp(CPU *c)  { RETD(c, ldexp(ARGD(c, 0), (int)ARG(c, 2))); }
static void h_ldexpf(CPU *c) { RETF(c, ldexpf(ARGF(c, 0), (int)ARG(c, 1))); }
static void h_frexp(CPU *c)  { int e; double r = frexp(ARGD(c, 0), &e); ST32(ARG(c, 2), (uint32_t)e); RETD(c, r); }
static void h_frexpf(CPU *c) { int e; float r = frexpf(ARGF(c, 0), &e); ST32(ARG(c, 1), (uint32_t)e); RETF(c, r); }
static void h_modf(CPU *c)   { double ip; double r = modf(ARGD(c, 0), &ip); STD(ARG(c, 2), ip); RETD(c, r); }
static void h_modff(CPU *c)  { float ip; float r = modff(ARGF(c, 0), &ip); STF(ARG(c, 1), ip); RETF(c, r); }
static void h_lrint(CPU *c)  { RET32(c, (uint32_t)(int32_t)lrint(ARGD(c, 0))); }
static void h_lrintf(CPU *c) { RET32(c, (uint32_t)(int32_t)lrintf(ARGF(c, 0))); }
static void h_lround(CPU *c) { RET32(c, (uint32_t)(int32_t)lround(ARGD(c, 0))); }
static void h_lroundf(CPU *c){ RET32(c, (uint32_t)(int32_t)lroundf(ARGF(c, 0))); }
static void h_sincos(CPU *c) { double x = ARGD(c, 0); STD(ARG(c, 2), sin(x)); STD(ARG(c, 3), cos(x)); }
static void h_sincosf(CPU *c){ float x = ARGF(c, 0); STF(ARG(c, 1), sinf(x)); STF(ARG(c, 2), cosf(x)); }
static void h_isnan(CPU *c)  { RET32(c, (uint32_t)!!isnan(ARGD(c, 0))); }
static void h_isnanf(CPU *c) { RET32(c, (uint32_t)!!isnan(ARGF(c, 0))); }
static void h_isinf(CPU *c)  { RET32(c, (uint32_t)!!isinf(ARGD(c, 0))); }
static void h_isinff(CPU *c) { RET32(c, (uint32_t)!!isinf(ARGF(c, 0))); }
static void h_finite(CPU *c) { RET32(c, (uint32_t)!!isfinite(ARGD(c, 0))); }
static void h_finitef(CPU *c){ RET32(c, (uint32_t)!!isfinite(ARGF(c, 0))); }
static void h_signbit(CPU *c){ RET32(c, (uint32_t)!!signbit(ARGD(c, 0))); }
static void h_signbitf(CPU *c){ RET32(c, (uint32_t)!!signbit(ARGF(c, 0))); }
static void h_fpclassifyd(CPU *c) { RET32(c, (uint32_t)fpclassify(ARGD(c, 0))); }

/* AEABI soft-float helpers (only needed if the module imports them) */
static double D(CPU *c, int n) { return ARGD(c, n); }
static float F(CPU *c, int n) { return ARGF(c, n); }
static void h_dadd(CPU *c) { RETD(c, D(c, 0) + D(c, 2)); }
static void h_dsub(CPU *c) { RETD(c, D(c, 0) - D(c, 2)); }
static void h_drsub(CPU *c){ RETD(c, D(c, 2) - D(c, 0)); }
static void h_dmul(CPU *c) { RETD(c, D(c, 0) * D(c, 2)); }
static void h_ddiv(CPU *c) { RETD(c, D(c, 0) / D(c, 2)); }
static void h_fadd(CPU *c) { RETF(c, F(c, 0) + F(c, 1)); }
static void h_fsub(CPU *c) { RETF(c, F(c, 0) - F(c, 1)); }
static void h_fmul(CPU *c) { RETF(c, F(c, 0) * F(c, 1)); }
static void h_fdiv(CPU *c) { RETF(c, F(c, 0) / F(c, 1)); }
static void h_i2d(CPU *c)  { RETD(c, (double)(int32_t)ARG(c, 0)); }
static void h_ui2d(CPU *c) { RETD(c, (double)ARG(c, 0)); }
static void h_i2f(CPU *c)  { RETF(c, (float)(int32_t)ARG(c, 0)); }
static void h_ui2f(CPU *c) { RETF(c, (float)ARG(c, 0)); }
static void h_l2d(CPU *c)  { RETD(c, (double)(int64_t)ARG64(c, 0)); }
static void h_ul2d(CPU *c) { RETD(c, (double)ARG64(c, 0)); }
static void h_l2f(CPU *c)  { RETF(c, (float)(int64_t)ARG64(c, 0)); }
static void h_ul2f(CPU *c) { RETF(c, (float)ARG64(c, 0)); }
static void h_d2iz(CPU *c) { RET32(c, (uint32_t)f2s32(D(c, 0))); }
static void h_d2uiz(CPU *c){ RET32(c, f2u32(D(c, 0))); }
static void h_f2iz(CPU *c) { RET32(c, (uint32_t)f2s32(F(c, 0))); }
static void h_f2uiz(CPU *c){ RET32(c, f2u32(F(c, 0))); }
static void h_d2lz(CPU *c) { RET64(c, (uint64_t)(int64_t)D(c, 0)); }
static void h_d2ulz(CPU *c){ double x = D(c, 0); RET64(c, x <= 0 ? 0 : (uint64_t)x); }
static void h_f2lz(CPU *c) { RET64(c, (uint64_t)(int64_t)F(c, 0)); }
static void h_f2ulz(CPU *c){ float x = F(c, 0); RET64(c, x <= 0 ? 0 : (uint64_t)x); }
static void h_f2d(CPU *c)  { RETD(c, (double)F(c, 0)); }
static void h_d2f(CPU *c)  { RETF(c, (float)D(c, 0)); }
static void h_dcmpeq(CPU *c){ RET32(c, D(c, 0) == D(c, 2)); }
static void h_dcmplt(CPU *c){ RET32(c, D(c, 0) <  D(c, 2)); }
static void h_dcmple(CPU *c){ RET32(c, D(c, 0) <= D(c, 2)); }
static void h_dcmpge(CPU *c){ RET32(c, D(c, 0) >= D(c, 2)); }
static void h_dcmpgt(CPU *c){ RET32(c, D(c, 0) >  D(c, 2)); }
static void h_dcmpun(CPU *c){ RET32(c, isnan(D(c, 0)) || isnan(D(c, 2))); }
static void h_fcmpeq(CPU *c){ RET32(c, F(c, 0) == F(c, 1)); }
static void h_fcmplt(CPU *c){ RET32(c, F(c, 0) <  F(c, 1)); }
static void h_fcmple(CPU *c){ RET32(c, F(c, 0) <= F(c, 1)); }
static void h_fcmpge(CPU *c){ RET32(c, F(c, 0) >= F(c, 1)); }
static void h_fcmpgt(CPU *c){ RET32(c, F(c, 0) >  F(c, 1)); }
static void h_fcmpun(CPU *c){ RET32(c, isnan(F(c, 0)) || isnan(F(c, 1))); }

#define ENT(n) {#n, h_##n},
static const HostFunc math_funcs[] = {
    MATH_D1(ENT) MATH_D2(ENT) MATH_F1(ENT) MATH_F2(ENT)
    ENT(ldexp) ENT(ldexpf) ENT(frexp) ENT(frexpf) ENT(modf) ENT(modff) ENT(lrint) ENT(lrintf)
    ENT(lround) ENT(lroundf) ENT(sincos) ENT(sincosf)
    {"scalbn", h_ldexp}, {"scalbnf", h_ldexpf},
    {"isnan", h_isnan}, {"__isnan", h_isnan}, {"isnanf", h_isnanf}, {"__isnanf", h_isnanf},
    {"isinf", h_isinf}, {"__isinf", h_isinf}, {"isinff", h_isinff}, {"__isinff", h_isinff},
    {"finite", h_finite}, {"__isfinite", h_finite}, {"finitef", h_finitef}, {"__isfinitef", h_finitef},
    {"__signbit", h_signbit}, {"__signbitf", h_signbitf}, {"__fpclassifyd", h_fpclassifyd},
    {"__aeabi_dadd", h_dadd}, {"__aeabi_dsub", h_dsub}, {"__aeabi_drsub", h_drsub}, {"__aeabi_dmul", h_dmul},
    {"__aeabi_ddiv", h_ddiv}, {"__aeabi_fadd", h_fadd}, {"__aeabi_fsub", h_fsub}, {"__aeabi_fmul", h_fmul},
    {"__aeabi_fdiv", h_fdiv}, {"__aeabi_i2d", h_i2d}, {"__aeabi_ui2d", h_ui2d}, {"__aeabi_i2f", h_i2f},
    {"__aeabi_ui2f", h_ui2f}, {"__aeabi_l2d", h_l2d}, {"__aeabi_ul2d", h_ul2d}, {"__aeabi_l2f", h_l2f},
    {"__aeabi_ul2f", h_ul2f}, {"__aeabi_d2iz", h_d2iz}, {"__aeabi_d2uiz", h_d2uiz}, {"__aeabi_f2iz", h_f2iz},
    {"__aeabi_f2uiz", h_f2uiz}, {"__aeabi_d2lz", h_d2lz}, {"__aeabi_d2ulz", h_d2ulz}, {"__aeabi_f2lz", h_f2lz},
    {"__aeabi_f2ulz", h_f2ulz}, {"__aeabi_f2d", h_f2d}, {"__aeabi_d2f", h_d2f},
    {"__aeabi_dcmpeq", h_dcmpeq}, {"__aeabi_dcmplt", h_dcmplt}, {"__aeabi_dcmple", h_dcmple},
    {"__aeabi_dcmpge", h_dcmpge}, {"__aeabi_dcmpgt", h_dcmpgt}, {"__aeabi_dcmpun", h_dcmpun},
    {"__aeabi_fcmpeq", h_fcmpeq}, {"__aeabi_fcmplt", h_fcmplt}, {"__aeabi_fcmple", h_fcmple},
    {"__aeabi_fcmpge", h_fcmpge}, {"__aeabi_fcmpgt", h_fcmpgt}, {"__aeabi_fcmpun", h_fcmpun},
    {NULL, NULL}
};

void rt_libc_math_init(void) { rt_register_host_funcs(math_funcs); }

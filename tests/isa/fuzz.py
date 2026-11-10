#!/usr/bin/env python3
"""Differential ISA fuzzer: qemu-arm (reference) vs nova3recomp output.

Each case is a random instruction sequence executed with a random initial
state (r0-r11, NZCV, d0-d31, 256-byte scratch at r12). The final state is
dumped and compared byte for byte (NaNs compared loosely).
"""
import argparse
import os
import random
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NDK = os.environ.get("ANDROID_NDK_HOME", "/opt/android/android-ndk-r27c")
TC = f"{NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin"
CC = f"{TC}/armv7a-linux-androideabi21-clang"

R = [f"r{i}" for i in range(12)]
RI = [f"r{i}" for i in range(10)]   # operands of random ALU ops (r10/r11 are address temps)
CONDS = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"]
SCRATCH = 256
STATE = 12 * 4 + 4 + 32 * 8 + SCRATCH + 4   # regs, apsr, d regs, scratch, fpscr


def rr(): return random.choice(RI)
def imm8(): return random.choice([0, 1, 2, 7, 31, 32, 255, 0x80, 0xff00, 0xff000000, 0x3fc, 0x10000, 0xab00ab00 if False else 0x2a0])


def shift_op(thumb):
    r = rr()
    k = random.randint(0, 5)
    if k == 0: return r
    t = random.choice(["lsl", "lsr", "asr", "ror"])
    if k == 1 and not thumb: return f"{r}, {t} {rr()}"
    if k == 2: return f"{r}, rrx"
    n = random.randint(1, 31) if t in ("lsl", "ror") else random.randint(1, 32)
    return f"{r}, {t} #{n}"


def gen_int(thumb):
    k = random.randint(0, 22)
    s = random.choice(["", "s"])
    op = random.choice(["add", "adc", "sub", "sbc", "rsb", "and", "orr", "eor", "bic"] + ([] if thumb else ["rsc"]) + (["orn"] if thumb else []))
    if k <= 4:
        return f"{op}{s} {rr()}, {rr()}, {shift_op(thumb)}"
    if k <= 6:
        return f"{op}{s} {rr()}, {rr()}, #{imm8()}"
    if k == 7:
        return f"{random.choice(['mov', 'mvn'])}{s} {rr()}, {shift_op(thumb)}"
    if k == 8:
        return f"{random.choice(['cmp', 'cmn', 'tst', 'teq'])} {rr()}, {random.choice([shift_op(thumb), '#' + str(imm8())])}"
    if k == 9:
        t = random.choice(["lsl", "lsr", "asr", "ror"])
        return f"{t}{s} {rr()}, {rr()}, {random.choice(['#' + str(random.randint(1, 31)), rr()])}"
    if k == 10:
        op = random.choice(['mul', 'mla', 'mls'])
        return f"{op} {rr()}, {rr()}, {rr()}" + (f", {rr()}" if op != "mul" else "")
    if k == 11:
        a, b = random.sample(R, 2)
        return f"{random.choice(['umull', 'smull', 'umlal', 'smlal'])} {a}, {b}, {rr()}, {rr()}"
    if k == 12:
        return f"{random.choice(['sxtb', 'sxth', 'uxtb', 'uxth'])} {rr()}, {rr()}" + random.choice(["", ", ror #8", ", ror #16", ", ror #24"])
    if k == 13:
        return f"{random.choice(['sxtab', 'sxtah', 'uxtab', 'uxtah'])} {rr()}, {rr()}, {rr()}" + random.choice(["", ", ror #8"])
    if k == 14:
        lsb = random.randint(0, 31); w = random.randint(1, 32 - lsb)
        return f"{random.choice(['ubfx', 'sbfx', 'bfi'])} {rr()}, {rr()}, #{lsb}, #{w}"
    if k == 15:
        lsb = random.randint(0, 31); w = random.randint(1, 32 - lsb)
        return f"bfc {rr()}, #{lsb}, #{w}"
    if k == 16:
        return f"{random.choice(['clz', 'rbit', 'rev', 'rev16', 'revsh'])} {rr()}, {rr()}"
    if k == 17:
        return f"{random.choice(['ssat', 'usat'])} {rr()}, #{random.randint(1, 31)}, {rr()}" + random.choice(["", ", lsl #3", ", asr #5"])
    if k == 18:
        return f"{random.choice(['smulbb', 'smulbt', 'smultb', 'smultt', 'smulwb', 'smulwt', 'smmul'])} {rr()}, {rr()}, {rr()}"
    if k == 19:
        return f"{random.choice(['smlabb', 'smlatt', 'smlawb', 'smmla', 'smmls'])} {rr()}, {rr()}, {rr()}, {rr()}"
    if k == 20:
        return f"{random.choice(['movw', 'movt'])} {rr()}, #{random.randint(0, 65535)}"
    if k == 21:
        op = random.choice(['pkhbt', 'pkhtb'])
        return f"{op} {rr()}, {rr()}, {rr()}" + random.choice(["", ", lsl #4" if op == "pkhbt" else ", asr #8"])
    return f"{random.choice(['qadd', 'qsub'])} {rr()}, {rr()}, {rr()}"


def gen_mem(thumb):
    k = random.randint(0, 6)
    off = random.randrange(0, 120, 4)
    if k <= 2:
        op = random.choice(["ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldrsb", "ldrsh"])
        mode = random.randint(0, 2)
        if mode == 0: return f"{op} {rr()}, [r12, #{off}]"
        if mode == 1: return f"add r11, r12, #{off}\n    {op} {random.choice(R[:11])}, [r11, #-{random.randrange(0, off + 1, 2) if 'h' in op else random.randrange(0, off + 1)}]"
        return f"and r10, r10, #60\n    {op} {random.choice(R[:10])}, [r12, r10]"
    if k == 3:
        return f"add r11, r12, #{off}\n    {random.choice(['ldr', 'str'])} {random.choice(R[:11])}, [r11], #{random.choice([4, -4, 8])}"
    if k == 4:
        regs = sorted(random.sample(R[:10], random.randint(1, 5)), key=lambda r: int(r[1:]))
        return f"add r11, r12, #{off}\n    {random.choice(['ldm', 'stm', 'stmdb', 'ldmdb'])} r11{random.choice(['', '!'])}, {{{', '.join(regs)}}}"
    if k == 5:
        a = random.randrange(0, 10, 2)
        return f"{random.choice(['ldrd', 'strd'])} r{a}, r{a + 1}, [r12, #{off}]"
    return f"add r11, r12, #{off}\n    vldr d{random.randint(0, 15)}, [r11]" if random.random() < 0.5 else \
        f"vstr s{random.randint(0, 31)}, [r12, #{off}]"


def sreg(): return f"s{random.randint(0, 31)}"
def dreg(): return f"d{random.randint(0, 31)}"
def qreg(): return f"q{random.randint(0, 15)}"


def gen_vfp(thumb):
    k = random.randint(0, 9)
    if k <= 2:
        op = random.choice(["vadd", "vsub", "vmul", "vdiv", "vmla", "vmls", "vnmul"])
        if random.random() < 0.5: return f"{op}.f32 {sreg()}, {sreg()}, {sreg()}"
        return f"{op}.f64 {dreg()}, {dreg()}, {dreg()}"
    if k == 3:
        op = random.choice(["vneg", "vabs", "vmov"])
        return random.choice([f"{op}.f32 {sreg()}, {sreg()}", f"{op}.f64 {dreg()}, {dreg()}"])
    if k == 4:
        return random.choice([f"vcvt.f64.f32 {dreg()}, {sreg()}", f"vcvt.f32.f64 {sreg()}, {dreg()}",
                              f"vcvt.s32.f32 {sreg()}, {sreg()}", f"vcvt.f32.s32 {sreg()}, {sreg()}",
                              f"vcvt.u32.f32 {sreg()}, {sreg()}", f"vcvt.f32.u32 {sreg()}, {sreg()}",
                              f"vcvt.s32.f64 {sreg()}, {dreg()}", f"vcvt.f64.s32 {dreg()}, {sreg()}"])
    if k == 5:
        return f"vcmp.f32 {sreg()}, {sreg()}\n    vmrs APSR_nzcv, fpscr"
    if k == 6:
        return random.choice([f"vmov {sreg()}, {rr()}", f"vmov {rr()}, {sreg()}", f"vmov {dreg()}, {rr()}, {rr()}",
                              f"vmov.32 d{random.randint(0, 31)}[{random.randint(0, 1)}], {rr()}"])
    if k == 7:
        a, b = random.sample(R, 2)
        return f"vmov {a}, {b}, {dreg()}"
    if k == 8:
        return random.choice(["vmov.f32 s3, #0.5", "vmov.f64 d5, #-2.0", "vmov.f32 s20, #1.25"])
    return f"vsqrt.f64 {dreg()}, {dreg()}\n    vabs.f64 d1, d1"


def gen_neon(thumb):
    k = random.randint(0, 12)
    it = random.choice(["i8", "i16", "i32"])
    st = random.choice(["s8", "s16", "s32", "u8", "u16", "u32"])
    reg = random.choice([dreg, qreg])
    if k <= 1:
        op = random.choice(["vadd", "vsub", "vmul", "vmla", "vmls"])
        dt = random.choice(["f32", it] if op != "vmul" else ["f32", "i8", "i16", "i32"])
        return f"{op}.{dt} {reg()}, {reg()}, {reg()}" if reg is dreg else f"{op}.{dt} {qreg()}, {qreg()}, {qreg()}"
    if k == 2:
        op = random.choice(["vand", "vorr", "veor", "vbic", "vorn", "vbsl", "vbit", "vbif"])
        return f"{op} {qreg()}, {qreg()}, {qreg()}"
    if k == 3:
        return random.choice([f"vdup.{random.choice(['16', '8', '32'])} {random.choice([qreg, dreg])()}, {rr()}", f"vdup.32 {qreg()}, d{random.randint(0, 31)}[1]",
                              f"vdup.16 {dreg()}, d{random.randint(0, 31)}[3]"])
    if k == 4:
        return random.choice([f"vmov.i32 {qreg()}, #{random.choice([0, 0xff, 0x7f00, 0x10000])}", f"vmov.i16 {qreg()}, #{random.choice([8, 0x7d00, 0xff])}",
                              f"vmov.i8 {dreg()}, #{random.randint(0, 255)}", f"vmov.f32 {qreg()}, #0.5", f"vmvn.i32 {qreg()}, #0xff"])
    if k == 5:
        op = random.choice(["vmax", "vmin", "vabd"])
        return f"{op}.{random.choice([st, 'f32'])} {qreg()}, {qreg()}, {qreg()}"
    if k == 6:
        op = random.choice(["vceq", "vcge", "vcgt"])
        return f"{op}.{random.choice([st, 'f32']) if op != 'vceq' else random.choice([it, 'f32'])} {qreg()}, {qreg()}, {qreg()}"
    if k == 7:
        n = random.randint(1, 7)
        return f"{random.choice(['vshl.i16', 'vshr.s16', 'vshr.u16', 'vsra.s16'])} {qreg()}, {qreg()}, #{n}"
    if k == 8:
        a, b = random.sample(range(32), 2)
        return f"{random.choice(['vzip', 'vuzp', 'vtrn'])}.{random.choice(['8', '16'])} d{a}, d{b}" if random.random() < .3 else \
            f"{random.choice(['vzip', 'vuzp', 'vtrn'])}.{random.choice(['8', '16', '32'])} q{random.randint(0, 7)}, q{random.randint(8, 15)}"
    if k == 9:
        return random.choice([f"vmovl.{random.choice(['s8', 'u8', 's16', 'u16', 's32', 'u32'])} {qreg()}, {dreg()}",
                              f"vmovn.{random.choice(['i16', 'i32', 'i64'])} {dreg()}, {qreg()}",
                              f"vqmovn.{random.choice(['s16', 's32', 'u16', 'u32'])} {dreg()}, {qreg()}"])
    if k == 10:
        return random.choice([f"vmul.f32 {qreg()}, {qreg()}, d{random.randint(0, 15)}[{random.randint(0, 1)}]",
                              f"vmla.f32 {qreg()}, {qreg()}, d{random.randint(0, 15)}[{random.randint(0, 1)}]",
                              f"vpadd.f32 {dreg()}, {dreg()}, {dreg()}", f"vpadd.i16 {dreg()}, {dreg()}, {dreg()}"])
    if k == 11:
        return random.choice([f"vext.8 {qreg()}, {qreg()}, {qreg()}, #{random.randint(0, 15)}",
                              f"vrev64.32 {qreg()}, {qreg()}", f"vrev32.16 {dreg()}, {dreg()}", f"vswp {dreg()}, {dreg()}",
                              f"vcvt.s32.f32 {qreg()}, {qreg()}", f"vcvt.f32.u32 {qreg()}, {qreg()}"])
    off = random.randrange(0, 96, 16)
    return random.choice([f"add r11, r12, #{off}\n    vld1.32 {{d{(a := random.randint(0, 30))}, d{a + 1}}}, [r11]!",
                          f"add r11, r12, #{off}\n    vst1.16 {{d{(a := random.randint(0, 30))}, d{a + 1}}}, [r11]",
                          f"add r11, r12, #{off}\n    vld1.32 {{d{random.randint(0, 31)}[1]}}, [r11]",
                          f"add r11, r12, #{off}\n    vld2.16 {{d{(a := random.randint(0, 30))}, d{a + 1}}}, [r11]",
                          f"add r11, r12, #{off}\n    vst2.32 {{d{(a := random.randint(0, 30))}, d{a + 1}}}, [r11]",
                          f"add r11, r12, #{off}\n    vld1.32 {{d{random.randint(0, 31)}[]}}, [r11]"])


def gen_case(thumb, n, kinds):
    lines = []
    for _ in range(n):
        g = random.choice(kinds)
        ins = g(thumb)
        if not thumb and random.random() < 0.25 and g is gen_int and "\n" not in ins:
            # conditional execution in ARM mode
            parts = ins.split(" ", 1)
            m = parts[0]
            c = random.choice(CONDS)
            m = m + c
            ins = m + " " + parts[1]
        elif thumb and random.random() < 0.2 and g is gen_int and "\n" not in ins:
            parts = ins.split(" ", 1)
            c = random.choice(CONDS)
            ins = f"it {c}\n    {parts[0]}{c} {parts[1]}"
        lines.append("    " + ins)
    return "\n".join(lines)


def rand_state():
    b = bytearray()
    for _ in range(12):
        b += struct.pack("<I", random.choice([0, 1, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, random.getrandbits(32), random.getrandbits(8), random.getrandbits(16)]))
    b += struct.pack("<I", random.getrandbits(4) << 28)
    for _ in range(32):
        if random.random() < 0.5:
            b += struct.pack("<ff", random.uniform(-1000, 1000), random.choice([0.5, -3.0, random.uniform(-10, 10)]))
        else:
            b += struct.pack("<d", random.uniform(-1e6, 1e6)) if random.random() < 0.5 else struct.pack("<Q", random.getrandbits(64))
    b += bytes(random.getrandbits(8) for _ in range(SCRATCH))
    b += struct.pack("<I", 0)
    return bytes(b)


def asm_source(body, state, thumb):
    mode = ".thumb\n    .thumb_func" if thumb else ".arm"
    sbytes = ", ".join(str(x) for x in state)
    return f"""    .syntax unified
    .fpu neon
    .text
    .global test_fn
    .type test_fn, %function
    {mode}
test_fn:
    push {{r4-r11, lr}}
    vpush {{d8-d15}}
    push {{r1}}
    mov r12, r0
    @ load state
    vldmia r12, {{d0-d15}}
    add r12, r0, #0
    ldr r1, [r12, #48]
    msr APSR_nzcvq, r1
    add r1, r12, #52
    vldmia r1!, {{d0-d15}}
    vldmia r1!, {{d16-d31}}
    ldm r12, {{r0-r11}}
    add r12, r12, #{52 + 256}
{body}
    @ store state: r12 = scratch, out pointer is on the stack
    push {{r0}}
    ldr r0, [sp, #4]
    stm r0, {{r1-r11}}
    pop {{r1}}
    str r1, [r0, #44]
    ldr r1, [r0, #0]
    @ shift r1..r11 down: stored at out[0..10] -> move to out[1..11]
    add r2, r0, #40
1:  ldr r3, [r2, #-4]
    str r3, [r2]
    sub r2, r2, #4
    cmp r2, r0
    bne 1b
    ldr r3, [r0, #44]
    str r3, [r0]
    mrs r1, APSR
    and r1, r1, #0xf0000000
    str r1, [r0, #48]
    add r1, r0, #52
    vstmia r1!, {{d0-d15}}
    vstmia r1!, {{d16-d31}}
    mov r2, #0
2:  ldr r3, [r12, r2]
    str r3, [r1, r2]
    add r2, r2, #4
    cmp r2, #{SCRATCH}
    bne 2b
    vmrs r3, fpscr
    and r3, r3, #0xf0000000
    str r3, [r1, #{SCRATCH}]
    add sp, sp, #4
    vpop {{d8-d15}}
    pop {{r4-r11, pc}}
    .ltorg

    .data
    .global state_in, state_out, state_size
    .balign 8
state_in:
    .byte {sbytes}
    .balign 8
state_out:
    .space {STATE}
state_size:
    .word {STATE}
    .equ STATE_SIZE, {STATE}
"""


def cmp_states(a, b):
    diffs = []
    names = [f"r{i}" for i in range(12)] + ["apsr"]
    for i in range(13):
        if i == 11:
            continue        # r11 holds scratch addresses (layout differs between runs)
        x, y = struct.unpack_from("<I", a, 4 * i)[0], struct.unpack_from("<I", b, 4 * i)[0]
        if x != y:
            diffs.append(f"{names[i]}: qemu={x:#010x} recomp={y:#010x}")
    for i in range(32):
        off = 52 + 8 * i
        x, y = a[off:off + 8], b[off:off + 8]
        if x != y:
            # loose NaN comparison per 32-bit lane and per 64-bit value
            fx = struct.unpack("<ff", x); fy = struct.unpack("<ff", y)
            dx = struct.unpack("<d", x)[0]; dy = struct.unpack("<d", y)[0]
            if (dx != dx and dy != dy) or all((p != p and q != q) or p == q for p, q in zip(fx, fy)):
                continue
            diffs.append(f"d{i}: qemu={x.hex()} recomp={y.hex()}")
    sa, sb = a[52 + 256:52 + 256 + SCRATCH], b[52 + 256:52 + 256 + SCRATCH]
    if sa != sb:
        k = next(j for j in range(SCRATCH) if sa[j] != sb[j])
        diffs.append(f"scratch[{k}]: qemu={sa[k:k + 8].hex()} recomp={sb[k:k + 8].hex()}")
    fa, fb = a[-4:], b[-4:]
    if fa != fb:
        diffs.append(f"fpscr: qemu={fa.hex()} recomp={fb.hex()}")
    return diffs


def build_runtime(out):
    lib = os.path.join(out, "libnova3rt.a")
    if os.path.exists(lib):
        return lib
    objs = []
    for f in sorted(os.listdir(f"{ROOT}/runtime/src")):
        if f.endswith(".c"):
            o = os.path.join(out, f + ".o")
            subprocess.check_call(["clang", "-O1", "-D_GNU_SOURCE", f"-I{ROOT}/runtime/include", "-w", "-c",
                                   f"{ROOT}/runtime/src/{f}", "-o", o])
            objs.append(o)
    subprocess.check_call(["ar", "rcs", lib] + objs)
    return lib


def run_case(idx, args, out, body=None, state=None, thumb=None):
    if thumb is None:
        thumb = args.mode == "thumb" or (args.mode == "both" and idx % 2)
    kinds = {"int": [gen_int], "mem": [gen_mem], "vfp": [gen_vfp], "neon": [gen_neon]}
    ks = []
    for k in args.kinds.split(","):
        ks += kinds[k]
    if body is None:
        body = gen_case(thumb, args.length, ks)
        state = rand_state()
    run_case.last = (body, state, thumb)
    d = os.path.join(out, f"case{idx}")
    os.makedirs(d, exist_ok=True)
    src = os.path.join(d, "case.S")
    open(src, "w").write(asm_source(body, state, thumb))
    flags = ["-march=armv7-a", "-mfpu=neon", "-mfloat-abi=softfp", "-Wa,-mimplicit-it=always"]
    exe = os.path.join(d, "ref")
    so = os.path.join(d, "case.so")
    r = subprocess.run([CC, *flags, "-nostdlib", "-static", "-Wl,-z,norelro", src, f"{ROOT}/tests/isa/start.S", "-o", exe],
                       capture_output=True, text=True)
    if r.returncode:
        return "skip", r.stderr.splitlines()[:3]
    subprocess.check_call([CC, *flags, "-nostdlib", "-shared", "-fPIC", src, "-o", so])
    ref = subprocess.run(["qemu-arm", "-cpu", "cortex-a15", exe], capture_output=True, timeout=20).stdout
    gen = os.path.join(d, "gen")
    subprocess.check_call([sys.executable, "-m", "nova3recomp", so, "-o", gen], stdout=subprocess.DEVNULL,
                          env={**os.environ, "PYTHONPATH": f"{ROOT}/recompiler"})
    hexe = os.path.join(d, "host")
    gens = [os.path.join(gen, f) for f in os.listdir(gen) if f.endswith(".c")]
    subprocess.check_call(["clang", "-O0", "-w", "-fwrapv", "-ffp-contract=off", f"-I{ROOT}/runtime/include", *gens,
                           f"{ROOT}/tests/isa/harness.c", args.rtlib, "-lm", "-lpthread", "-o", hexe])
    res = subprocess.run([hexe, so], capture_output=True, timeout=20)
    if res.returncode or len(res.stdout) != len(ref):
        return "fail", [f"host run failed: rc={res.returncode}", res.stderr.decode()[-400:]]
    diffs = cmp_states(ref, res.stdout)
    if diffs:
        return "fail", diffs
    return "pass", []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=20)
    ap.add_argument("--length", type=int, default=12)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--mode", default="both", choices=["arm", "thumb", "both"])
    ap.add_argument("--kinds", default="int,mem,vfp,neon")
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "isa"))
    ap.add_argument("--reduce", action="store_true", help="shrink failing cases")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    args.rtlib = build_runtime(args.out)
    counts = {"pass": 0, "fail": 0, "skip": 0}
    for k in range(args.n):
        random.seed(args.seed * 100003 + k)
        st, info = run_case(k, args, args.out)
        counts[st] += 1
        if st != "pass":
            print(f"case{k}: {st.upper()}")
            for line in info[:8]:
                print("    " + line)
            if st == "fail" and args.reduce:
                body, state, thumb = run_case.last
                lines = body.split("\n")
                # group "it" lines and helper lines with their instruction
                groups, cur = [], []
                for ln in lines:
                    cur.append(ln)
                    t = ln.strip()
                    if not (t.startswith("it ") or t.startswith("add r11, r12") or t.startswith("and r10, r10")):
                        groups.append(cur); cur = []
                if cur: groups.append(cur)
                i = 0
                while i < len(groups):
                    trial = groups[:i] + groups[i + 1:]
                    st2, _ = run_case(f"{k}r", args, args.out, "\n".join(sum(trial, [])), state, thumb)
                    if st2 == "fail":
                        groups = trial
                    else:
                        i += 1
                st2, info2 = run_case(f"{k}r", args, args.out, "\n".join(sum(groups, [])), state, thumb)
                print(f"    reduced ({'thumb' if thumb else 'arm'}):")
                for g in groups:
                    for ln in g:
                        print("      " + ln.strip())
                for line in info2[:6]:
                    print("      => " + line)
    print(counts)
    return 1 if counts["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())

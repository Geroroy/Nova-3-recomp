"""Translate decoded ARMv7 instructions into C statements.

Every guest function becomes `void f_XXXXXXXX(CPU *c)`. Guest registers live
in the CPU struct; guest memory is accessed through the LD*/ST* helpers of
runtime/include/recomp.h.
"""
from __future__ import annotations

import struct
from collections import Counter

from capstone import arm as A

from .analysis import BRANCH, CALL, ICALL, IJUMP, RET, SEQ, STOP, Function, Insn
from .disasm import ARM, THUMB, reg_kind

COND = {
    A.ARM_CC_EQ: "C_EQ", A.ARM_CC_NE: "C_NE", A.ARM_CC_HS: "C_HS", A.ARM_CC_LO: "C_LO",
    A.ARM_CC_MI: "C_MI", A.ARM_CC_PL: "C_PL", A.ARM_CC_VS: "C_VS", A.ARM_CC_VC: "C_VC",
    A.ARM_CC_HI: "C_HI", A.ARM_CC_LS: "C_LS", A.ARM_CC_GE: "C_GE", A.ARM_CC_LT: "C_LT",
    A.ARM_CC_GT: "C_GT", A.ARM_CC_LE: "C_LE",
}

VD = A  # shorthand for vector data constants
INT_DT = {
    A.ARM_VECTORDATA_I8: (8, "u"), A.ARM_VECTORDATA_I16: (16, "u"),
    A.ARM_VECTORDATA_I32: (32, "u"), A.ARM_VECTORDATA_I64: (64, "u"),
    A.ARM_VECTORDATA_S8: (8, "s"), A.ARM_VECTORDATA_S16: (16, "s"),
    A.ARM_VECTORDATA_S32: (32, "s"), A.ARM_VECTORDATA_S64: (64, "s"),
    A.ARM_VECTORDATA_U8: (8, "u"), A.ARM_VECTORDATA_U16: (16, "u"),
    A.ARM_VECTORDATA_U32: (32, "u"), A.ARM_VECTORDATA_U64: (64, "u"),
    A.ARM_VECTORDATA_P8: (8, "u"),
    A.ARM_VECTORDATA_F32: (32, "f"), A.ARM_VECTORDATA_F64: (64, "f"),
}


LEGACY_NAMES = {"fmdhr": "vmov", "fmdlr": "vmov", "fmrdh": "vmov", "fmrdl": "vmov",
                "fmrs": "vmov", "fmsr": "vmov", "fmrrd": "vmov", "fmdrr": "vmov"}


CC_SUFFIX = {A.ARM_CC_EQ: "eq", A.ARM_CC_NE: "ne", A.ARM_CC_HS: "hs", A.ARM_CC_LO: "lo",
             A.ARM_CC_MI: "mi", A.ARM_CC_PL: "pl", A.ARM_CC_VS: "vs", A.ARM_CC_VC: "vc",
             A.ARM_CC_HI: "hi", A.ARM_CC_LS: "ls", A.ARM_CC_GE: "ge", A.ARM_CC_LT: "lt",
             A.ARM_CC_GT: "gt", A.ARM_CC_LE: "le"}


def sets_flags(i) -> bool:
    """S bit, derived from the UAL mnemonic (capstone's update_flags is unreliable)."""
    m = i.mnemonic.split(".")[0]
    cs = CC_SUFFIX.get(i.cc)
    if cs and m.endswith(cs) and len(m) > 2:
        m = m[:-2]
    base = i.insn_name()
    if m == base:
        return base in ("movs",) and i.update_flags
    return m == base + "s"


class Unsupported(Exception):
    pass


class ImmOp:
    """Synthetic immediate operand (for ARM 'imm, rot' operand pairs)."""
    type = A.ARM_OP_IMM
    subtracted = False
    vector_index = -1

    def __init__(self, v):
        self.imm = v


def norm_ops(i):
    """Operands with capstone's (imm8, rotate) pairs folded into one immediate."""
    ops = list(i.operands)
    if len(ops) >= 2 and ops[-1].type == A.ARM_OP_IMM and ops[-2].type == A.ARM_OP_IMM \
            and i.id in DP_ROT_IDS:
        imm, r = ops[-2].imm & 0xFFFFFFFF, ops[-1].imm & 31
        v = ((imm >> r) | (imm << (32 - r))) & 0xFFFFFFFF if r else imm
        ops = ops[:-2] + [ImmOp(v)]
    return ops


DP_ROT_IDS = {getattr(A, "ARM_INS_" + n) for n in (
    "AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC", "TST", "TEQ", "CMP", "CMN",
    "ORR", "MOV", "BIC", "MVN", "MSR")}


def dtinfo(i, default):
    """(element bits, kind) of a NEON instruction: typed .s16/.f32/... from
    vector_data, untyped .16/.32 (vext, vzip, vrev, vdup, vld1...) from vector_size."""
    if i.vector_data in INT_DT:
        return INT_DT[i.vector_data]
    if i.vector_size:
        return i.vector_size, default[1]
    return default


def ctype(bits: int, kind: str) -> str:
    if kind == "f":
        return "float" if bits == 32 else "double"
    return f"{'int' if kind == 's' else 'uint'}{bits}_t"


def hx(v: int) -> str:
    return f"0x{v & 0xFFFFFFFF:08x}u"


class Lifter:
    def __init__(self, analyzer, base: int, func_names: dict[int, str], module: str = "mod"):
        self.module = module
        self.an = analyzer
        self.img = analyzer.img
        self.base = base
        self.func_names = func_names  # vaddr -> C name, for direct calls
        self.unsupported = Counter()
        self.unsupported_where = {}

    # ------------------------------------------------------------ helpers
    def g(self, vaddr: int) -> int:
        return (vaddr + self.base) & 0xFFFFFFFF

    def label(self, vaddr: int) -> str:
        return f"L_{self.g(vaddr):08x}"

    def rn(self, i, o) -> str:
        return i.reg_name(o.reg)

    def rnum(self, i, o) -> int:
        k, n = reg_kind(i.reg_name(o.reg))
        if k != "r":
            raise Unsupported(f"expected core reg, got {i.reg_name(o.reg)}")
        return n

    def pcval(self, ins: Insn, aligned=False) -> int:
        v = ins.addr + (8 if ins.mode == ARM else 4)
        if aligned:
            v &= ~3
        return self.g(v)

    def reg_read(self, ins, o, aligned_pc=False) -> str:
        n = self.rnum(ins.cs, o)
        if n == 15:
            return hx(self.pcval(ins, aligned_pc))
        return f"c->r[{n}]"

    def is_pc(self, i, o) -> bool:
        return o.type == A.ARM_OP_REG and i.reg_name(o.reg) == "pc"

    def shifted(self, ins, o, carry: bool, pre: list, aligned_pc=False) -> str:
        """Value of a (possibly shifted) register operand or immediate."""
        i = ins.cs
        if o.type == A.ARM_OP_IMM:
            v = o.imm & 0xFFFFFFFF
            if carry and v > 0xFF:
                pre.append(f"sc = {v >> 31};")
            return hx(v)
        if o.type != A.ARM_OP_REG:
            raise Unsupported("operand type")
        x = self.reg_read(ins, o, aligned_pc)
        st, sv = o.shift.type, o.shift.value
        if st == 0:
            return x
        if st in (A.ARM_SFT_LSL_REG, A.ARM_SFT_LSR_REG, A.ARM_SFT_ASR_REG, A.ARM_SFT_ROR_REG):
            amt = f"c->r[{reg_kind(i.reg_name(sv))[1]}]"
            fn = {A.ARM_SFT_LSL_REG: "lsl", A.ARM_SFT_LSR_REG: "lsr",
                  A.ARM_SFT_ASR_REG: "asr", A.ARM_SFT_ROR_REG: "ror"}[st]
            if carry:
                pre.append(f"uint32_t sh = {fn}_c({x}, {amt}, &sc);")
                return "sh"
            return f"{fn}_r({x}, {amt})"
        if st == A.ARM_SFT_RRX or st == A.ARM_SFT_RRX_REG:
            if carry:
                pre.append(f"uint32_t sh = ({x} >> 1) | (c->cf << 31); sc = {x} & 1;")
                return "sh"
            return f"(({x} >> 1) | (c->cf << 31))"
        fn = {A.ARM_SFT_LSL: "lsl", A.ARM_SFT_LSR: "lsr", A.ARM_SFT_ASR: "asr",
              A.ARM_SFT_ROR: "ror"}[st]
        if carry:
            pre.append(f"uint32_t sh = {fn}_c({x}, {sv}, &sc);")
            return "sh"
        if fn == "lsl":
            return f"({x} << {sv})" if sv < 32 else "0u"
        if fn == "lsr":
            return f"({x} >> {sv})" if sv < 32 else "0u"
        if fn == "asr":
            return f"(uint32_t)((int32_t){x} >> {min(sv, 31)})"
        return f"ror32({x}, {sv})"

    # ------------------------------------------------------------ memory
    def mem_ea(self, ins, ops, mi, pre):
        """Compute effective address for memory operand ops[mi].

        Returns (ea_expr, writeback_lines). Handles pre/post indexing."""
        i = ins.cs
        o = ops[mi]
        m = o.mem
        base_name = i.reg_name(m.base)
        if base_name == "pc":
            base = hx(self.pcval(ins, aligned=True))
            bnum = 15
        else:
            bnum = reg_kind(base_name)[1]
            base = f"c->r[{bnum}]"
        # offset
        if m.index:
            idx = f"c->r[{reg_kind(i.reg_name(m.index))[1]}]"
            if o.shift.type == A.ARM_SFT_LSL and o.shift.value:
                idx = f"({idx} << {o.shift.value})"
            elif o.shift.type == A.ARM_SFT_LSR:
                idx = f"lsr_r({idx}, {o.shift.value})"
            elif o.shift.type == A.ARM_SFT_ASR:
                idx = f"asr_r({idx}, {o.shift.value or 32})"
            elif o.shift.type == A.ARM_SFT_ROR:
                idx = f"ror32({idx}, {o.shift.value})"
            elif o.shift.type == A.ARM_SFT_RRX:
                idx = f"(({idx} >> 1) | (c->cf << 31))"
            off = f"- {idx}" if o.subtracted else f"+ {idx}"
        else:
            d = m.disp
            off = f"- {hx(-d)}" if d < 0 else (f"+ {hx(d)}" if d else "")
        post = ops[mi + 1:] if len(ops) > mi + 1 else []
        wb = []
        if post:  # post-indexed
            p = post[0]
            if p.type == A.ARM_OP_IMM:
                pv = p.imm
                if p.subtracted:
                    pv = -pv
                poff = f"- {hx(-pv)}" if pv < 0 else f"+ {hx(pv)}"
            else:
                r = self.shifted(ins, p, False, pre)
                poff = f"- {r}" if p.subtracted else f"+ {r}"
            pre.append(f"uint32_t ea = {base};")
            wb.append(f"c->r[{bnum}] = ea {poff};")
        else:
            pre.append(f"uint32_t ea = {base} {off};")
            if i.writeback:
                wb.append(f"c->r[{bnum}] = ea;")
        return "ea", wb, bnum

    # ------------------------------------------------------------ main
    def lift_insn(self, fn: Function, ins: Insn) -> list[str]:
        i = ins.cs
        if i is None:
            return [f'rt_unimplemented(c, {hx(self.g(ins.addr))}, "undecodable"); return;']
        try:
            body = self._lift(fn, ins)
        except Unsupported as e:
            key = f"{i.insn_name()}"
            self.unsupported[key] += 1
            self.unsupported_where.setdefault(key, f"{self.g(ins.addr):08x}: {i.mnemonic} {i.op_str} ({e})")
            text = f"{i.mnemonic} {i.op_str}".replace('"', "'")
            body = [f'rt_unimplemented(c, {hx(self.g(ins.addr))}, "{text}"); return;']
        if ins.cond and i.id not in (A.ARM_INS_CBZ, A.ARM_INS_CBNZ) and i.cc in COND:
            return [f"if ({COND[i.cc]}) {{"] + ["    " + b for b in body] + ["}"]
        return body

    def call_direct(self, ins: Insn, target: int, mode: str) -> str:
        name = self.func_names.get(target)
        if name:
            return f"{name}(c);"
        return f"call_addr(c, {hx(self.g(target) | (1 if mode == THUMB else 0))});"

    def import_call(self, imp) -> str:
        if isinstance(imp, tuple):
            return f"call_addr(c, LD32({hx(self.g(imp[1]))}));"
        return f"{self.module}_import_fns[{imp.id}](c); /* {imp.name} */"

    def ret_addr(self, ins: Insn) -> str:
        return hx(self.g(ins.next) | (1 if ins.mode == THUMB else 0))

    def jump_dispatch(self, fn: Function, ins: Insn, texpr: str) -> list[str]:
        """Indirect jump to the guest address in texpr."""
        out = [f"uint32_t jt = {texpr};"]
        targets = [t for t, _ in ins.targets] if ins.targets else sorted(getattr(self, "_cur_labels", fn.labels))
        out.append("switch (jt & ~1u) {")
        for t in sorted(set(targets)):
            out.append(f"case {hx(self.g(t))}: goto {self.label(t)};")
        out.append("default: call_addr(c, jt); return;")
        out.append("}")
        return out

    def _lift(self, fn: Function, ins: Insn) -> list[str]:
        i = ins.cs
        iid = i.id
        ops = i.operands
        name = i.insn_name()
        k = ins.kind

        # ------------------------------------------------ control flow
        if ins.const_target is not None and k in (BRANCH, CALL):
            pre = []
            if k == CALL:
                pre.append(f"c->r[14] = {self.ret_addr(ins)};")
            callexpr = self.import_call(ins.plt_import) if ins.plt_import is not None else \
                self.call_direct(ins, ins.target, ins.target_mode)
            return pre + [callexpr] + (["return;"] if k == BRANCH else [])
        if iid in (A.ARM_INS_B, A.ARM_INS_BL, A.ARM_INS_BLX) and ops and ops[0].type == A.ARM_OP_IMM:
            if k == CALL:
                pre = [f"c->r[14] = {self.ret_addr(ins)};"]
                if ins.plt_import is not None:
                    return pre + [self.import_call(ins.plt_import)]
                return pre + [self.call_direct(ins, ins.target, ins.target_mode)]
            if ins.tailcall:
                if ins.plt_import is not None:
                    return [self.import_call(ins.plt_import), "return;"]
                return [self.call_direct(ins, ins.target, ins.target_mode), "return;"]
            if ins.target not in fn.insns:
                return [f"rt_bad_jump(c, {hx(self.g(ins.addr))}, {hx(self.g(ins.target))}); return;"]
            return [f"goto {self.label(ins.target)};"]
        if iid in (A.ARM_INS_CBZ, A.ARM_INS_CBNZ):
            r = self.rnum(i, ops[0])
            op = "==" if iid == A.ARM_INS_CBZ else "!="
            if ins.tailcall:
                return [f"if (c->r[{r}] {op} 0) {{ {self.call_direct(ins, ins.target, ins.mode)} return; }}"]
            return [f"if (c->r[{r}] {op} 0) goto {self.label(ins.target)};"]
        if iid == A.ARM_INS_BX:
            if k == RET:
                return ["return;"]
            if k == BRANCH:
                return [f"goto {self.label(ins.target)};"]
            return self.jump_dispatch(fn, ins, self.reg_read(ins, ops[0]))
        if iid == A.ARM_INS_BLX:
            return [f"uint32_t t = {self.reg_read(ins, ops[0])};",
                    f"c->r[14] = {self.ret_addr(ins)};", "call_addr(c, t);"]
        if iid in (A.ARM_INS_TBB, A.ARM_INS_TBH):
            m = ops[0].mem
            idx = f"c->r[{reg_kind(i.reg_name(m.index))[1]}]"
            base = self.pcval(ins)
            if iid == A.ARM_INS_TBB:
                t = f"{hx(base)} + 2u * LD8({hx(base)} + {idx})"
            else:
                t = f"{hx(base)} + 2u * LD16({hx(base)} + ({idx} << 1))"
            return self.jump_dispatch(fn, ins, t)
        if iid == A.ARM_INS_IT:
            return []
        if iid in (A.ARM_INS_NOP, A.ARM_INS_HINT, A.ARM_INS_YIELD, A.ARM_INS_WFE,
                   A.ARM_INS_WFI, A.ARM_INS_SEV, A.ARM_INS_PLD, A.ARM_INS_PLDW, A.ARM_INS_PLI):
            return []
        if iid in (A.ARM_INS_DMB, A.ARM_INS_DSB, A.ARM_INS_ISB):
            return ["__atomic_thread_fence(__ATOMIC_SEQ_CST);"]
        if iid in (A.ARM_INS_UDF, A.ARM_INS_BKPT, A.ARM_INS_TRAP):
            return [f'rt_unimplemented(c, {hx(self.g(ins.addr))}, "trap {name}"); return;']
        if iid == A.ARM_INS_SVC:
            return [f"rt_svc(c, {hx(self.g(ins.addr))}, {ops[0].imm & 0xFFFFFF});"]

        name = LEGACY_NAMES.get(name, name)
        h = getattr(self, "op_" + name, None)
        if h is None:
            if name.startswith("v"):
                return self.neon_or_vfp(fn, ins)
            raise Unsupported("no handler")
        return h(fn, ins)

    # ======================================================= data processing
    def _dp_operands(self, ins):
        i = ins.cs
        ops = norm_ops(i)
        if len(ops) == 2:
            return ops[0], ops[0], ops[1]
        return ops[0], ops[1], ops[2]

    def _write_dest(self, fn, ins, d, value: str, pre: list) -> list[str]:
        i = ins.cs
        n = self.rnum(i, d)
        if n == 15:
            if ins.kind == RET:
                return pre + ["return;"]
            return pre + self.jump_dispatch(fn, ins, value)
        return pre + [f"c->r[{n}] = {value};"]

    def _logical(self, fn, ins, expr_fmt):
        i = ins.cs
        d, a, b = self._dp_operands(ins)
        pre = []
        S = sets_flags(i)
        if S:
            pre.append("uint32_t sc = c->cf;")
        aligned = ins.mode == THUMB and b.type == A.ARM_OP_IMM
        av = self.shifted(ins, a, False, pre, aligned)
        bv = self.shifted(ins, b, S, pre)
        res = expr_fmt.format(a=av, b=bv)
        if S:
            pre.append(f"uint32_t res = {res};")
            pre.append("nz_flags(c, res); c->cf = sc;")
            return self._write_dest(fn, ins, d, "res", pre)
        return self._write_dest(fn, ins, d, res, pre)

    def op_and(self, fn, ins): return self._logical(fn, ins, "{a} & {b}")
    def op_eor(self, fn, ins): return self._logical(fn, ins, "{a} ^ {b}")
    def op_orr(self, fn, ins): return self._logical(fn, ins, "{a} | {b}")
    def op_orn(self, fn, ins): return self._logical(fn, ins, "{a} | ~{b}")
    def op_bic(self, fn, ins): return self._logical(fn, ins, "{a} & ~{b}")

    def _move(self, fn, ins, neg):
        i = ins.cs
        ops = norm_ops(i)
        d, b = ops[0], ops[1]
        pre = []
        S = sets_flags(i)
        if S:
            pre.append("uint32_t sc = c->cf;")
        bv = self.shifted(ins, b, S, pre)
        res = f"~{bv}" if neg else bv
        if S:
            pre.append(f"uint32_t res = {res};")
            pre.append("nz_flags(c, res); c->cf = sc;")
            return self._write_dest(fn, ins, d, "res", pre)
        return self._write_dest(fn, ins, d, res, pre)

    def op_mov(self, fn, ins):
        ops = ins.cs.operands
        if len(ops) == 2 and ops[1].type == A.ARM_OP_REG and ops[1].shift.type == 0 and \
                self.is_pc(ins.cs, ops[0]) and ins.kind == RET:
            return ["return;"]
        return self._move(fn, ins, False)

    def op_movs(self, fn, ins): return self._move(fn, ins, False)
    def op_mvn(self, fn, ins): return self._move(fn, ins, True)

    def op_movw(self, fn, ins):
        ops = ins.cs.operands
        return [f"c->r[{self.rnum(ins.cs, ops[0])}] = {hx(ops[1].imm & 0xFFFF)};"]

    def op_movt(self, fn, ins):
        ops = ins.cs.operands
        r = self.rnum(ins.cs, ops[0])
        return [f"c->r[{r}] = (c->r[{r}] & 0xffffu) | {hx((ops[1].imm & 0xFFFF) << 16)};"]

    def _arith(self, fn, ins, kind):
        i = ins.cs
        d, a, b = self._dp_operands(ins)
        pre = []
        aligned = ins.mode == THUMB and b.type == A.ARM_OP_IMM
        av = self.shifted(ins, a, False, pre, aligned)
        bv = self.shifted(ins, b, False, pre)
        S = sets_flags(i)
        if S:
            f = {"add": f"add_flags(c, {av}, {bv}, 0)",
                 "adc": f"add_flags(c, {av}, {bv}, c->cf)",
                 "sub": f"sub_flags(c, {av}, {bv}, 1)",
                 "sbc": f"sub_flags(c, {av}, {bv}, c->cf)",
                 "rsb": f"sub_flags(c, {bv}, {av}, 1)",
                 "rsc": f"sub_flags(c, {bv}, {av}, c->cf)"}[kind]
            if self.rnum(i, d) == 15:
                raise Unsupported("flag-setting write to pc")
            pre.append(f"uint32_t res = {f};")
            return self._write_dest(fn, ins, d, "res", pre)
        e = {"add": f"{av} + {bv}", "adc": f"{av} + {bv} + c->cf",
             "sub": f"{av} - {bv}", "sbc": f"{av} - {bv} - (c->cf ^ 1)",
             "rsb": f"{bv} - {av}", "rsc": f"{bv} - {av} - (c->cf ^ 1)"}[kind]
        return self._write_dest(fn, ins, d, e, pre)

    def op_add(self, fn, ins): return self._arith(fn, ins, "add")
    def op_addw(self, fn, ins): return self._arith(fn, ins, "add")
    def op_adc(self, fn, ins): return self._arith(fn, ins, "adc")
    def op_sub(self, fn, ins): return self._arith(fn, ins, "sub")
    def op_subw(self, fn, ins): return self._arith(fn, ins, "sub")
    def op_sbc(self, fn, ins): return self._arith(fn, ins, "sbc")
    def op_rsb(self, fn, ins): return self._arith(fn, ins, "rsb")
    def op_rsc(self, fn, ins): return self._arith(fn, ins, "rsc")

    def op_adr(self, fn, ins):
        ops = ins.cs.operands
        return [f"c->r[{self.rnum(ins.cs, ops[0])}] = {hx(self.pcval(ins, True) + ops[1].imm)};"]

    def _compare(self, fn, ins, kind):
        i = ins.cs
        a, b = norm_ops(i)[:2]
        pre = []
        if kind in ("tst", "teq"):
            pre.append("uint32_t sc = c->cf;")
            av = self.shifted(ins, a, False, pre)
            bv = self.shifted(ins, b, True, pre)
            op = "&" if kind == "tst" else "^"
            return pre + [f"nz_flags(c, {av} {op} {bv}); c->cf = sc;"]
        av = self.shifted(ins, a, False, pre)
        bv = self.shifted(ins, b, False, pre)
        if kind == "cmp":
            return pre + [f"sub_flags(c, {av}, {bv}, 1);"]
        return pre + [f"add_flags(c, {av}, {bv}, 0);"]

    def op_cmp(self, fn, ins): return self._compare(fn, ins, "cmp")
    def op_cmn(self, fn, ins): return self._compare(fn, ins, "cmn")
    def op_tst(self, fn, ins): return self._compare(fn, ins, "tst")
    def op_teq(self, fn, ins): return self._compare(fn, ins, "teq")

    def _shift_insn(self, fn, ins, kind):
        i = ins.cs
        ops = i.operands
        d = ops[0]
        if len(ops) == 2 and ops[1].type == A.ARM_OP_REG and ops[1].shift.type != 0:
            # ARM-mode alias "lsr rd, rm, #n" == "mov rd, rm, lsr #n"
            return self._move(fn, ins, False)
        if kind == "rrx":
            src, amt = ops[1] if len(ops) > 1 else ops[0], None
        elif len(ops) == 2:
            src, amt = ops[0], ops[1]
        else:
            src, amt = ops[1], ops[2]
        x = self.reg_read(ins, src)
        S = sets_flags(i)
        pre = []
        if kind == "rrx":
            if S:
                pre += [f"uint32_t x = {x};", "uint32_t res = (x >> 1) | (c->cf << 31);",
                        "c->cf = x & 1; nz_flags(c, res);"]
                return self._write_dest(fn, ins, d, "res", pre)
            return self._write_dest(fn, ins, d, f"(({x} >> 1) | (c->cf << 31))", pre)
        if amt.type == A.ARM_OP_IMM:
            n = str(amt.imm)
            if kind in ("lsr", "asr") and amt.imm == 0:
                n = "32"
        else:
            n = f"c->r[{self.rnum(i, amt)}]"
        if S:
            pre += ["uint32_t sc = c->cf;", f"uint32_t res = {kind}_c({x}, {n}, &sc);",
                    "nz_flags(c, res); c->cf = sc;"]
            return self._write_dest(fn, ins, d, "res", pre)
        return self._write_dest(fn, ins, d, f"{kind}_r({x}, {n})", pre)

    def op_lsl(self, fn, ins): return self._shift_insn(fn, ins, "lsl")
    def op_lsr(self, fn, ins): return self._shift_insn(fn, ins, "lsr")
    def op_asr(self, fn, ins): return self._shift_insn(fn, ins, "asr")
    def op_ror(self, fn, ins): return self._shift_insn(fn, ins, "ror")
    def op_rrx(self, fn, ins): return self._shift_insn(fn, ins, "rrx")

    # ============================================================ multiply
    def _r(self, ins, o):
        return self.reg_read(ins, o)

    def op_mul(self, fn, ins):
        i = ins.cs
        ops = i.operands
        if len(ops) == 2:
            d, a, b = ops[0], ops[0], ops[1]
        else:
            d, a, b = ops
        out = [f"uint32_t res = {self._r(ins, a)} * {self._r(ins, b)};"]
        if sets_flags(i):
            out.append("nz_flags(c, res);")
        return out + [f"c->r[{self.rnum(i, d)}] = res;"]

    def op_mla(self, fn, ins):
        i = ins.cs
        d, a, b, acc = i.operands
        out = [f"uint32_t res = {self._r(ins, a)} * {self._r(ins, b)} + {self._r(ins, acc)};"]
        if sets_flags(i):
            out.append("nz_flags(c, res);")
        return out + [f"c->r[{self.rnum(i, d)}] = res;"]

    def op_mls(self, fn, ins):
        i = ins.cs
        d, a, b, acc = i.operands
        return [f"c->r[{self.rnum(i, d)}] = {self._r(ins, acc)} - {self._r(ins, a)} * {self._r(ins, b)};"]

    def _long_mul(self, fn, ins, signed, acc):
        i = ins.cs
        lo, hi, a, b = i.operands
        L, H = self.rnum(i, lo), self.rnum(i, hi)
        if signed:
            e = f"(uint64_t)((int64_t)(int32_t){self._r(ins, a)} * (int64_t)(int32_t){self._r(ins, b)})"
        else:
            e = f"(uint64_t){self._r(ins, a)} * (uint64_t){self._r(ins, b)}"
        out = [f"uint64_t res = {e};"]
        if acc:
            out.append(f"res += ((uint64_t)c->r[{H}] << 32) | c->r[{L}];")
        out += [f"c->r[{L}] = (uint32_t)res;", f"c->r[{H}] = (uint32_t)(res >> 32);"]
        if sets_flags(i):
            out.append("c->n = (uint32_t)(res >> 63); c->z = (res == 0);")
        return out

    def op_umull(self, fn, ins): return self._long_mul(fn, ins, False, False)
    def op_smull(self, fn, ins): return self._long_mul(fn, ins, True, False)
    def op_umlal(self, fn, ins): return self._long_mul(fn, ins, False, True)
    def op_smlal(self, fn, ins): return self._long_mul(fn, ins, True, True)

    def op_umaal(self, fn, ins):
        i = ins.cs
        lo, hi, a, b = i.operands
        L, H = self.rnum(i, lo), self.rnum(i, hi)
        return [f"uint64_t res = (uint64_t){self._r(ins, a)} * {self._r(ins, b)} + c->r[{L}] + c->r[{H}];",
                f"c->r[{L}] = (uint32_t)res;", f"c->r[{H}] = (uint32_t)(res >> 32);"]

    def _half(self, ins, o, top):
        return f"(int32_t)(int16_t)({self._r(ins, o)} >> 16)" if top else f"(int32_t)(int16_t){self._r(ins, o)}"

    def _smulxy(self, fn, ins, x, y, acc):
        i = ins.cs
        ops = i.operands
        e = f"{self._half(ins, ops[1], x == 't')} * {self._half(ins, ops[2], y == 't')}"
        if acc:
            return [f"int64_t res = (int64_t)({e}) + (int32_t){self._r(ins, ops[3])};",
                    "if (res != (int32_t)res) c->q = 1;",
                    f"c->r[{self.rnum(i, ops[0])}] = (uint32_t)res;"]
        return [f"c->r[{self.rnum(i, ops[0])}] = (uint32_t)({e});"]

    def __getattr__(self, item):
        # smulbb/smulbt/... and smlabb/... families
        if item.startswith("op_smul") and len(item) == 9 and item[7] in "bt" and item[8] in "bt":
            return lambda fn, ins: self._smulxy(fn, ins, item[7], item[8], False)
        if item.startswith("op_smla") and len(item) == 9 and item[7] in "bt" and item[8] in "bt":
            return lambda fn, ins: self._smulxy(fn, ins, item[7], item[8], True)
        if item in ("op_smulwb", "op_smulwt", "op_smlawb", "op_smlawt"):
            top = item[-1] == "t"
            acc = item.startswith("op_smla")

            def f(fn, ins):
                i = ins.cs
                ops = i.operands
                e = f"(int32_t)(((int64_t)(int32_t){self._r(ins, ops[1])} * {self._half(ins, ops[2], top)}) >> 16)"
                if acc:
                    e = f"(uint32_t)({e} + (int32_t){self._r(ins, ops[3])})"
                return [f"c->r[{self.rnum(i, ops[0])}] = (uint32_t){e};"]
            return f
        raise AttributeError(item)

    def _smm(self, fn, ins, acc, sub, rnd):
        i = ins.cs
        ops = i.operands
        prod = f"(int64_t)(int32_t){self._r(ins, ops[1])} * (int32_t){self._r(ins, ops[2])}"
        if acc:
            a = f"((int64_t)(int32_t){self._r(ins, ops[3])} << 32)"
            prod = f"({a} - {prod})" if sub else f"({a} + {prod})"
        r = " + 0x80000000ll" if rnd else ""
        return [f"c->r[{self.rnum(i, ops[0])}] = (uint32_t)((uint64_t)({prod}{r}) >> 32);"]

    def op_smmul(self, fn, ins): return self._smm(fn, ins, False, False, False)
    def op_smmulr(self, fn, ins): return self._smm(fn, ins, False, False, True)
    def op_smmla(self, fn, ins): return self._smm(fn, ins, True, False, False)
    def op_smmlar(self, fn, ins): return self._smm(fn, ins, True, False, True)
    def op_smmls(self, fn, ins): return self._smm(fn, ins, True, True, False)
    def op_smmlsr(self, fn, ins): return self._smm(fn, ins, True, True, True)

    def op_smlalbb(self, fn, ins):
        i = ins.cs
        lo, hi, a, b = i.operands
        L, H = self.rnum(i, lo), self.rnum(i, hi)
        return [f"int64_t res = (int64_t)(((uint64_t)c->r[{H}] << 32) | c->r[{L}]) + "
                f"(int64_t)({self._half(ins, a, False)} * {self._half(ins, b, False)});",
                f"c->r[{L}] = (uint32_t)res; c->r[{H}] = (uint32_t)((uint64_t)res >> 32);"]

    def op_sdiv(self, fn, ins):
        i = ins.cs
        d, a, b = self._dp_operands(ins)
        return [f"c->r[{self.rnum(i, d)}] = sdiv32((int32_t){self._r(ins, a)}, (int32_t){self._r(ins, b)});"]

    def op_udiv(self, fn, ins):
        i = ins.cs
        d, a, b = self._dp_operands(ins)
        return [f"c->r[{self.rnum(i, d)}] = udiv32({self._r(ins, a)}, {self._r(ins, b)});"]

    # ================================================== saturating arithmetic
    def _qop(self, fn, ins, expr):
        i = ins.cs
        d, a, b = i.operands
        return [f"int64_t x = (int32_t){self._r(ins, a)}, y = (int32_t){self._r(ins, b)};",
                f"c->r[{self.rnum(i, d)}] = ssat32(c, {expr}, 32);"]

    def op_qadd(self, fn, ins): return self._qop(fn, ins, "x + y")
    def op_qsub(self, fn, ins): return self._qop(fn, ins, "x - y")
    def op_qdadd(self, fn, ins): return self._qop(fn, ins, "x + (int32_t)ssat32(c, 2 * y, 32)")
    def op_qdsub(self, fn, ins): return self._qop(fn, ins, "x - (int32_t)ssat32(c, 2 * y, 32)")

    def _sat(self, fn, ins, signed):
        i = ins.cs
        ops = i.operands
        d, bits, src = ops[0], ops[1].imm, ops[2]
        pre = []
        v = self.shifted(ins, src, False, pre)
        if signed:
            return pre + [f"c->r[{self.rnum(i, d)}] = ssat32(c, (int32_t){v}, {bits});"]
        return pre + [f"c->r[{self.rnum(i, d)}] = usat32(c, (int32_t){v}, {bits});"]

    def op_ssat(self, fn, ins): return self._sat(fn, ins, True)
    def op_usat(self, fn, ins): return self._sat(fn, ins, False)

    # ===================================================== bit manipulation
    def _unary(self, fn, ins, fmt):
        i = ins.cs
        d, s = i.operands[0], i.operands[1]
        return [f"c->r[{self.rnum(i, d)}] = {fmt.format(x=self._r(ins, s))};"]

    def op_clz(self, fn, ins): return self._unary(fn, ins, "clz32({x})")
    def op_rbit(self, fn, ins): return self._unary(fn, ins, "rbit32({x})")
    def op_rev(self, fn, ins): return self._unary(fn, ins, "__builtin_bswap32({x})")
    def op_rev16(self, fn, ins):
        return self._unary(fn, ins, "((({x}) & 0xff00ff00u) >> 8) | ((({x}) & 0x00ff00ffu) << 8)")
    def op_revsh(self, fn, ins):
        return self._unary(fn, ins, "(uint32_t)(int32_t)(int16_t)__builtin_bswap16((uint16_t)({x}))")

    def _extend(self, fn, ins, bits, signed, acc):
        i = ins.cs
        ops = list(i.operands)
        rot = 0
        if ops and ops[-1].type == A.ARM_OP_IMM:
            rot = ops.pop().imm
        src = ops[-1]
        if src.shift.type == A.ARM_SFT_ROR:
            rot = src.shift.value
        x = f"c->r[{self.rnum(i, src)}]"
        if rot:
            x = f"ror32({x}, {rot})"
        t = f"{'int' if signed else 'uint'}{bits}_t"
        e = f"(uint32_t)(int32_t)({t}){x}" if signed else f"(uint32_t)({t}){x}"
        if acc:
            e = f"{self._r(ins, ops[1])} + {e}"
        return [f"c->r[{self.rnum(i, ops[0])}] = {e};"]

    def op_sxtb(self, fn, ins): return self._extend(fn, ins, 8, True, False)
    def op_sxth(self, fn, ins): return self._extend(fn, ins, 16, True, False)
    def op_uxtb(self, fn, ins): return self._extend(fn, ins, 8, False, False)
    def op_uxth(self, fn, ins): return self._extend(fn, ins, 16, False, False)
    def op_sxtab(self, fn, ins): return self._extend(fn, ins, 8, True, True)
    def op_sxtah(self, fn, ins): return self._extend(fn, ins, 16, True, True)
    def op_uxtab(self, fn, ins): return self._extend(fn, ins, 8, False, True)
    def op_uxtah(self, fn, ins): return self._extend(fn, ins, 16, False, True)

    def op_uxtb16(self, fn, ins):
        i = ins.cs
        ops = list(i.operands)
        rot = ops.pop().imm if ops[-1].type == A.ARM_OP_IMM else 0
        x = f"ror32(c->r[{self.rnum(i, ops[-1])}], {rot})"
        return [f"c->r[{self.rnum(i, ops[0])}] = {x} & 0x00ff00ffu;"]

    def op_ubfx(self, fn, ins):
        i = ins.cs
        d, s, lsb, w = i.operands
        mask = (1 << w.imm) - 1
        return [f"c->r[{self.rnum(i, d)}] = ({self._r(ins, s)} >> {lsb.imm}) & {hx(mask)};"]

    def op_sbfx(self, fn, ins):
        i = ins.cs
        d, s, lsb, w = i.operands
        sh = 32 - lsb.imm - w.imm
        return [f"c->r[{self.rnum(i, d)}] = (uint32_t)((int32_t)({self._r(ins, s)} << {sh}) >> {32 - w.imm});"]

    def op_bfi(self, fn, ins):
        i = ins.cs
        d, s, lsb, w = i.operands
        mask = ((1 << w.imm) - 1) << lsb.imm
        r = self.rnum(i, d)
        return [f"c->r[{r}] = (c->r[{r}] & {hx(~mask)}) | (({self._r(ins, s)} << {lsb.imm}) & {hx(mask)});"]

    def op_bfc(self, fn, ins):
        i = ins.cs
        d, lsb, w = i.operands
        mask = ((1 << w.imm) - 1) << lsb.imm
        r = self.rnum(i, d)
        return [f"c->r[{r}] &= {hx(~mask)};"]

    def op_pkhbt(self, fn, ins):
        i = ins.cs
        ops = i.operands
        pre = []
        b = self.shifted(ins, ops[2], False, pre)
        return pre + [f"c->r[{self.rnum(i, ops[0])}] = ({self._r(ins, ops[1])} & 0xffffu) | ({b} & 0xffff0000u);"]

    def op_pkhtb(self, fn, ins):
        i = ins.cs
        ops = i.operands
        pre = []
        b = self.shifted(ins, ops[2], False, pre)
        return pre + [f"c->r[{self.rnum(i, ops[0])}] = ({self._r(ins, ops[1])} & 0xffff0000u) | ({b} & 0xffffu);"]

    # ========================================================== status regs
    def op_mrs(self, fn, ins):
        i = ins.cs
        return [f"c->r[{self.rnum(i, i.operands[0])}] = (c->n << 31) | (c->z << 30) | (c->cf << 29) | "
                f"(c->v << 28) | (c->q << 27) | (c->ge << 16) | 0x10u;"]

    def op_msr(self, fn, ins):
        i = ins.cs
        src = norm_ops(i)[-1]
        pre = []
        v = self.shifted(ins, src, False, pre)
        return pre + [f"uint32_t x = {v};",
                      "c->n = x >> 31; c->z = (x >> 30) & 1; c->cf = (x >> 29) & 1; "
                      "c->v = (x >> 28) & 1; c->q = (x >> 27) & 1; c->ge = (x >> 16) & 15;"]

    def _cop(self, ins, is_read):
        i = ins.cs
        ops = i.operands
        # mrc p15, #opc1, rt, cN, cM, #opc2
        cp, opc1, rt, crn, crm = ops[0].imm, ops[1].imm, ops[2], ops[3].imm, ops[4].imm
        opc2 = ops[5].imm if len(ops) > 5 else 0
        r = self.rnum(i, rt)
        if is_read and cp == 15 and opc1 == 0 and crn == 13 and crm == 0 and opc2 == 3:
            return [f"c->r[{r}] = c->tls;"]
        return [f"rt_mcr_mrc(c, {hx(self.g(ins.addr))}, {int(is_read)}, {cp}, {opc1}, {crn}, {crm}, {opc2}, &c->r[{r}]);"]

    def op_mrc(self, fn, ins): return self._cop(ins, True)
    def op_mcr(self, fn, ins): return self._cop(ins, False)

    # ========================================================= loads/stores
    def _ldst(self, fn, ins, size, signed, store):
        i = ins.cs
        ops = i.operands
        rt = ops[0]
        pre = []
        ea, wb, bnum = self.mem_ea(ins, ops, 1, pre)
        r = self.rnum(i, rt)
        if store:
            v = self.reg_read(ins, rt)
            fnn = {1: "ST8", 2: "ST16", 4: "ST32"}[size]
            return pre + [f"{fnn}({ea}, {v});"] + wb
        ld = {1: "LD8", 2: "LD16", 4: "LD32"}[size]
        val = f"{ld}({ea})"
        if signed:
            val = f"(uint32_t)(int32_t)(int{size * 8}_t){val}"
        if r == 15:
            out = pre + [f"uint32_t t = {val};"] + wb
            if ins.kind == RET:
                return out + ["return;"]
            return out + self.jump_dispatch(fn, ins, "t")
        if r == bnum and wb:
            return pre + [f"uint32_t t = {val};"] + wb + [f"c->r[{r}] = t;"]
        return pre + [f"c->r[{r}] = {val};"] + wb

    def op_ldr(self, fn, ins): return self._ldst(fn, ins, 4, False, False)
    def op_ldrt(self, fn, ins): return self._ldst(fn, ins, 4, False, False)
    def op_ldrb(self, fn, ins): return self._ldst(fn, ins, 1, False, False)
    def op_ldrbt(self, fn, ins): return self._ldst(fn, ins, 1, False, False)
    def op_ldrh(self, fn, ins): return self._ldst(fn, ins, 2, False, False)
    def op_ldrht(self, fn, ins): return self._ldst(fn, ins, 2, False, False)
    def op_ldrsb(self, fn, ins): return self._ldst(fn, ins, 1, True, False)
    def op_ldrsbt(self, fn, ins): return self._ldst(fn, ins, 1, True, False)
    def op_ldrsh(self, fn, ins): return self._ldst(fn, ins, 2, True, False)
    def op_ldrsht(self, fn, ins): return self._ldst(fn, ins, 2, True, False)
    def op_str(self, fn, ins): return self._ldst(fn, ins, 4, False, True)
    def op_strt(self, fn, ins): return self._ldst(fn, ins, 4, False, True)
    def op_strb(self, fn, ins): return self._ldst(fn, ins, 1, False, True)
    def op_strbt(self, fn, ins): return self._ldst(fn, ins, 1, False, True)
    def op_strh(self, fn, ins): return self._ldst(fn, ins, 2, False, True)
    def op_strht(self, fn, ins): return self._ldst(fn, ins, 2, False, True)

    def op_ldrd(self, fn, ins):
        i = ins.cs
        ops = i.operands
        a, b = self.rnum(i, ops[0]), self.rnum(i, ops[1])
        pre = []
        ea, wb, _ = self.mem_ea(ins, ops, 2, pre)
        return pre + [f"uint32_t t0 = LD32({ea}), t1 = LD32({ea} + 4);"] + wb + \
            [f"c->r[{a}] = t0; c->r[{b}] = t1;"]

    def op_strd(self, fn, ins):
        i = ins.cs
        ops = i.operands
        pre = []
        ea, wb, _ = self.mem_ea(ins, ops, 2, pre)
        return pre + [f"ST32({ea}, {self.reg_read(ins, ops[0])}); ST32({ea} + 4, {self.reg_read(ins, ops[1])});"] + wb

    def _ldrex(self, fn, ins, sz):
        i = ins.cs
        ops = i.operands
        if sz == 8:
            a, b = self.rnum(i, ops[0]), self.rnum(i, ops[1])
            return [f"uint64_t t = ldrex64(c, c->r[{reg_kind(i.reg_name(ops[2].mem.base))[1]}]);",
                    f"c->r[{a}] = (uint32_t)t; c->r[{b}] = (uint32_t)(t >> 32);"]
        base = f"c->r[{reg_kind(i.reg_name(ops[1].mem.base))[1]}] + {hx(ops[1].mem.disp)}"
        fnn = {1: "ldrex8", 2: "ldrex16", 4: "ldrex32"}[sz]
        return [f"c->r[{self.rnum(i, ops[0])}] = {fnn}(c, {base});"]

    def _strex(self, fn, ins, sz):
        i = ins.cs
        ops = i.operands
        st = self.rnum(i, ops[0])
        if sz == 8:
            a, b = self.rnum(i, ops[1]), self.rnum(i, ops[2])
            base = f"c->r[{reg_kind(i.reg_name(ops[3].mem.base))[1]}]"
            return [f"c->r[{st}] = strex64(c, {base}, ((uint64_t)c->r[{b}] << 32) | c->r[{a}]);"]
        base = f"c->r[{reg_kind(i.reg_name(ops[2].mem.base))[1]}] + {hx(ops[2].mem.disp)}"
        fnn = {1: "strex8", 2: "strex16", 4: "strex32"}[sz]
        return [f"c->r[{st}] = {fnn}(c, {base}, c->r[{self.rnum(i, ops[1])}]);"]

    def op_ldrex(self, fn, ins): return self._ldrex(fn, ins, 4)
    def op_ldrexb(self, fn, ins): return self._ldrex(fn, ins, 1)
    def op_ldrexh(self, fn, ins): return self._ldrex(fn, ins, 2)
    def op_ldrexd(self, fn, ins): return self._ldrex(fn, ins, 8)
    def op_strex(self, fn, ins): return self._strex(fn, ins, 4)
    def op_strexb(self, fn, ins): return self._strex(fn, ins, 1)
    def op_strexh(self, fn, ins): return self._strex(fn, ins, 2)
    def op_strexd(self, fn, ins): return self._strex(fn, ins, 8)
    def op_clrex(self, fn, ins): return ["c->excl_valid = 0;"]

    def op_swp(self, fn, ins):
        i = ins.cs
        ops = i.operands
        base = f"c->r[{reg_kind(i.reg_name(ops[2].mem.base))[1]}]"
        return [f"uint32_t t = __atomic_exchange_n((uint32_t *)G2H({base}), c->r[{self.rnum(i, ops[1])}], __ATOMIC_SEQ_CST);",
                f"c->r[{self.rnum(i, ops[0])}] = t;"]

    def _ldm_stm(self, fn, ins, base_reg, regs, mode, load, wb):
        """mode: ia, ib, da, db"""
        n = len(regs)
        out = [f"uint32_t base = c->r[{base_reg}];"]
        start = {"ia": "base", "ib": "base + 4", "da": f"base - {4 * n - 4}", "db": f"base - {4 * n}"}[mode]
        out.append(f"uint32_t ea = {start};")
        newbase = f"base + {4 * n}" if mode in ("ia", "ib") else f"base - {4 * n}"
        has_pc = False
        lines = []
        for k, r in enumerate(sorted(regs)):
            if load:
                if r == 15:
                    has_pc = True
                    lines.append(f"uint32_t newpc = LD32(ea + {4 * k});")
                else:
                    lines.append(f"c->r[{r}] = LD32(ea + {4 * k});")
            else:
                v = hx(self.pcval(ins)) if r == 15 else f"c->r[{r}]"
                if r == base_reg and k:
                    v = "base"
                lines.append(f"ST32(ea + {4 * k}, {v});")
        out += lines
        if wb and not (load and base_reg in regs):
            out.append(f"c->r[{base_reg}] = {newbase};")
        if has_pc:
            if ins.kind == RET:
                out.append("return;")
            else:
                out += self.jump_dispatch(fn, ins, "newpc")
        return out

    def _ldm_generic(self, fn, ins, mode, load):
        i = ins.cs
        ops = i.operands
        base = self.rnum(i, ops[0])
        regs = [self.rnum(i, o) for o in ops[1:]]
        return self._ldm_stm(fn, ins, base, regs, mode, load, i.writeback)

    def op_ldm(self, fn, ins): return self._ldm_generic(fn, ins, "ia", True)
    def op_ldmib(self, fn, ins): return self._ldm_generic(fn, ins, "ib", True)
    def op_ldmda(self, fn, ins): return self._ldm_generic(fn, ins, "da", True)
    def op_ldmdb(self, fn, ins): return self._ldm_generic(fn, ins, "db", True)
    def op_stm(self, fn, ins): return self._ldm_generic(fn, ins, "ia", False)
    def op_stmib(self, fn, ins): return self._ldm_generic(fn, ins, "ib", False)
    def op_stmda(self, fn, ins): return self._ldm_generic(fn, ins, "da", False)
    def op_stmdb(self, fn, ins): return self._ldm_generic(fn, ins, "db", False)

    def op_push(self, fn, ins):
        i = ins.cs
        return self._ldm_stm(fn, ins, 13, [self.rnum(i, o) for o in i.operands], "db", False, True)

    def op_pop(self, fn, ins):
        i = ins.cs
        return self._ldm_stm(fn, ins, 13, [self.rnum(i, o) for o in i.operands], "ia", True, True)

    # ================================================================ VFP
    def vreg(self, i, o):
        k, n = reg_kind(i.reg_name(o.reg))
        return k, n

    def vexpr(self, i, o):
        k, n = self.vreg(i, o)
        if k == "s":
            return f"VS({n})"
        if k == "d":
            return f"VD({n})"
        raise Unsupported(f"vfp operand {i.reg_name(o.reg)}")

    F64_DTS = {A.ARM_VECTORDATA_F64, A.ARM_VECTORDATA_F64F32, A.ARM_VECTORDATA_F32F64,
               A.ARM_VECTORDATA_S32F64, A.ARM_VECTORDATA_U32F64, A.ARM_VECTORDATA_F64S32,
               A.ARM_VECTORDATA_F64U32, A.ARM_VECTORDATA_F64S16, A.ARM_VECTORDATA_F64U16,
               A.ARM_VECTORDATA_S16F64, A.ARM_VECTORDATA_U16F64}

    def is_vfp_scalar(self, i) -> bool:
        """True if instruction operates on VFP scalars (s regs, or d regs as f64)."""
        regs = [reg_kind(i.reg_name(o.reg))[0] for o in i.operands if o.type == A.ARM_OP_REG]
        if any(r == "q" for r in regs):
            return False
        if any(o.type == A.ARM_OP_REG and o.vector_index >= 0 for o in i.operands):
            return False
        if any(r == "s" for r in regs):
            return True
        return i.vector_data in self.F64_DTS

    def neon_or_vfp(self, fn, ins):
        i = ins.cs
        name = LEGACY_NAMES.get(i.insn_name(), i.insn_name())
        h = getattr(self, "v_" + name, None)
        if h is not None:
            return h(fn, ins)
        raise Unsupported("no vfp/neon handler")

    # ---- loads / stores
    def v_vldr(self, fn, ins):
        i = ins.cs
        ops = i.operands
        pre = []
        ea, wb, _ = self.mem_ea(ins, ops, 1, pre)
        k, n = self.vreg(i, ops[0])
        if k == "s":
            return pre + [f"VSW({n}) = LD32({ea});"]
        return pre + [f"VDX({n}) = LD64({ea});"]

    def v_vstr(self, fn, ins):
        i = ins.cs
        ops = i.operands
        pre = []
        ea, wb, _ = self.mem_ea(ins, ops, 1, pre)
        k, n = self.vreg(i, ops[0])
        if k == "s":
            return pre + [f"ST32({ea}, VSW({n}));"]
        return pre + [f"ST64({ea}, VDX({n}));"]

    def _vldm(self, ins, base, regs, mode, load, wb):
        i = ins.cs
        out = [f"uint32_t base = c->r[{base}];"]
        size = sum(4 if k == "s" else 8 for k, _ in regs)
        out.append(f"uint32_t ea = base{' - ' + str(size) if mode == 'db' else ''};")
        off = 0
        for k, n in regs:
            if k == "s":
                out.append(f"VSW({n}) = LD32(ea + {off});" if load else f"ST32(ea + {off}, VSW({n}));")
                off += 4
            else:
                out.append(f"VDX({n}) = LD64(ea + {off});" if load else f"ST64(ea + {off}, VDX({n}));")
                off += 8
        if wb:
            out.append(f"c->r[{base}] = base {'+' if mode == 'ia' else '-'} {size};")
        return out

    def _vldm_generic(self, fn, ins, mode, load):
        i = ins.cs
        ops = i.operands
        return self._vldm(ins, self.rnum(i, ops[0]), [self.vreg(i, o) for o in ops[1:]], mode, load,
                          i.writeback)

    def v_vldmia(self, fn, ins): return self._vldm_generic(fn, ins, "ia", True)
    def v_vldmdb(self, fn, ins): return self._vldm_generic(fn, ins, "db", True)
    def v_vstmia(self, fn, ins): return self._vldm_generic(fn, ins, "ia", False)
    def v_vstmdb(self, fn, ins): return self._vldm_generic(fn, ins, "db", False)

    def v_vpush(self, fn, ins):
        i = ins.cs
        return self._vldm(ins, 13, [self.vreg(i, o) for o in i.operands], "db", False, True)

    def v_vpop(self, fn, ins):
        i = ins.cs
        return self._vldm(ins, 13, [self.vreg(i, o) for o in i.operands], "ia", True, True)

    # ---- moves
    def v_vmov(self, fn, ins):
        i = ins.cs
        ops = i.operands
        kinds = []
        for o in ops:
            if o.type == A.ARM_OP_REG:
                kinds.append(reg_kind(i.reg_name(o.reg))[0])
            elif o.type == A.ARM_OP_IMM:
                kinds.append("imm")
            elif o.type == A.ARM_OP_FP:
                kinds.append("fp")
        nums = [reg_kind(i.reg_name(o.reg))[1] if o.type == A.ARM_OP_REG else None for o in ops]
        sig = "".join(k[0] for k in kinds)
        # scalar lane forms
        if len(ops) == 2 and ops[0].type == A.ARM_OP_REG and ops[0].vector_index >= 0 and kinds[1] == "r":
            bits = {A.ARM_VECTORDATA_I8: 8, A.ARM_VECTORDATA_I16: 16}.get(i.vector_data, i.vector_size or 32)
            off = nums[0] * 8 + ops[0].vector_index * bits // 8
            return [f"{{ uint{bits}_t t = (uint{bits}_t)c->r[{nums[1]}]; memcpy(c->vfp.b + {off}, &t, {bits // 8}); }}"]
        if len(ops) == 2 and kinds[0] == "r" and ops[1].type == A.ARM_OP_REG and ops[1].vector_index >= 0:
            bits, kind = dtinfo(i, (i.vector_size or 32, "u"))
            off = nums[1] * 8 + ops[1].vector_index * bits // 8
            t = ctype(bits, "s" if kind == "s" else "u")
            return [f"{{ {t} t; memcpy(&t, c->vfp.b + {off}, {bits // 8}); c->r[{nums[0]}] = (uint32_t)(int32_t)t; }}"
                    if kind == "s" else
                    f"{{ {t} t; memcpy(&t, c->vfp.b + {off}, {bits // 8}); c->r[{nums[0]}] = (uint32_t)t; }}"]
        if sig == "sr":
            return [f"VSW({nums[0]}) = {self.reg_read(ins, ops[1])};"]
        if sig == "rs":
            return [f"c->r[{nums[0]}] = VSW({nums[1]});"]
        if sig == "rrd":
            return [f"c->r[{nums[0]}] = (uint32_t)VDX({nums[2]}); c->r[{nums[1]}] = (uint32_t)(VDX({nums[2]}) >> 32);"]
        if sig == "drr":
            return [f"VDX({nums[0]}) = ((uint64_t)c->r[{nums[2]}] << 32) | c->r[{nums[1]}];"]
        if sig == "ssrr":
            return [f"VSW({nums[0]}) = c->r[{nums[2]}]; VSW({nums[1]}) = c->r[{nums[3]}];"]
        if sig == "rrss":
            return [f"c->r[{nums[0]}] = VSW({nums[2]}); c->r[{nums[1]}] = VSW({nums[3]});"]
        if sig == "ss":
            return [f"VSW({nums[0]}) = VSW({nums[1]});"]
        if sig == "dd":
            return [f"VDX({nums[0]}) = VDX({nums[1]});"]
        if sig == "qq":
            return [f"VDX({2 * nums[0]}) = VDX({2 * nums[1]}); VDX({2 * nums[0] + 1}) = VDX({2 * nums[1] + 1});"]
        if sig in ("di", "qi", "df", "qf"):
            return self.neon_imm(ins, nums[0], kinds[0], ops[1], invert=False)
        raise Unsupported(f"vmov form {sig}")

    def v_vmvn(self, fn, ins):
        i = ins.cs
        ops = i.operands
        k, n = self.vreg(i, ops[0])
        if ops[1].type == A.ARM_OP_IMM:
            return self.neon_imm(ins, n, k, ops[1], invert=True)
        return self.neon_elementwise(ins, "~{a}", force=(8, "u"))

    def neon_imm(self, ins, n, k, o, invert):
        i = ins.cs
        nbytes = 8 if k == "d" else 16
        off = n * 8 if k == "d" else n * 16
        if o.type == A.ARM_OP_FP:
            v = struct.unpack("<I", struct.pack("<f", o.fp))[0]
            bits = 32
        else:
            v = o.imm & 0xFFFFFFFFFFFFFFFF
            bits, _ = dtinfo(i, (32, "u"))
        if i.vector_data == A.ARM_VECTORDATA_I64:
            # capstone expands the byte mask into a 64-bit value
            bits = 64
        if invert:
            v = ~v & ((1 << bits) - 1)
        v &= (1 << bits) - 1
        lane = v.to_bytes(bits // 8, "little")
        data = (lane * (nbytes // len(lane)))
        lines = []
        for q in range(0, nbytes, 8):
            w = int.from_bytes(data[q:q + 8], "little")
            lines.append(f"VDX({off // 8 + q // 8}) = 0x{w:016x}ull;")
        return lines

    def v_fconsts(self, fn, ins):
        i = ins.cs
        k, n = self.vreg(i, i.operands[0])
        return [f"VS({n}) = {repr(float(i.operands[1].fp))}f;"]

    def v_fconstd(self, fn, ins):
        i = ins.cs
        k, n = self.vreg(i, i.operands[0])
        return [f"VD({n}) = {repr(float(i.operands[1].fp))};"]

    def _fconst(self, fn, ins):
        i = ins.cs
        k, n = self.vreg(i, i.operands[0])
        return [f"VS({n}) = {repr(float(i.operands[1].fp))}f;" if k == "s" else f"VD({n}) = {repr(float(i.operands[1].fp))};"]

    def op_fconsts(self, fn, ins): return self._fconst(fn, ins)
    def op_fconstd(self, fn, ins): return self._fconst(fn, ins)

    def op_fmstat(self, fn, ins): return ["vfp_to_apsr(c);"]

    def v_vmrs(self, fn, ins):
        i = ins.cs
        d = i.reg_name(i.operands[0].reg)
        if d == "apsr_nzcv":
            return ["vfp_to_apsr(c);"]
        return [f"c->r[{self.rnum(i, i.operands[0])}] = c->fpscr;"]

    def v_vmsr(self, fn, ins):
        i = ins.cs
        return [f"c->fpscr = c->r[{self.rnum(i, i.operands[1])}];"]

    # ---- arithmetic
    def _vfp3(self, fn, ins, fmt, neon_fmt=None):
        i = ins.cs
        if self.is_vfp_scalar(i):
            ops = i.operands
            if len(ops) == 2:
                d, a, b = ops[0], ops[0], ops[1]
            else:
                d, a, b = ops
            de, ae, be = self.vexpr(i, d), self.vexpr(i, a), self.vexpr(i, b)
            return [f"{de} = {fmt.format(d=de, a=ae, b=be)};"]
        if neon_fmt is None:
            neon_fmt = fmt
        return self.neon_elementwise(ins, neon_fmt)

    def v_vadd(self, fn, ins): return self._vfp3(fn, ins, "{a} + {b}")
    def v_vsub(self, fn, ins): return self._vfp3(fn, ins, "{a} - {b}")
    def v_vmul(self, fn, ins): return self._vfp3(fn, ins, "{a} * {b}")
    def v_vdiv(self, fn, ins): return self._vfp3(fn, ins, "{a} / {b}")
    def v_vmla(self, fn, ins): return self._vfp3(fn, ins, "{d} + {a} * {b}")
    def v_vmls(self, fn, ins): return self._vfp3(fn, ins, "{d} - {a} * {b}")
    def v_vnmul(self, fn, ins): return self._vfp3(fn, ins, "-({a} * {b})")
    def v_vnmla(self, fn, ins): return self._vfp3(fn, ins, "-{d} - {a} * {b}")
    def v_vnmls(self, fn, ins): return self._vfp3(fn, ins, "-{d} + {a} * {b}")

    def _fma(self, fn, ins, fmt):
        i = ins.cs
        if self.is_vfp_scalar(i):
            d, a, b = i.operands
            de, ae, be = self.vexpr(i, d), self.vexpr(i, a), self.vexpr(i, b)
            f = "fmaf" if de.startswith("VS") else "fma"
            return [f"{de} = {fmt.format(f=f, d=de, a=ae, b=be)};"]
        return self.neon_elementwise(ins, fmt.format(f="fmaf", d="{d}", a="{a}", b="{b}"))

    def v_vfma(self, fn, ins): return self._fma(fn, ins, "{f}({a}, {b}, {d})")
    def v_vfms(self, fn, ins): return self._fma(fn, ins, "{f}(-{a}, {b}, {d})")
    def v_vfnma(self, fn, ins): return self._fma(fn, ins, "{f}(-{a}, {b}, -{d})")
    def v_vfnms(self, fn, ins): return self._fma(fn, ins, "{f}({a}, {b}, -{d})")

    def _vfp2(self, fn, ins, fmt_s, fmt_d, neon_fmt):
        i = ins.cs
        if self.is_vfp_scalar(i):
            d, a = i.operands[0], i.operands[1]
            de, ae = self.vexpr(i, d), self.vexpr(i, a)
            f = fmt_s if de.startswith("VS") else fmt_d
            return [f"{de} = {f.format(a=ae)};"]
        return self.neon_elementwise(ins, neon_fmt)

    def v_vneg(self, fn, ins): return self._vfp2(fn, ins, "-{a}", "-{a}", "-{a}")
    def v_vabs(self, fn, ins):
        i = ins.cs
        _, kind = dtinfo(i, (32, "f"))
        nf = "fabsf({a})" if kind == "f" else "({a} < 0 ? -{a} : {a})"
        return self._vfp2(fn, ins, "fabsf({a})", "fabs({a})", nf)
    def v_vsqrt(self, fn, ins): return self._vfp2(fn, ins, "sqrtf({a})", "sqrt({a})", "sqrtf({a})")

    def v_vcmp(self, fn, ins):
        i = ins.cs
        ops = i.operands
        a = self.vexpr(i, ops[0])
        b = self.vexpr(i, ops[1]) if ops[1].type == A.ARM_OP_REG else repr(float(ops[1].fp if ops[1].type == A.ARM_OP_FP else ops[1].imm))
        return [f"vfp_cmp(c, (double){a}, (double){b});"]

    v_vcmpe = v_vcmp

    def v_vcvt(self, fn, ins):
        i = ins.cs
        ops = i.operands
        dt = i.vector_data
        if not self.is_vfp_scalar(i) or any(reg_kind(i.reg_name(o.reg))[0] == "q" for o in ops if o.type == A.ARM_OP_REG):
            return self.neon_cvt(ins)
        d, m = ops[0], ops[1]
        dk, dn = self.vreg(i, d)
        mk, mn = self.vreg(i, m)
        fb = ops[2].imm if len(ops) > 2 and ops[2].type == A.ARM_OP_IMM else None
        src_f = f"VS({mn})" if mk == "s" else f"VD({mn})"
        if fb is not None:
            # fixed point <-> float, in place (d == m)
            scale = float(1 << fb)
            if dt in (A.ARM_VECTORDATA_S32F32, A.ARM_VECTORDATA_U32F32):
                f = "f2s32" if dt == A.ARM_VECTORDATA_S32F32 else "f2u32"
                return [f"VSW({dn}) = (uint32_t){f}((double)VS({mn}) * {scale});"]
            if dt in (A.ARM_VECTORDATA_F32S32, A.ARM_VECTORDATA_F32U32):
                cast = "(int32_t)" if dt == A.ARM_VECTORDATA_F32S32 else ""
                return [f"VS({dn}) = (float)((double){cast}VSW({mn}) / {scale});"]
            if dt in (A.ARM_VECTORDATA_S32F64, A.ARM_VECTORDATA_U32F64):
                f = "f2s32" if dt == A.ARM_VECTORDATA_S32F64 else "f2u32"
                return [f"VDX({dn}) = (uint64_t)(uint32_t){f}(VD({mn}) * {scale});"]
            if dt in (A.ARM_VECTORDATA_F64S32, A.ARM_VECTORDATA_F64U32):
                cast = "(int32_t)" if dt == A.ARM_VECTORDATA_F64S32 else ""
                return [f"VD({dn}) = (double){cast}(uint32_t)VDX({mn}) / {scale};"]
            if dt in (A.ARM_VECTORDATA_S16F32, A.ARM_VECTORDATA_U16F32):
                lo, hi = (-32768, 32767) if dt == A.ARM_VECTORDATA_S16F32 else (0, 65535)
                return [f"{{ double x = (double)VS({mn}) * {scale}; int32_t t = x != x ? 0 : x <= {lo} ? {lo} : x >= {hi} ? {hi} : (int32_t)x; VSW({dn}) = (uint32_t)t; }}"]
            if dt in (A.ARM_VECTORDATA_F32S16, A.ARM_VECTORDATA_F32U16):
                cast = "(int16_t)" if dt == A.ARM_VECTORDATA_F32S16 else "(uint16_t)"
                return [f"VS({dn}) = (float)((double){cast}VSW({mn}) / {scale});"]
            raise Unsupported(f"vcvt fixed dt {dt}")
        if dt == A.ARM_VECTORDATA_F64F32:
            return [f"VD({dn}) = (double)VS({mn});"]
        if dt == A.ARM_VECTORDATA_F32F64:
            return [f"VS({dn}) = (float)VD({mn});"]
        if dt in (A.ARM_VECTORDATA_S32F32, A.ARM_VECTORDATA_S32F64):
            return [f"VSW({dn}) = (uint32_t)f2s32((double){src_f});"]
        if dt in (A.ARM_VECTORDATA_U32F32, A.ARM_VECTORDATA_U32F64):
            return [f"VSW({dn}) = f2u32((double){src_f});"]
        if dt == A.ARM_VECTORDATA_F32S32:
            return [f"VS({dn}) = (float)(int32_t)VSW({mn});"]
        if dt == A.ARM_VECTORDATA_F32U32:
            return [f"VS({dn}) = (float)VSW({mn});"]
        if dt == A.ARM_VECTORDATA_F64S32:
            return [f"VD({dn}) = (double)(int32_t)VSW({mn});"]
        if dt == A.ARM_VECTORDATA_F64U32:
            return [f"VD({dn}) = (double)VSW({mn});"]
        raise Unsupported(f"vcvt dt {dt}")

    def v_vcvtr(self, fn, ins):
        i = ins.cs
        d, m = i.operands[0], i.operands[1]
        dk, dn = self.vreg(i, d)
        mk, mn = self.vreg(i, m)
        src = f"VS({mn})" if mk == "s" else f"VD({mn})"
        dt = i.vector_data
        f = "f2s32_rn" if dt in (A.ARM_VECTORDATA_S32F32, A.ARM_VECTORDATA_S32F64) else "f2u32_rn"
        return [f"VSW({dn}) = (uint32_t){f}(c, (double){src});"]

    # ================================================================ NEON
    def vop(self, i, o):
        """(byte offset, nbytes, lane) for a d/q register operand."""
        k, n = reg_kind(i.reg_name(o.reg))
        if k == "d":
            return n * 8, 8, o.vector_index
        if k == "q":
            return n * 16, 16, o.vector_index
        if k == "s":
            return n * 4, 4, o.vector_index
        raise Unsupported(f"neon operand {i.reg_name(o.reg)}")

    def neon_elementwise(self, ins, fmt, force=None, dt=None):
        """dst[i] = fmt(a[i], b[i], d[i]) for 2/3-operand NEON instructions."""
        i = ins.cs
        ops = [o for o in i.operands if o.type == A.ARM_OP_REG]
        bits, kind = force or (INT_DT.get(dt) if dt is not None else dtinfo(i, (None, "u")))
        if bits is None:
            if i.vector_data == 0:
                bits, kind = 64, "u"   # untyped bitwise op (vand, vorr...)
            else:
                raise Unsupported(f"neon dt {i.vector_data}")
        T = ctype(bits, kind)
        if kind == "u" and "<" not in fmt and ">" not in fmt:
            T = f"uint{bits}_t"
        dof, nb, _ = self.vop(i, ops[0])
        lanes = nb * 8 // bits
        out = [f"{T} D_[{lanes}], A_[{lanes}], B_[{lanes}], R_[{lanes}];",
               f"memcpy(D_, c->vfp.b + {dof}, {nb});"]
        srcs = ops[1:] if len(ops) > 1 else ops[:1]
        if len(ops) == 2:
            srcs = [ops[1]]
        for name, o in zip(("A_", "B_"), srcs):
            off, n2, lane = self.vop(i, o)
            if lane is not None and lane >= 0:
                out.append(f"{{ {T} s_; memcpy(&s_, c->vfp.b + {off + lane * bits // 8}, {bits // 8}); "
                           f"for (int k = 0; k < {lanes}; k++) {name}[k] = s_; }}")
            else:
                out.append(f"memcpy({name}, c->vfp.b + {off}, {nb});")
        out.append(f"for (int k = 0; k < {lanes}; k++) R_[k] = ({T})({fmt.format(a='A_[k]', b='B_[k]', d='D_[k]')});")
        out.append(f"memcpy(c->vfp.b + {dof}, R_, {nb});")
        return ["{"] + ["    " + x for x in out] + ["}"]

    def _neon_bits(self, ins, fmt):
        return self.neon_elementwise(ins, fmt, force=(64, "u"))

    def v_vand(self, fn, ins): return self._neon_bits(ins, "{a} & {b}")
    def v_vorr(self, fn, ins):
        i = ins.cs
        if any(o.type == A.ARM_OP_IMM for o in i.operands):
            k, n = self.vreg(i, i.operands[0])
            off, nb, _ = self.vop(i, i.operands[0])
            bits, _ = dtinfo(i, (32, "u"))
            v = i.operands[1].imm & ((1 << bits) - 1)
            T = f"uint{bits}_t"
            return [f"{{ {T} t[{nb * 8 // bits}]; memcpy(t, c->vfp.b + {off}, {nb}); for (int k = 0; k < {nb * 8 // bits}; k++) t[k] |= {v}u; memcpy(c->vfp.b + {off}, t, {nb}); }}"]
        return self._neon_bits(ins, "{a} | {b}")
    def v_veor(self, fn, ins): return self._neon_bits(ins, "{a} ^ {b}")
    def v_vbic(self, fn, ins):
        i = ins.cs
        if any(o.type == A.ARM_OP_IMM for o in i.operands):
            off, nb, _ = self.vop(i, i.operands[0])
            bits, _ = dtinfo(i, (32, "u"))
            v = i.operands[1].imm & ((1 << bits) - 1)
            T = f"uint{bits}_t"
            return [f"{{ {T} t[{nb * 8 // bits}]; memcpy(t, c->vfp.b + {off}, {nb}); for (int k = 0; k < {nb * 8 // bits}; k++) t[k] &= ({T})~{v}u; memcpy(c->vfp.b + {off}, t, {nb}); }}"]
        return self._neon_bits(ins, "{a} & ~{b}")
    def v_vorn(self, fn, ins): return self._neon_bits(ins, "{a} | ~{b}")
    def v_vbsl(self, fn, ins): return self._neon_bits(ins, "({d} & {a}) | (~{d} & {b})")
    def v_vbit(self, fn, ins): return self._neon_bits(ins, "({a} & {b}) | ({d} & ~{b})")
    def v_vbif(self, fn, ins): return self._neon_bits(ins, "({d} & {b}) | ({a} & ~{b})")

    def _cmp(self, ins, op):
        i = ins.cs
        bits, kind = dtinfo(i, (32, "u"))
        ops = i.operands
        if ops[-1].type in (A.ARM_OP_IMM, A.ARM_OP_FP):
            b = "0"
            fmt = f"({{a}} {op} {b}) ? (uint{bits}_t)~0ull : 0"
            return self._neon_unary_cmp(ins, fmt, bits, kind)
        T = ctype(bits, kind)
        return self.neon_cmp_lanes(ins, op, bits, kind)

    def neon_cmp_lanes(self, ins, op, bits, kind):
        i = ins.cs
        ops = i.operands
        T = ctype(bits, kind)
        U = f"uint{bits}_t"
        dof, nb, _ = self.vop(i, ops[0])
        aof, _, _ = self.vop(i, ops[1])
        bof, _, _ = self.vop(i, ops[2])
        lanes = nb * 8 // bits
        return ["{", f"    {T} A_[{lanes}], B_[{lanes}]; {U} R_[{lanes}];",
                f"    memcpy(A_, c->vfp.b + {aof}, {nb}); memcpy(B_, c->vfp.b + {bof}, {nb});",
                f"    for (int k = 0; k < {lanes}; k++) R_[k] = (A_[k] {op} B_[k]) ? ({U})~0ull : 0;",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    def _neon_unary_cmp(self, ins, fmt, bits, kind):
        i = ins.cs
        ops = i.operands
        T = ctype(bits, kind)
        U = f"uint{bits}_t"
        dof, nb, _ = self.vop(i, ops[0])
        aof, _, _ = self.vop(i, ops[1])
        lanes = nb * 8 // bits
        return ["{", f"    {T} A_[{lanes}]; {U} R_[{lanes}];",
                f"    memcpy(A_, c->vfp.b + {aof}, {nb});",
                f"    for (int k = 0; k < {lanes}; k++) R_[k] = {fmt.format(a='A_[k]')};",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    def v_vceq(self, fn, ins): return self._cmp(ins, "==")
    def v_vcge(self, fn, ins): return self._cmp(ins, ">=")
    def v_vcgt(self, fn, ins): return self._cmp(ins, ">")
    def v_vcle(self, fn, ins): return self._cmp(ins, "<=")
    def v_vclt(self, fn, ins): return self._cmp(ins, "<")

    def v_vtst(self, fn, ins):
        i = ins.cs
        bits, _ = dtinfo(i, (32, "u"))
        return self.neon_elementwise(ins, f"({{a}} & {{b}}) ? (uint{bits}_t)~0ull : 0", force=(bits, "u"))

    def v_vmax(self, fn, ins):
        i = ins.cs
        if self.is_vfp_scalar(i):
            raise Unsupported("vfp vmax")
        return self.neon_elementwise(ins, "({a} > {b} ? {a} : {b})")

    def v_vmin(self, fn, ins):
        return self.neon_elementwise(ins, "({a} < {b} ? {a} : {b})")

    def v_vabd(self, fn, ins):
        _, kind = dtinfo(ins.cs, (32, "f"))
        if kind == "f":
            return self.neon_elementwise(ins, "fabsf({a} - {b})")
        return self.neon_elementwise(ins, "({a} > {b} ? {a} - {b} : {b} - {a})")

    def v_vrecpe(self, fn, ins): return self._neon_unary(ins, "neon_recpe({a})")
    def v_vrsqrte(self, fn, ins): return self._neon_unary(ins, "neon_rsqrte({a})")
    def v_vrecps(self, fn, ins): return self.neon_elementwise(ins, "neon_recps({a}, {b})")
    def v_vrsqrts(self, fn, ins): return self.neon_elementwise(ins, "neon_rsqrts({a}, {b})")

    def _neon_unary(self, ins, fmt, dt_override=None):
        i = ins.cs
        ops = i.operands
        bits, kind = dt_override or dtinfo(i, (32, "f"))
        T = ctype(bits, kind)
        dof, nb, _ = self.vop(i, ops[0])
        aof, _, _ = self.vop(i, ops[1])
        lanes = nb * 8 // bits
        return ["{", f"    {T} A_[{lanes}], R_[{lanes}];",
                f"    memcpy(A_, c->vfp.b + {aof}, {nb});",
                f"    for (int k = 0; k < {lanes}; k++) R_[k] = ({T})({fmt.format(a='A_[k]')});",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    def v_vdup(self, fn, ins):
        i = ins.cs
        ops = i.operands
        dof, nb, _ = self.vop(i, ops[0])
        if reg_kind(i.reg_name(ops[1].reg))[0] == "r":
            bits = {A.ARM_VECTORDATA_I8: 8, A.ARM_VECTORDATA_I16: 16}.get(i.vector_data, i.vector_size or 32)
            src = f"(uint{bits}_t)c->r[{self.rnum(i, ops[1])}]"
        else:
            bits, _ = dtinfo(i, (32, "u"))
            aof, _, lane = self.vop(i, ops[1])
            src = f"*(uint{bits}_t *)(c->vfp.b + {aof + lane * bits // 8})"
        T = f"uint{bits}_t"
        lanes = nb * 8 // bits
        return ["{", f"    {T} s_ = {src}, R_[{lanes}];",
                f"    for (int k = 0; k < {lanes}; k++) R_[k] = s_;",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    def _neon_shift_imm(self, ins, kind):
        i = ins.cs
        ops = i.operands
        bits, sk = dtinfo(i, (32, "u"))
        T = ctype(bits, sk if kind != "shl" else "u")
        if len(ops) == 2:
            dst, src, sh = ops[0], ops[0], ops[1]
        else:
            dst, src, sh = ops
        if sh.type != A.ARM_OP_IMM:
            raise Unsupported("neon register shift")
        n = sh.imm
        dof, nb, _ = self.vop(i, dst)
        aof, _, _ = self.vop(i, src)
        lanes = nb * 8 // bits
        if kind == "shl":
            e = f"(({T})(A_[k] << {n}))" if n < bits else "0"
        elif kind in ("shr", "sra"):
            e = f"(A_[k] >> {n})" if n < bits else ("(A_[k] >> " + str(bits - 1) + ")" if sk == "s" else "0")
            if kind == "sra":
                e = f"(D_[k] + {e})"
        elif kind == "rshr":
            e = f"(({T})((A_[k] + (({T})1 << ({n} - 1))) >> {n}))"
        else:
            raise Unsupported(kind)
        return ["{", f"    {T} A_[{lanes}], D_[{lanes}], R_[{lanes}];",
                f"    memcpy(A_, c->vfp.b + {aof}, {nb}); memcpy(D_, c->vfp.b + {dof}, {nb});",
                f"    for (int k = 0; k < {lanes}; k++) R_[k] = ({T}){e};",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    def v_vshl(self, fn, ins): return self._neon_shift_imm(ins, "shl")
    def v_vshr(self, fn, ins): return self._neon_shift_imm(ins, "shr")
    def v_vsra(self, fn, ins): return self._neon_shift_imm(ins, "sra")
    def v_vrshr(self, fn, ins): return self._neon_shift_imm(ins, "rshr")

    def v_vext(self, fn, ins):
        i = ins.cs
        d, a, b, imm = i.operands
        dof, nb, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        bof, _, _ = self.vop(i, b)
        bits, _ = dtinfo(i, (8, "u"))
        sh = imm.imm * bits // 8
        return ["{", f"    uint8_t T_[{2 * nb}];", f"    memcpy(T_, c->vfp.b + {aof}, {nb}); memcpy(T_ + {nb}, c->vfp.b + {bof}, {nb});",
                f"    memcpy(c->vfp.b + {dof}, T_ + {sh}, {nb});", "}"]

    def _vrev(self, ins, group_bits):
        i = ins.cs
        d, a = i.operands[0], i.operands[1]
        dof, nb, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        bits, _ = dtinfo(i, (8, "u"))
        esz = bits // 8
        gsz = group_bits // 8
        n = gsz // esz
        return ["{", f"    uint8_t A_[{nb}], R_[{nb}]; memcpy(A_, c->vfp.b + {aof}, {nb});",
                f"    for (int g = 0; g < {nb}; g += {gsz}) for (int e = 0; e < {n}; e++) memcpy(R_ + g + e * {esz}, A_ + g + ({n} - 1 - e) * {esz}, {esz});",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    def v_vrev16(self, fn, ins): return self._vrev(ins, 16)
    def v_vrev32(self, fn, ins): return self._vrev(ins, 32)
    def v_vrev64(self, fn, ins): return self._vrev(ins, 64)

    def _vpermute(self, ins, kind):
        i = ins.cs
        a, b = i.operands[0], i.operands[1]
        aof, nb, _ = self.vop(i, a)
        bof, _, _ = self.vop(i, b)
        bits, _ = dtinfo(i, (8, "u"))
        T = f"uint{bits}_t"
        n = nb * 8 // bits
        body = {
            "zip": f"for (int k = 0; k < {n}; k++) {{ O_[2 * k] = X_[k]; O_[2 * k + 1] = Y_[k]; }}",
            "uzp": f"for (int k = 0; k < {n}; k++) {{ O_[k] = I_[2 * k]; O_[{n} + k] = I_[2 * k + 1]; }}",
            "trn": f"for (int k = 0; k < {n}; k += 2) {{ O_[k] = X_[k]; O_[k + 1] = Y_[k]; O_[{n} + k] = X_[k + 1]; O_[{n} + k + 1] = Y_[k + 1]; }}",
        }[kind]
        return ["{", f"    {T} I_[{2 * n}], O_[{2 * n}]; {T} *X_ = I_, *Y_ = I_ + {n};",
                f"    memcpy(X_, c->vfp.b + {aof}, {nb}); memcpy(Y_, c->vfp.b + {bof}, {nb});",
                f"    {body}",
                f"    memcpy(c->vfp.b + {aof}, O_, {nb}); memcpy(c->vfp.b + {bof}, O_ + {n}, {nb});", "}"]

    def v_vzip(self, fn, ins): return self._vpermute(ins, "zip")
    def v_vuzp(self, fn, ins): return self._vpermute(ins, "uzp")
    def v_vtrn(self, fn, ins): return self._vpermute(ins, "trn")

    def v_vswp(self, fn, ins):
        i = ins.cs
        aof, nb, _ = self.vop(i, i.operands[0])
        bof, _, _ = self.vop(i, i.operands[1])
        return ["{", f"    uint8_t T_[{nb}]; memcpy(T_, c->vfp.b + {aof}, {nb});",
                f"    memcpy(c->vfp.b + {aof}, c->vfp.b + {bof}, {nb}); memcpy(c->vfp.b + {bof}, T_, {nb});", "}"]

    def v_vmovl(self, fn, ins):
        i = ins.cs
        d, a = i.operands[0], i.operands[1]
        bits, kind = dtinfo(i, (16, "u"))
        T, W = ctype(bits, kind), ctype(2 * bits, kind)
        dof, _, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        n = 64 // bits
        return ["{", f"    {T} A_[{n}]; {W} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, 8);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = ({W})A_[k];",
                f"    memcpy(c->vfp.b + {dof}, R_, 16);", "}"]

    def v_vmovn(self, fn, ins):
        i = ins.cs
        d, a = i.operands[0], i.operands[1]
        bits, _ = dtinfo(i, (32, "u"))   # source element size
        T, N = f"uint{bits}_t", f"uint{bits // 2}_t"
        dof, _, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        n = 128 // bits
        return ["{", f"    {T} A_[{n}]; {N} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, 16);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = ({N})A_[k];",
                f"    memcpy(c->vfp.b + {dof}, R_, 8);", "}"]

    def v_vqmovn(self, fn, ins):
        i = ins.cs
        d, a = i.operands[0], i.operands[1]
        bits, kind = dtinfo(i, (32, "s"))
        T, N = ctype(bits, kind), ctype(bits // 2, kind)
        h = bits // 2
        lo, hi = ((-(1 << (h - 1)), (1 << (h - 1)) - 1) if kind == "s" else (0, (1 << h) - 1))
        dof, _, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        n = 128 // bits
        return ["{", f"    {T} A_[{n}]; {N} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, 16);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = ({N})(A_[k] < ({T}){lo}ll ? ({T}){lo}ll : A_[k] > ({T}){hi}ll ? ({T}){hi}ll : A_[k]);",
                f"    memcpy(c->vfp.b + {dof}, R_, 8);", "}"]

    def v_vqmovun(self, fn, ins):
        i = ins.cs
        d, a = i.operands[0], i.operands[1]
        bits, _ = dtinfo(i, (32, "s"))
        T, N = ctype(bits, "s"), ctype(bits // 2, "u")
        hi = (1 << (bits // 2)) - 1
        dof, _, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        n = 128 // bits
        return ["{", f"    {T} A_[{n}]; {N} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, 16);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = ({N})(A_[k] < 0 ? 0 : A_[k] > {hi} ? {hi} : A_[k]);",
                f"    memcpy(c->vfp.b + {dof}, R_, 8);", "}"]

    def v_vpadd(self, fn, ins):
        i = ins.cs
        d, a, b = i.operands
        bits, kind = dtinfo(i, (32, "f"))
        T = ctype(bits, kind if kind == "f" else "u")
        dof, nb, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        bof, _, _ = self.vop(i, b)
        n = 64 // bits
        return ["{", f"    {T} I_[{2 * n}], R_[{n}]; memcpy(I_, c->vfp.b + {aof}, 8); memcpy(I_ + {n}, c->vfp.b + {bof}, 8);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = I_[2 * k] + I_[2 * k + 1];",
                f"    memcpy(c->vfp.b + {dof}, R_, 8);", "}"]

    def _vpminmax(self, ins, op):
        i = ins.cs
        d, a, b = i.operands
        bits, kind = dtinfo(i, (32, "f"))
        T = ctype(bits, kind)
        dof, nb, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        bof, _, _ = self.vop(i, b)
        n = 64 // bits
        return ["{", f"    {T} I_[{2 * n}], R_[{n}]; memcpy(I_, c->vfp.b + {aof}, 8); memcpy(I_ + {n}, c->vfp.b + {bof}, 8);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = (I_[2 * k] {op} I_[2 * k + 1]) ? I_[2 * k] : I_[2 * k + 1];",
                f"    memcpy(c->vfp.b + {dof}, R_, 8);", "}"]

    def v_vpmax(self, fn, ins): return self._vpminmax(ins, ">")
    def v_vpmin(self, fn, ins): return self._vpminmax(ins, "<")

    def v_vmull(self, fn, ins):
        i = ins.cs
        d, a, b = i.operands
        bits, kind = dtinfo(i, (16, "s"))
        T, W = ctype(bits, kind), ctype(2 * bits, kind)
        dof, _, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        bof, _, lane = self.vop(i, b)
        n = 64 // bits
        bsrc = f"B_[k]" if lane is None or lane < 0 else f"B_[{lane}]"
        return ["{", f"    {T} A_[{n}], B_[{n}]; {W} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, 8); memcpy(B_, c->vfp.b + {bof}, 8);",
                f"    for (int k = 0; k < {n}; k++) R_[k] = ({W})A_[k] * ({W}){bsrc};",
                f"    memcpy(c->vfp.b + {dof}, R_, 16);", "}"]

    def v_vmlal(self, fn, ins):
        i = ins.cs
        d, a, b = i.operands
        bits, kind = dtinfo(i, (16, "s"))
        T, W = ctype(bits, kind), ctype(2 * bits, kind)
        dof, _, _ = self.vop(i, d)
        aof, _, _ = self.vop(i, a)
        bof, _, lane = self.vop(i, b)
        n = 64 // bits
        bsrc = f"B_[k]" if lane is None or lane < 0 else f"B_[{lane}]"
        return ["{", f"    {T} A_[{n}], B_[{n}]; {W} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, 8); memcpy(B_, c->vfp.b + {bof}, 8);",
                f"    memcpy(R_, c->vfp.b + {dof}, 16);",
                f"    for (int k = 0; k < {n}; k++) R_[k] += ({W})A_[k] * ({W}){bsrc};",
                f"    memcpy(c->vfp.b + {dof}, R_, 16);", "}"]

    def v_vqadd(self, fn, ins):
        bits, kind = dtinfo(ins.cs, (16, "s"))
        if bits == 64:
            raise Unsupported("vqadd.64")
        W = ctype(64, "s")
        lo, hi = ((-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if kind == "s" else (0, (1 << bits) - 1))
        return self.neon_elementwise(ins, f"(({W}){{a}} + {{b}} < {lo}ll ? {lo}ll : ({W}){{a}} + {{b}} > {hi}ll ? {hi}ll : ({W}){{a}} + {{b}})")

    def v_vqsub(self, fn, ins):
        bits, kind = dtinfo(ins.cs, (16, "s"))
        if bits == 64:
            raise Unsupported("vqsub.64")
        W = ctype(64, "s")
        lo, hi = ((-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if kind == "s" else (0, (1 << bits) - 1))
        return self.neon_elementwise(ins, f"(({W}){{a}} - {{b}} < {lo}ll ? {lo}ll : ({W}){{a}} - {{b}} > {hi}ll ? {hi}ll : ({W}){{a}} - {{b}})")

    def neon_cvt(self, ins):
        i = ins.cs
        ops = i.operands
        dt = i.vector_data
        dof, nb, _ = self.vop(i, ops[0])
        aof, _, _ = self.vop(i, ops[1])
        fb = ops[2].imm if len(ops) > 2 and ops[2].type == A.ARM_OP_IMM else 0
        scale = float(1 << fb)
        n = nb // 4
        conv = {
            A.ARM_VECTORDATA_F32S32: ("int32_t", "float", f"(float)((double)A_[k] / {scale})"),
            A.ARM_VECTORDATA_F32U32: ("uint32_t", "float", f"(float)((double)A_[k] / {scale})"),
            A.ARM_VECTORDATA_S32F32: ("float", "int32_t", f"f2s32((double)A_[k] * {scale})"),
            A.ARM_VECTORDATA_U32F32: ("float", "uint32_t", f"f2u32((double)A_[k] * {scale})"),
        }.get(dt)
        if conv is None:
            raise Unsupported(f"neon vcvt dt {dt}")
        S, D, e = conv
        return ["{", f"    {S} A_[{n}]; {D} R_[{n}]; memcpy(A_, c->vfp.b + {aof}, {nb});",
                f"    for (int k = 0; k < {n}; k++) R_[k] = {e};",
                f"    memcpy(c->vfp.b + {dof}, R_, {nb});", "}"]

    # ---- structure loads/stores
    def _vldst(self, fn, ins, load, nstruct):
        i = ins.cs
        ops = list(i.operands)
        mi = next(k for k, o in enumerate(ops) if o.type == A.ARM_OP_MEM)
        regs = ops[:mi]
        post = ops[mi + 1:]
        bits = i.vector_size or 8
        esz = bits // 8
        base = reg_kind(i.reg_name(ops[mi].mem.base))[1]
        dregs = [reg_kind(i.reg_name(o.reg))[1] for o in regs]
        import re as _re
        lane_m = _re.findall(r"d\d+\[(\d+)\]", i.op_str)
        lanes = [int(lane_m[0])] * len(regs) if lane_m else [o.vector_index for o in regs]
        out = [f"uint32_t ea = c->r[{base}];"]
        total = 0
        all_lanes = "[]" in i.op_str
        if all(l is not None and l >= 0 for l in lanes):
            # single lane
            l = lanes[0]
            for k, d in enumerate(dregs):
                off = d * 8 + l * esz
                if load:
                    out.append(f"memcpy(c->vfp.b + {off}, G2H(ea + {k * esz}), {esz});")
                else:
                    out.append(f"memcpy(G2H(ea + {k * esz}), c->vfp.b + {off}, {esz});")
            total = esz * len(dregs)
        elif all_lanes:
            n = nstruct
            per = len(dregs) // n if nstruct > 1 else 1
            if nstruct == 1:
                for d in dregs:
                    out.append(f"{{ uint8_t e_[{esz}]; memcpy(e_, G2H(ea), {esz}); for (int k = 0; k < {8 // esz}; k++) memcpy(c->vfp.b + {d * 8} + k * {esz}, e_, {esz}); }}")
                total = esz
            else:
                for k, d in enumerate(dregs):
                    out.append(f"{{ uint8_t e_[{esz}]; memcpy(e_, G2H(ea + {k * esz}), {esz}); for (int j = 0; j < {8 // esz}; j++) memcpy(c->vfp.b + {d * 8} + j * {esz}, e_, {esz}); }}")
                total = esz * len(dregs)
        else:
            if nstruct == 1:
                for k, d in enumerate(dregs):
                    if load:
                        out.append(f"VDX({d}) = LD64(ea + {8 * k});")
                    else:
                        out.append(f"ST64(ea + {8 * k}, VDX({d}));")
                total = 8 * len(dregs)
            else:
                n = nstruct
                nel = 8 // esz
                for e in range(nel):
                    for k, d in enumerate(dregs):
                        off = d * 8 + e * esz
                        mo = (e * len(dregs) + k) * esz
                        if load:
                            out.append(f"memcpy(c->vfp.b + {off}, G2H(ea + {mo}), {esz});")
                        else:
                            out.append(f"memcpy(G2H(ea + {mo}), c->vfp.b + {off}, {esz});")
                total = 8 * len(dregs)
        if post:
            out.append(f"c->r[{base}] = ea + c->r[{self.rnum(i, post[0])}];")
        elif i.writeback:
            out.append(f"c->r[{base}] = ea + {total};")
        return out

    def v_vld1(self, fn, ins): return self._vldst(fn, ins, True, 1)
    def v_vst1(self, fn, ins): return self._vldst(fn, ins, False, 1)
    def v_vld2(self, fn, ins): return self._vldst(fn, ins, True, 2)
    def v_vst2(self, fn, ins): return self._vldst(fn, ins, False, 2)
    def v_vld3(self, fn, ins): return self._vldst(fn, ins, True, 3)
    def v_vst3(self, fn, ins): return self._vldst(fn, ins, False, 3)
    def v_vld4(self, fn, ins): return self._vldst(fn, ins, True, 4)
    def v_vst4(self, fn, ins): return self._vldst(fn, ins, False, 4)

    # ============================================================ function
    def lift_function(self, fn: Function, cname: str) -> str:
        insns = sorted(fn.insns.values(), key=lambda x: x.addr)
        labels = set(fn.labels)
        # every instruction is a potential target of unresolved indirect jumps
        if fn.unresolved_ijumps:
            labels |= {x.addr for x in insns}
        self._cur_labels = labels
        order = [x.addr for x in insns]
        nxt = {order[k]: (order[k + 1] if k + 1 < len(order) else None) for k in range(len(order))}
        falls = {}
        for x in insns:
            cont = x.kind in (SEQ, CALL, ICALL) or x.cond
            if cont and nxt[x.addr] != x.next:
                labels.add(x.next)
                falls[x.addr] = x.next
        out = [f"void {cname}(CPU *c) {{"]
        if fn.addr not in labels or insns[0].addr != fn.addr:
            out.append(f"    goto {self.label(fn.addr)};")
        for x in insns:
            if x.addr in labels:
                out.append(f"{self.label(x.addr)}:;")
            if x.cs is not None:
                out.append(f"    /* {self.g(x.addr):08x}: {x.cs.mnemonic} {x.cs.op_str} */".replace("*/ */", "* /"))
            body = self.lift_insn(fn, x)
            if body:
                out.append("    {")
                out += ["        " + b for b in body]
                out.append("    }")
            if x.addr in falls:
                t = falls[x.addr]
                if t in fn.insns:
                    out.append(f"    goto {self.label(t)};")
                else:
                    out.append(f'    rt_unimplemented(c, {hx(self.g(t))}, "fell off function"); return;')
        out.append("}")
        return "\n".join(out) + "\n"

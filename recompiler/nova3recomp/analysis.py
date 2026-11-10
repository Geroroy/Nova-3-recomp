"""Function discovery and control-flow recovery."""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from capstone import arm as A

from .disasm import ARM, THUMB, Disassembler, reg_kind
from .elf import ElfImage

# kinds of control flow at the end of an instruction
SEQ = "seq"            # falls through
BRANCH = "branch"      # direct jump (maybe conditional) to .target
CALL = "call"          # direct call to .target (falls through afterwards)
RET = "ret"            # function return
IJUMP = "ijump"        # indirect jump (.targets: resolved table, may be empty)
ICALL = "icall"        # indirect call (falls through)
STOP = "stop"          # undecodable / trap; never falls through

NORETURN_IMPORTS = {
    "abort", "exit", "_exit", "_Exit", "__stack_chk_fail", "__assert", "__assert2",
    "longjmp", "siglongjmp", "_longjmp", "__cxa_throw", "__cxa_rethrow",
    "_Unwind_Resume", "__cxa_bad_cast", "__cxa_bad_typeid", "__cxa_pure_virtual",
    "pthread_exit", "__fortify_fatal", "__android_log_assert", "__cxa_call_unexpected",
    "_ZSt9terminatev", "_ZSt17__throw_bad_allocv",
}


@dataclass
class Insn:
    addr: int
    mode: str
    cs: object               # capstone instruction (None if undecodable)
    kind: str = SEQ
    target: int | None = None        # direct branch / call target (no thumb bit)
    target_mode: str | None = None
    targets: list = field(default_factory=list)  # resolved indirect targets [(addr, mode)]
    cond: bool = False       # conditionally executed control flow
    plt_import: object = None        # call/branch into a PLT stub
    tailcall: bool = False
    const_target: int | None = None  # statically known target of BX/BLX/MOV PC (with thumb bit)

    @property
    def size(self) -> int:
        return self.cs.size if self.cs is not None else (4 if self.mode == ARM else 2)

    @property
    def next(self) -> int:
        return self.addr + self.size


@dataclass
class Function:
    addr: int
    mode: str
    name: str | None = None
    insns: dict = field(default_factory=dict)    # addr -> Insn
    labels: set = field(default_factory=set)
    unresolved_ijumps: int = 0

    @property
    def guest_addr(self) -> int:
        return self.addr | (1 if self.mode == THUMB else 0)


def _pc_val(insn: Insn) -> int:
    return insn.addr + (8 if insn.mode == ARM else 4)


class Analyzer:
    def __init__(self, image: ElfImage, log=print):
        self.img = image
        self.dis = Disassembler(image)
        self.log = log
        self.entries: dict[int, str] = {}       # addr -> mode
        self.names: dict[int, str] = {}
        self.functions: dict[int, Function] = {}
        self.plt_range = image.section_range(".plt")
        self._plt_cache: dict[int, object] = {}
        self.stats = {"ijump_unresolved": 0, "ijump_tables": 0, "undecodable": 0, "code_pointers": 0}
        tr = image.section_range(".text")
        self.text_range = tr

    def in_text(self, addr: int) -> bool:
        if self.text_range:
            return self.text_range[0] <= addr < self.text_range[1]
        return self.img.is_code(addr) and not self.in_plt(addr)

    # ----------------------------------------------------------- entries
    def add_entry(self, addr: int, mode: str | None = None, name: str | None = None) -> bool:
        if mode is None:
            mode = THUMB if addr & 1 else ARM
        addr &= ~1
        if not self.img.is_code(addr) or self.in_plt(addr):
            return False
        if addr in self.entries:
            if name and addr not in self.names:
                self.names[addr] = name
            return False
        self.entries[addr] = mode
        if name:
            self.names[addr] = name
        return True

    def collect_entries(self, extra=()):
        img = self.img
        for s in img.dynsyms + img.symtab:
            if s.defined and s.type == "STT_FUNC" and s.value:
                self.add_entry(s.value, None, s.name)
        for a in img.init_array + img.fini_array:
            self.add_entry(a)
        for a in (img.dt_init, img.dt_fini):
            if a:
                self.add_entry(a)
        # function pointers stored in data (vtables, callbacks...)
        for r in img.relocs:
            if r.type == 23:  # RELATIVE
                try:
                    v = img.u32(r.offset)
                except IndexError:
                    continue
                if img.is_code(v & ~1) and not img.is_code(r.offset):
                    if v & 1 or self._looks_like_arm_func(v):
                        self.add_entry(v)
        # unwind table entries: mode inferred from neighbours
        known = sorted(self.entries.items())
        keys = [k for k, _ in known]
        for a in img.exidx_starts:
            if a in self.entries or not img.is_code(a):
                continue
            mode = img.mapping_mode(a)
            if mode in ("a", "t"):
                mode = ARM if mode == "a" else THUMB
            else:
                i = bisect.bisect_right(keys, a) - 1
                mode = known[i][1] if i >= 0 else (known[0][1] if known else THUMB)
                mode = self._guess_mode(a, mode)
            self.add_entry(a, mode)
        for a, mode, name in extra:
            self.add_entry(a, mode, name)

    def _looks_like_arm_func(self, v: int) -> bool:
        return (v & 3) == 0 and self.dis.decode(v, ARM) is not None

    def _guess_mode(self, addr: int, preferred: str) -> str:
        """Pick the mode that decodes a plausible run of instructions."""
        def score(mode):
            a, n = addr, 0
            for _ in range(6):
                i = self.dis.decode(a, mode)
                if i is None:
                    return n - 10
                n += 1
                if i.id in (A.ARM_INS_PUSH, A.ARM_INS_STMDB) and n == 1:
                    n += 5
                a += i.size
            return n
        if addr & 3:
            return THUMB
        other = ARM if preferred == THUMB else THUMB
        return other if score(other) > score(preferred) + 3 else preferred

    # ---------------------------------------------------------------- PLT
    def in_plt(self, addr: int) -> bool:
        return bool(self.plt_range and self.plt_range[0] <= addr < self.plt_range[1])

    def plt_import(self, addr: int):
        """Resolve a PLT stub to the import it jumps through."""
        if addr in self._plt_cache:
            return self._plt_cache[addr]
        res = None
        ip = None
        a = addr & ~1
        mode = THUMB if addr & 1 else ARM
        for _ in range(6):
            i = self.dis.decode(a, mode)
            if i is None:
                break
            ops = i.operands
            pc = a + (8 if mode == ARM else 4)
            name = i.insn_name()
            regs = [i.reg_name(o.reg) if o.type == A.ARM_OP_REG else None for o in ops]

            def val(o):
                if o.type == A.ARM_OP_IMM:
                    return o.imm & 0xFFFFFFFF
                rn = i.reg_name(o.reg)
                return pc if rn == "pc" else ip
            if name == "add" and len(ops) == 4 and regs[0] in ("ip", "lr") and ops[2].type == A.ARM_OP_IMM and ops[3].type == A.ARM_OP_IMM:
                imm = ops[2].imm & 0xFFFFFFFF
                r = ops[3].imm & 31
                imm = ((imm >> r) | (imm << (32 - r))) & 0xFFFFFFFF if r else imm
                x = val(ops[1])
                if x is None:
                    break
                ip = (x + imm) & 0xFFFFFFFF
            elif name == "add" and regs[0] == "ip":
                srcs = ops[1:] if len(ops) == 3 else ops
                v = 0
                for o in srcs:
                    x = val(o)
                    if x is None:
                        break
                    v += x
                ip = v & 0xFFFFFFFF
            elif name == "movw" and regs[0] == "ip":
                ip = ops[1].imm & 0xFFFF
            elif name == "movt" and regs[0] == "ip":
                ip = ((ops[1].imm & 0xFFFF) << 16) | ((ip or 0) & 0xFFFF)
            elif name == "ldr" and ops[1].type == A.ARM_OP_MEM:
                base = i.reg_name(ops[1].mem.base)
                b = (pc & ~3) if base == "pc" else ip
                if b is None:
                    break
                ea = (b + ops[1].mem.disp) & 0xFFFFFFFF
                if regs[0] == "pc":
                    res = self.img.got_import.get(ea)
                    if res is None:
                        r = self.img.reloc_at.get(ea)
                        if r is not None and r.sym is not None and r.sym.defined:
                            res = ("func", r.sym.value)
                        else:
                            res = ("addr", ea)
                    break
                ip = self.img.u32(ea)
            elif name == "bx" and regs[0] == "pc":
                a = (a + 4) & ~3
                mode = ARM
                continue
            elif name in ("nop", "hint"):
                pass
            else:
                break
            a += i.size
        self._plt_cache[addr] = res
        return res

    # ------------------------------------------------------- classification
    def classify(self, ins: Insn):
        i = ins.cs
        if i is None:
            ins.kind = STOP
            self.stats["undecodable"] += 1
            return
        iid = i.id
        ops = i.operands
        cond = i.cc not in (A.ARM_CC_AL, A.ARM_CC_INVALID)
        ins.cond = cond

        def is_pc(o):
            return o.type == A.ARM_OP_REG and i.reg_name(o.reg) == "pc"

        if iid in (A.ARM_INS_B, A.ARM_INS_BL, A.ARM_INS_BLX) and ops and ops[0].type == A.ARM_OP_IMM:
            t = ops[0].imm & 0xFFFFFFFF
            if iid == A.ARM_INS_BLX:
                tm = THUMB if ins.mode == ARM else ARM
                if tm == ARM:
                    t &= ~3
            else:
                tm = ins.mode
            ins.kind = BRANCH if iid == A.ARM_INS_B else CALL
            ins.target, ins.target_mode = t & ~1, tm
            if self.in_plt(ins.target):
                imp = self.plt_import(ins.target | (1 if tm == THUMB else 0))
                if isinstance(imp, tuple) and imp[0] == "func":
                    ins.target = imp[1] & ~1
                    ins.target_mode = THUMB if imp[1] & 1 else ARM
                    if ins.kind == BRANCH:
                        ins.tailcall = True
                        self.add_entry(imp[1])
                else:
                    ins.plt_import = imp
            return
        if iid in (A.ARM_INS_CBZ, A.ARM_INS_CBNZ):
            ins.kind = BRANCH
            ins.cond = True
            ins.target, ins.target_mode = ops[1].imm & 0xFFFFFFFF, ins.mode
            return
        if iid == A.ARM_INS_BX:
            r = i.reg_name(ops[0].reg)
            if r == "lr":
                ins.kind = RET
            elif r == "pc":
                ins.kind = BRANCH
                ins.target, ins.target_mode = (_pc_val(ins)) & ~3, ARM
            else:
                ins.kind = IJUMP
            return
        if iid == A.ARM_INS_BLX:
            ins.kind = ICALL
            return
        if iid in (A.ARM_INS_TBB, A.ARM_INS_TBH):
            ins.kind = IJUMP
            return
        if iid in (A.ARM_INS_POP,) or (iid == A.ARM_INS_LDM and i.reg_name(ops[0].reg) == "sp"):
            regs = ops if iid == A.ARM_INS_POP else ops[1:]
            if any(is_pc(o) for o in regs):
                ins.kind = RET
            return
        if iid in (A.ARM_INS_LDM, A.ARM_INS_LDMDA, A.ARM_INS_LDMDB, A.ARM_INS_LDMIB):
            if any(is_pc(o) for o in ops[1:]):
                ins.kind = IJUMP
            return
        if iid == A.ARM_INS_LDR and ops and is_pc(ops[0]):
            m = ops[1].mem
            if i.reg_name(m.base) == "sp" and (len(ops) > 2 or i.writeback):
                ins.kind = RET
            else:
                ins.kind = IJUMP
            return
        if iid in (A.ARM_INS_UDF, A.ARM_INS_BKPT, A.ARM_INS_TRAP):
            ins.kind = STOP
            return
        # data processing writing PC
        if ops and is_pc(ops[0]) and iid in (
                A.ARM_INS_MOV, A.ARM_INS_ADD, A.ARM_INS_SUB, A.ARM_INS_ORR, A.ARM_INS_AND,
                A.ARM_INS_EOR, A.ARM_INS_BIC, A.ARM_INS_MVN, A.ARM_INS_RSB, A.ARM_INS_ADC,
                A.ARM_INS_SBC, A.ARM_INS_LSL, A.ARM_INS_LSR, A.ARM_INS_ASR, A.ARM_INS_ROR):
            if iid == A.ARM_INS_MOV and len(ops) == 2 and ops[1].type == A.ARM_OP_REG \
                    and i.reg_name(ops[1].reg) == "lr" and ops[1].shift.type == 0:
                ins.kind = RET
            else:
                ins.kind = IJUMP
            return

    # ---------------------------------------------------------- jump tables
    def _find_bound(self, fn: Function, ins: Insn, reg: str) -> int | None:
        """Look back a few instructions for `cmp R, #N` (+ unsigned branch) where R
        holds the same value as the table index register -> N+1 entries."""
        window = []
        a = ins.addr
        while len(window) < 14:
            prev = None
            for back in (2, 4):
                p = fn.insns.get(a - back)
                if p is not None and p.next == a and p.cs is not None:
                    prev = p
                    break
            if prev is None:
                # also accept the block start reached through a conditional branch
                break
            window.append(prev)
            a = prev.addr
        aliases = {reg}
        # registers copied to/from the index register inside the window
        for p in window:
            i = p.cs
            ops = i.operands
            if i.id == A.ARM_INS_MOV and len(ops) == 2 and ops[1].type == A.ARM_OP_REG \
                    and ops[1].shift.type == 0:
                d, srcr = i.reg_name(ops[0].reg), i.reg_name(ops[1].reg)
                if d in aliases or srcr in aliases:
                    aliases |= {d, srcr}
        for p in window:
            i = p.cs
            ops = i.operands
            if i.id == A.ARM_INS_CMP and ops[0].type == A.ARM_OP_REG and \
                    i.reg_name(ops[0].reg) in aliases and ops[1].type == A.ARM_OP_IMM:
                return ops[1].imm + 1
        return None

    def resolve_ijump(self, fn: Function, ins: Insn) -> list:
        i = ins.cs
        ops = i.operands
        img = self.img
        out = []
        if i.id in (A.ARM_INS_TBB, A.ARM_INS_TBH):
            m = ops[0].mem
            idx = i.reg_name(m.index)
            n = self._find_bound(fn, ins, idx)
            if n is None or n > 4096:
                return []
            tbase = ins.addr + 4
            for k in range(n):
                off = img.u8(tbase + k) if i.id == A.ARM_INS_TBB else img.u16(tbase + 2 * k)
                out.append((tbase + 2 * off, THUMB))
            return out
        if i.id == A.ARM_INS_LDR and ops[1].type == A.ARM_OP_MEM:
            m = ops[1].mem
            if i.reg_name(m.base) == "pc" and m.index:
                n = self._find_bound(fn, ins, i.reg_name(m.index))
                if n is None or n > 4096:
                    return []
                tbase = _pc_val(ins)
                for k in range(n):
                    v, _ = img.word_after_reloc(tbase + 4 * k)
                    out.append((v & ~1, THUMB if v & 1 else ARM))
                return out
        if i.id == A.ARM_INS_ADD and len(ops) == 3 and i.reg_name(ops[1].reg) == "pc" \
                and ops[2].type == A.ARM_OP_REG and ops[2].shift.type == A.ARM_SFT_LSL \
                and ops[2].shift.value == 2 and ins.mode == ARM:
            n = self._find_bound(fn, ins, i.reg_name(ops[2].reg))
            if n is None or n > 4096:
                return []
            base = _pc_val(ins)
            return [(base + 4 * k, ARM) for k in range(n)]
        if i.id == A.ARM_INS_ADD and len(ops) == 3 and ops[1].type == A.ARM_OP_REG \
                and ops[2].type == A.ARM_OP_REG and ops[2].shift.type == 0:
            ra, rb = i.reg_name(ops[1].reg), i.reg_name(ops[2].reg)
            tbase = idx = None
            a = ins.addr
            for _ in range(10):
                p = fn.insns.get(a - (4 if ins.mode == ARM else 2)) or fn.insns.get(a - 4)
                if p is None or p.cs is None or p.next != a:
                    break
                pi = p.cs
                po = pi.operands
                if pi.id == A.ARM_INS_LDR and po[0].type == A.ARM_OP_REG and pi.reg_name(po[0].reg) == rb \
                        and po[1].type == A.ARM_OP_MEM and po[1].mem.index and pi.reg_name(po[1].mem.base) == ra:
                    idx = pi.reg_name(po[1].mem.index)
                if pi.id in (A.ARM_INS_ADD, A.ARM_INS_ADR) and po[0].type == A.ARM_OP_REG and \
                        pi.reg_name(po[0].reg) == ra and len(po) == 3 and po[1].type == A.ARM_OP_REG and \
                        pi.reg_name(po[1].reg) == "pc" and po[2].type == A.ARM_OP_IMM:
                    pcv = p.addr + (8 if p.mode == ARM else 4)
                    if p.mode == THUMB:
                        pcv &= ~3
                    tbase = pcv + po[2].imm
                if pi.id == A.ARM_INS_SUB and po[0].type == A.ARM_OP_REG and pi.reg_name(po[0].reg) == ra \
                        and len(po) == 3 and po[1].type == A.ARM_OP_REG and pi.reg_name(po[1].reg) == "pc" \
                        and po[2].type == A.ARM_OP_IMM:
                    pcv = p.addr + (8 if p.mode == ARM else 4)
                    if p.mode == THUMB:
                        pcv &= ~3
                    tbase = pcv - po[2].imm
                a = p.addr
            if tbase is not None and idx is not None:
                n = self._find_bound(fn, ins, idx)
                if n is not None and n <= 4096:
                    for k in range(n):
                        t = (tbase + self.img.u32(tbase + 4 * k)) & 0xFFFFFFFF
                        out.append((t & ~1, THUMB if (t & 1) else ins.mode))
                    return out
        return []

    # ------------------------------------------------------------ traversal
    def build_function(self, addr: int, mode: str) -> Function:
        fn = Function(addr, mode, self.names.get(addr))
        fn.labels.add(addr)
        self._explore(fn, [(addr, mode)])
        if fn.unresolved_ijumps:
            # Computed jumps with unknown targets (e.g. libgcc's unrolled division
            # loops): decode every instruction up to the next known function so
            # all of them can be reached through the dispatch switch.
            end = self._next_entry(addr)
            end = min(end, addr + 0x4000) if end else addr + 0x1000
            a = addr
            while a < end:
                if a in fn.insns:
                    a = fn.insns[a].next
                    continue
                if not self.img.is_code(a) or self.in_plt(a):
                    break
                self._explore(fn, [(a, mode)], speculative=True)
                a = fn.insns[a].next if a in fn.insns else a + (4 if mode == ARM else 2)
        return fn

    def _next_entry(self, addr: int) -> int | None:
        if getattr(self, "_sorted_entries_n", -1) != len(self.entries):
            self._sorted_entries = sorted(set(self.entries) | set(self.img.exidx_starts))
            self._sorted_entries_n = len(self.entries)
        i = bisect.bisect_right(self._sorted_entries, addr)
        return self._sorted_entries[i] if i < len(self._sorted_entries) else None

    # -------------------------------------------------------- constants
    def _track(self, ins: Insn, consts: dict):
        """Very small constant propagation over a linear instruction run."""
        i = ins.cs
        if i is None:
            consts.clear()
            return
        ops = i.operands
        iid = i.id
        pc = ins.addr + (8 if ins.mode == ARM else 4)
        rn = lambda o: i.reg_name(o.reg) if o.type == A.ARM_OP_REG else None
        dest = rn(ops[0]) if ops and ops[0].type == A.ARM_OP_REG else None
        newval = None
        cond = i.cc not in (A.ARM_CC_AL, A.ARM_CC_INVALID)
        if not cond and dest and dest != "pc":
            if iid == A.ARM_INS_MOVW and len(ops) == 2:
                newval = ops[1].imm & 0xFFFF
            elif iid == A.ARM_INS_MOVT and dest in consts:
                newval = (consts[dest] & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
            elif iid == A.ARM_INS_MOV and len(ops) == 2 and ops[1].type == A.ARM_OP_IMM:
                newval = ops[1].imm & 0xFFFFFFFF
            elif iid == A.ARM_INS_MOV and len(ops) == 2 and rn(ops[1]) in consts and ops[1].shift.type == 0:
                newval = consts[rn(ops[1])]
            elif iid == A.ARM_INS_LDR and len(ops) == 2 and ops[1].type == A.ARM_OP_MEM \
                    and i.reg_name(ops[1].mem.base) == "pc" and not ops[1].mem.index:
                try:
                    v, imp = self.img.word_after_reloc(((pc & ~3) + ops[1].mem.disp) & 0xFFFFFFFF)
                    if imp is None:
                        newval = v
                except IndexError:
                    pass
            elif iid in (A.ARM_INS_ADD, A.ARM_INS_SUB, A.ARM_INS_ADR):
                srcs = ops[1:] if len(ops) >= 3 else ops
                vals = []
                for o in srcs[:2]:
                    if o.type == A.ARM_OP_IMM:
                        vals.append(o.imm & 0xFFFFFFFF)
                    elif o.type == A.ARM_OP_REG and o.shift.type == 0:
                        r = rn(o)
                        if r == "pc":
                            imm_form = any(x.type == A.ARM_OP_IMM for x in srcs)
                            vals.append((pc & ~3) if (ins.mode == THUMB and imm_form) else pc)
                        elif r in consts:
                            vals.append(consts[r])
                        else:
                            vals = None
                            break
                    else:
                        vals = None
                        break
                if vals and len(vals) == 2 and len(ops) in (2, 3):
                    newval = (vals[0] + vals[1] if iid != A.ARM_INS_SUB else vals[0] - vals[1]) & 0xFFFFFFFF
        # invalidate everything written by this instruction
        try:
            _, written = i.regs_access()
            for r in written:
                consts.pop(i.reg_name(r), None)
        except Exception:
            consts.clear()
        if iid in (A.ARM_INS_BL, A.ARM_INS_BLX):
            for r in ("r0", "r1", "r2", "r3", "ip", "lr"):
                consts.pop(r, None)
        if newval is not None:
            consts[dest] = newval
            if (iid in (A.ARM_INS_ADD, A.ARM_INS_SUB, A.ARM_INS_ADR, A.ARM_INS_MOVT)) and self.in_text(newval & ~1):
                self._code_pointer(newval, ins.mode)

    def _code_pointer(self, v: int, from_mode: str = THUMB):
        """A computed address points into .text: maybe a function pointer."""
        a = v & ~1
        if a in self.entries:
            return
        if v & 1:
            if self.add_entry(v):
                self.stats["code_pointers"] += 1
        elif (a & 3) == 0 and a in set(self.img.exidx_starts):
            if self.add_entry(a, ARM):
                self.stats["code_pointers"] += 1
        elif (a & 3) == 0 and from_mode == ARM:
            # even address computed in ARM code: accept if it decodes as a
            # plausible run of ARM instructions (jump-table bases may slip
            # through; they only cost an unused function)
            x = a
            for _ in range(4):
                i = self.dis.decode(x, ARM)
                if i is None or i.id in (A.ARM_INS_UDF,):
                    return
                x += 4
            if self.add_entry(a, ARM):
                self.stats["code_pointers"] += 1

    def _explore(self, fn: Function, work: list, speculative: bool = False):
        while work:
            a, m = work.pop()
            consts: dict = {}
            while True:
                if a in fn.insns:
                    break
                if not self.img.is_code(a):
                    ins = Insn(a, m, None, STOP)
                    fn.insns[a] = ins
                    break
                if a in fn.labels and a != fn.addr:
                    consts = {}
                cs = self.dis.decode(a, m)
                ins = Insn(a, m, cs)
                self.classify(ins)
                fn.insns[a] = ins
                k = ins.kind
                if cs is not None and k in (IJUMP, ICALL) and cs.id in (A.ARM_INS_BX, A.ARM_INS_BLX, A.ARM_INS_MOV) \
                        and cs.operands and cs.operands[-1].type == A.ARM_OP_REG:
                    r = cs.reg_name(cs.operands[-1].reg)
                    if r in consts and cs.operands[-1].shift.type == 0:
                        t = consts[r]
                        if cs.id == A.ARM_INS_MOV:
                            t |= 1 if m == THUMB else 0
                        if self.img.is_code(t & ~1):
                            ins.const_target = t
                            tm = THUMB if t & 1 else ARM
                            if self.in_plt(t & ~1):
                                imp = self.plt_import(t)
                                if isinstance(imp, tuple) and imp[0] == "func":
                                    ins.const_target = imp[1]
                                    tm = THUMB if imp[1] & 1 else ARM
                                else:
                                    ins.plt_import = imp
                            if ins.plt_import is None and not speculative:
                                self.add_entry(ins.const_target & ~1, tm)
                            if k == IJUMP:
                                ins.kind = k = BRANCH
                                ins.tailcall = True
                                ins.target, ins.target_mode = ins.const_target & ~1, tm
                            else:
                                ins.kind = k = CALL
                                ins.target, ins.target_mode = ins.const_target & ~1, tm
                if not speculative:
                    self._track(ins, consts)
                if k == BRANCH:
                    t = ins.target
                    if ins.tailcall or ins.plt_import is not None or (t != fn.addr and t in self.entries) \
                            or not self.img.is_code(t):
                        ins.tailcall = True
                        if ins.plt_import is None and self.img.is_code(t) and not speculative:
                            self.add_entry(t, ins.target_mode)
                    else:
                        fn.labels.add(t)
                        work.append((t, ins.target_mode))
                    if not ins.cond:
                        break
                elif k == CALL:
                    if ins.plt_import is None and not speculative:
                        self.add_entry(ins.target, ins.target_mode)
                    elif ins.plt_import is not None and not isinstance(ins.plt_import, tuple) and \
                            ins.plt_import.name in NORETURN_IMPORTS:
                        break
                elif k == IJUMP:
                    ts = self.resolve_ijump(fn, ins)
                    ins.targets = ts
                    if ts:
                        self.stats["ijump_tables"] += 1
                        for t, tm in ts:
                            fn.labels.add(t)
                            work.append((t, tm))
                    else:
                        fn.unresolved_ijumps += 1
                        self.stats["ijump_unresolved"] += 1
                    if not ins.cond:
                        break
                elif k in (RET, STOP):
                    if not ins.cond:
                        break
                a = ins.next

    def run(self, extra=()):
        self.collect_entries(extra)
        done = set()
        while True:
            pending = [a for a in self.entries if a not in done]
            if not pending:
                break
            for a in sorted(pending):
                done.add(a)
                self.functions[a] = self.build_function(a, self.entries[a])
        # second pass: branches that target entries discovered late become
        # tail calls only if they were not inlined already (inlined copies are
        # harmless duplicates, so nothing to do).
        return self.functions

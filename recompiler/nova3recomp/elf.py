"""Loading of an ARM (armeabi / armeabi-v7a) ELF32 shared object.

Only the information needed for static recompilation is extracted:
segments, dynamic symbols, relocations, PLT stubs, init/fini arrays and the
ARM exception index (a great source of function start addresses even in
fully stripped binaries).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

R_ARM_ABS32 = 2
R_ARM_REL32 = 3
R_ARM_COPY = 20
R_ARM_GLOB_DAT = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23
R_ARM_TLS_DTPMOD32 = 17
R_ARM_TLS_DTPOFF32 = 18
R_ARM_TLS_TPOFF32 = 19
R_ARM_IRELATIVE = 160

RELOC_NAMES = {
    R_ARM_ABS32: "ABS32", R_ARM_REL32: "REL32", R_ARM_COPY: "COPY",
    R_ARM_GLOB_DAT: "GLOB_DAT", R_ARM_JUMP_SLOT: "JUMP_SLOT",
    R_ARM_RELATIVE: "RELATIVE", R_ARM_TLS_DTPMOD32: "TLS_DTPMOD32",
    R_ARM_TLS_DTPOFF32: "TLS_DTPOFF32", R_ARM_TLS_TPOFF32: "TLS_TPOFF32",
}


@dataclass
class Segment:
    vaddr: int
    memsz: int
    offset: int
    filesz: int
    flags: int  # PF_X=1 PF_W=2 PF_R=4

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    type: str      # STT_FUNC / STT_OBJECT / ...
    bind: str
    defined: bool


@dataclass
class Reloc:
    offset: int
    type: int
    sym: Symbol | None
    addend: int = 0


@dataclass
class Import:
    """An undefined dynamic symbol referenced by the module."""
    id: int
    name: str
    is_func: bool
    slots: list[int] = field(default_factory=list)  # GOT addresses


class ElfImage:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        self.sha1 = hashlib.sha1(self.raw).hexdigest()
        import io
        self.elf = ELFFile(io.BytesIO(self.raw))
        if self.elf["e_machine"] != "EM_ARM" or self.elf.elfclass != 32:
            raise ValueError(f"{path}: not an ARM ELF32 file")

        self.segments: list[Segment] = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.segments.append(Segment(seg["p_vaddr"], seg["p_memsz"], seg["p_offset"],
                                             seg["p_filesz"], seg["p_flags"]))
        self.min_vaddr = min(s.vaddr for s in self.segments) & ~0xFFF
        self.max_vaddr = max(s.vaddr + s.memsz for s in self.segments)

        self.sections = {s.name: s for s in self.elf.iter_sections()}
        self._load_symbols()
        self._load_relocs()
        self._build_imports()
        self._load_arrays()
        self._load_exidx()

    # ------------------------------------------------------------- memory
    def seg_for(self, addr: int) -> Segment | None:
        for s in self.segments:
            if s.vaddr <= addr < s.vaddr + s.memsz:
                return s
        return None

    def is_code(self, addr: int) -> bool:
        s = self.seg_for(addr)
        return bool(s and s.executable and addr < s.vaddr + s.filesz)

    def read(self, addr: int, size: int) -> bytes:
        s = self.seg_for(addr)
        if s is None:
            raise IndexError(f"address {addr:#x} not mapped")
        off = addr - s.vaddr
        out = bytearray(size)
        avail = max(0, min(size, s.filesz - off))
        if avail:
            out[:avail] = self.raw[s.offset + off: s.offset + off + avail]
        return bytes(out)

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def u16(self, addr: int) -> int:
        return struct.unpack("<H", self.read(addr, 2))[0]

    def u8(self, addr: int) -> int:
        return self.read(addr, 1)[0]

    def word_after_reloc(self, addr: int) -> tuple[int, str | None]:
        """Value of a 32-bit word after static relocation.

        Returns (value, import_name). For imports the value is meaningless.
        """
        r = self.reloc_at.get(addr)
        raw = self.u32(addr)
        if r is None:
            return raw, None
        if r.type == R_ARM_RELATIVE:
            return raw, None
        if r.type in (R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT):
            if r.sym and r.sym.defined:
                return (r.sym.value + (raw if r.type == R_ARM_ABS32 else 0)) & 0xFFFFFFFF, None
            return 0, r.sym.name if r.sym else None
        return raw, None

    # ------------------------------------------------------------ symbols
    def _load_symbols(self):
        self.dynsyms: list[Symbol] = []
        self.symtab: list[Symbol] = []
        for secname, dest in ((".dynsym", self.dynsyms), (".symtab", self.symtab)):
            sec = self.sections.get(secname)
            if not isinstance(sec, SymbolTableSection):
                continue
            for s in sec.iter_symbols():
                dest.append(Symbol(s.name, s["st_value"], s["st_size"], s["st_info"]["type"],
                                   s["st_info"]["bind"], s["st_shndx"] != "SHN_UNDEF"))
        # $a / $t / $d mapping symbols (only in unstripped files)
        self.mapping: list[tuple[int, str]] = sorted(
            (s.value, s.name[1]) for s in self.symtab
            if s.name in ("$a", "$t", "$d") or s.name.startswith(("$a.", "$t.", "$d.")))

    def _load_relocs(self):
        self.relocs: list[Reloc] = []
        dynsym = self.sections.get(".dynsym")
        cache: dict[int, Symbol] = {}

        def sym(idx: int) -> Symbol | None:
            if idx == 0 or dynsym is None:
                return None
            if idx not in cache:
                s = dynsym.get_symbol(idx)
                cache[idx] = Symbol(s.name, s["st_value"], s["st_size"], s["st_info"]["type"],
                                    s["st_info"]["bind"], s["st_shndx"] != "SHN_UNDEF")
            return cache[idx]

        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            if sec["sh_flags"] & 2 == 0 and sec.name not in (".rel.dyn", ".rel.plt", ".rela.dyn", ".rela.plt"):
                continue  # skip object-file relocs of non-alloc sections
            for r in sec.iter_relocations():
                add = r["r_addend"] if r.is_RELA() else 0
                self.relocs.append(Reloc(r["r_offset"], r["r_info_type"], sym(r["r_info_sym"]), add))
        self.reloc_at = {r.offset: r for r in self.relocs}

    def _build_imports(self):
        self.imports: list[Import] = []
        self.import_by_name: dict[str, Import] = {}
        for r in self.relocs:
            if r.sym is None or r.sym.defined or not r.sym.name:
                continue
            imp = self.import_by_name.get(r.sym.name)
            if imp is None:
                is_func = r.type == R_ARM_JUMP_SLOT or r.sym.type == "STT_FUNC"
                imp = Import(len(self.imports), r.sym.name, is_func)
                self.imports.append(imp)
                self.import_by_name[imp.name] = imp
            if r.type == R_ARM_JUMP_SLOT:
                imp.is_func = True
            imp.slots.append(r.offset)
        # GOT slot -> import
        self.got_import: dict[int, Import] = {}
        for imp in self.imports:
            for s in imp.slots:
                self.got_import[s] = imp

    def _load_arrays(self):
        self.init_array: list[int] = []
        self.fini_array: list[int] = []
        self.dt_init = None
        self.dt_fini = None
        dyn = self.sections.get(".dynamic")
        tags = {}
        if dyn is not None:
            for t in dyn.iter_tags():
                tags.setdefault(t.entry.d_tag, t.entry.d_val)
        self.dt_init = tags.get("DT_INIT")
        self.dt_fini = tags.get("DT_FINI")
        for tag, sz, dest in (("DT_INIT_ARRAY", "DT_INIT_ARRAYSZ", self.init_array),
                              ("DT_FINI_ARRAY", "DT_FINI_ARRAYSZ", self.fini_array)):
            if tag in tags:
                base, n = tags[tag], tags.get(sz, 0)
                for a in range(base, base + n, 4):
                    v, imp = self.word_after_reloc(a)
                    if imp is None and v not in (0, 0xFFFFFFFF):
                        dest.append(v)
        self.dyn_tags = tags

    def _load_exidx(self):
        """Function starts from .ARM.exidx (prel31 encoded)."""
        self.exidx_starts: list[int] = []
        sec = self.sections.get(".ARM.exidx")
        if sec is None:
            for seg in self.elf.iter_segments():
                if seg["p_type"] == "PT_ARM_EXIDX":
                    base, size = seg["p_vaddr"], seg["p_memsz"]
                    break
            else:
                return
        else:
            base, size = sec["sh_addr"], sec["sh_size"]
        for a in range(base, base + size, 8):
            w = self.u32(a)
            off = w & 0x7FFFFFFF
            if off & 0x40000000:
                off -= 0x80000000
            self.exidx_starts.append((a + off) & 0xFFFFFFFF)

    # ---------------------------------------------------------------- misc
    def section_range(self, name: str) -> tuple[int, int] | None:
        s = self.sections.get(name)
        if s is None or s["sh_addr"] == 0:
            return None
        return s["sh_addr"], s["sh_addr"] + s["sh_size"]

    def mapping_mode(self, addr: int) -> str | None:
        """'a', 't' or 'd' according to mapping symbols, if present."""
        if not self.mapping:
            return None
        import bisect
        i = bisect.bisect_right(self.mapping, (addr, "~")) - 1
        return self.mapping[i][1] if i >= 0 else None

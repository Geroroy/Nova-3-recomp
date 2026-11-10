"""Capstone wrapper with IT-block aware Thumb decoding."""
from __future__ import annotations

import capstone
from capstone import arm as A

ARM, THUMB = "arm", "thumb"

REG_NUM = {f"r{i}": i for i in range(13)}
REG_NUM.update({"sb": 9, "sl": 10, "fp": 11, "ip": 12, "sp": 13, "lr": 14, "pc": 15})


def reg_kind(name: str) -> tuple[str, int]:
    """'r0'/'sp' -> ('r', n); 's3' -> ('s', 3); 'd7' -> ('d', 7); 'q2' -> ('q', 2)."""
    if name in REG_NUM:
        return "r", REG_NUM[name]
    if name[0] in "sdq" and name[1:].isdigit():
        return name[0], int(name[1:])
    return name, -1


class Disassembler:
    def __init__(self, image):
        self.image = image
        self.md = {}
        for mode, csmode in ((ARM, capstone.CS_MODE_ARM), (THUMB, capstone.CS_MODE_THUMB)):
            md = capstone.Cs(capstone.CS_ARCH_ARM, csmode | capstone.CS_MODE_V8 * 0)
            md.detail = True
            self.md[mode] = md
        self.cache: dict[tuple[int, str], object] = {}
        self.it_cond: dict[int, bool] = {}   # addr -> True if inside an IT block

    def _read(self, addr: int, n: int) -> bytes:
        try:
            return self.image.read(addr, n)
        except IndexError:
            return b""

    def decode(self, addr: int, mode: str):
        key = (addr, mode)
        if key in self.cache:
            return self.cache[key]
        code = self._read(addr, 4)
        insn = None
        if code:
            for i in self.md[mode].disasm(code, addr, 1):
                insn = i
        if insn is not None and mode == THUMB and insn.id == A.ARM_INS_IT:
            # Re-decode the whole IT block in one go so capstone tracks the
            # IT state (conditions + non-flag-setting 16-bit forms).
            n = len(insn.mnemonic) - 1
            block = list(self.md[mode].disasm(self._read(addr, 2 + 4 * n), addr, 1 + n))
            for j, bi in enumerate(block):
                self.cache[(bi.address, mode)] = bi
                if j:
                    self.it_cond[bi.address] = True
            return block[0]
        self.cache[key] = insn
        return insn

    @staticmethod
    def rname(insn, reg: int) -> str:
        return insn.reg_name(reg)

import argparse
import json
import sys
import time

from .analysis import Analyzer
from .elf import ElfImage
from .emit import emit


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nova3recomp",
                                 description="Statically recompile an armeabi(-v7a) .so into portable C")
    ap.add_argument("input", help="ARM ELF shared object (e.g. libnova3.so from your own APK)")
    ap.add_argument("-o", "--out", required=True, help="output directory for generated C")
    ap.add_argument("--module", default="mod", help="C identifier prefix for the module")
    ap.add_argument("--base", default="0x10000000", help="guest load address (default 0x10000000)")
    ap.add_argument("--funcs-per-file", type=int, default=400)
    ap.add_argument("--entry", action="append", default=[],
                    help="extra function entry, hex address; append 't' for Thumb (e.g. 0x1234t)")
    args = ap.parse_args(argv)

    t0 = time.time()
    img = ElfImage(args.input)
    print(f"[*] {args.input}: {len(img.segments)} segments, {len(img.dynsyms)} dynsyms, "
          f"{len(img.relocs)} relocs, {len(img.imports)} imports, {len(img.exidx_starts)} exidx entries")
    extra = []
    for e in args.entry:
        thumb = e.endswith("t")
        extra.append((int(e.rstrip("ta"), 16), "thumb" if thumb else "arm", None))
    an = Analyzer(img)
    an.run(extra)
    print(f"[*] analysis: {len(an.functions)} functions ({time.time() - t0:.1f}s)")
    stats = emit(img, an, args.out, int(args.base, 0), args.funcs_per_file, args.module)
    print(f"[*] emitted {stats['instructions']} instructions in {time.time() - t0:.1f}s")
    if stats["unsupported"]:
        print("[!] unsupported instructions (see report):")
        for k, v in list(stats["unsupported"].items())[:30]:
            print(f"      {k:12s} {v}")
    print(f"[*] indirect jumps: {stats['ijump_tables']} tables resolved, {stats['ijump_unresolved']} unresolved")
    return 0


if __name__ == "__main__":
    sys.exit(main())

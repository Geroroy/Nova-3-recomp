#!/usr/bin/env python3
"""Inspect an Android APK (your own copy) for a static recompilation port.

    python3 tools/apk_inspect.py NOVA3.apk -o build/inspect

Produces:
  - <out>/lib/<abi>/*.so          extracted native libraries
  - <out>/natives.json            Java `native` methods (class, name, JNI signature)
  - <out>/report.md               ABIs, manifest info, JNI usage, imported APIs

Nothing is uploaded anywhere; everything stays on your machine.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recompiler"))


# ----------------------------------------------------------------- dex
def uleb(data: bytes, off: int) -> tuple[int, int]:
    r = shift = 0
    while True:
        b = data[off]
        off += 1
        r |= (b & 0x7F) << shift
        if b < 0x80:
            return r, off
        shift += 7


def dex_natives(data: bytes) -> list[dict]:
    """All methods with ACC_NATIVE in a classes.dex file."""
    if not data.startswith(b"dex\n"):
        return []
    (string_ids_size, string_ids_off, type_ids_size, type_ids_off, proto_ids_size, proto_ids_off,
     field_ids_size, field_ids_off, method_ids_size, method_ids_off, class_defs_size,
     class_defs_off) = struct.unpack_from("<12I", data, 0x38)

    def string(i):
        off = struct.unpack_from("<I", data, string_ids_off + 4 * i)[0]
        _, p = uleb(data, off)
        e = data.index(b"\0", p)
        return data[p:e].decode("utf-8", "replace")

    def type_name(i):
        return string(struct.unpack_from("<I", data, type_ids_off + 4 * i)[0])

    def proto(i):
        shorty, ret, params = struct.unpack_from("<III", data, proto_ids_off + 12 * i)
        args = []
        if params:
            n = struct.unpack_from("<I", data, params)[0]
            for k in range(n):
                args.append(type_name(struct.unpack_from("<H", data, params + 4 + 2 * k)[0]))
        return "(" + "".join(args) + ")" + type_name(ret)

    def method(i):
        cls, pr, name = struct.unpack_from("<HHI", data, method_ids_off + 8 * i)
        return type_name(cls), string(name), proto(pr)

    out = []
    for c in range(class_defs_size):
        base = class_defs_off + 32 * c
        class_data_off = struct.unpack_from("<I", data, base + 24)[0]
        if not class_data_off:
            continue
        p = class_data_off
        sf, p = uleb(data, p)
        inf, p = uleb(data, p)
        dm, p = uleb(data, p)
        vm, p = uleb(data, p)
        for _ in range(sf + inf):
            _, p = uleb(data, p)
            _, p = uleb(data, p)
        for count, static in ((dm, True), (vm, False)):
            idx = 0
            for _ in range(count):
                d, p = uleb(data, p)
                flags, p = uleb(data, p)
                _, p = uleb(data, p)
                idx += d
                if flags & 0x100:
                    cls, name, sig = method(idx)
                    out.append({"class": cls[1:-1], "name": name, "sig": sig,
                                "static": bool(flags & 0x8)})
    return out


def jni_mangle(s: str) -> str:
    out = []
    for ch in s:
        if ch == "/":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch.isalnum() and ord(ch) < 128:
            out.append(ch)
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


# ------------------------------------------------------- binary XML (AXML)
def axml_attrs(data: bytes) -> list[tuple[str, dict]]:
    """Minimal AndroidManifest.xml (binary) reader: [(tag, {attr: value})]."""
    strings: list[str] = []
    out = []
    off = 8
    while off + 8 <= len(data):
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize == 0:
            break
        if ctype == 0x0001:  # string pool
            n, _, flags, sstart, _ = struct.unpack_from("<IIIII", data, off + 8)
            utf8 = flags & 0x100
            offs = struct.unpack_from(f"<{n}I", data, off + 28)
            for so in offs:
                p = off + sstart + so
                if utf8:
                    l1 = data[p]; p += 2 if l1 & 0x80 else 1
                    l = data[p]
                    if l & 0x80:
                        l = ((l & 0x7F) << 8) | data[p + 1]; p += 2
                    else:
                        p += 1
                    strings.append(data[p:p + l].decode("utf-8", "replace"))
                else:
                    l = struct.unpack_from("<H", data, p)[0]; p += 2
                    if l & 0x8000:
                        l = ((l & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
                    strings.append(data[p:p + 2 * l].decode("utf-16le", "replace"))
        elif ctype == 0x0102:  # start tag
            name_i = struct.unpack_from("<I", data, off + 20)[0]
            astart, asize, acount = struct.unpack_from("<HHH", data, off + 24)
            attrs = {}
            for k in range(acount):
                a = off + 16 + astart + k * asize
                _, aname, araw, _, _, dtype, dval = struct.unpack_from("<IIIHBBI", data, a)
                key = strings[aname] if aname < len(strings) else str(aname)
                if araw != 0xFFFFFFFF and araw < len(strings):
                    attrs[key] = strings[araw]
                elif dtype == 0x03 and dval < len(strings):
                    attrs[key] = strings[dval]
                else:
                    attrs[key] = dval
            out.append((strings[name_i] if name_i < len(strings) else "?", attrs))
        off += csize
    return out


# ---------------------------------------------------------- .so strings
JNI_CLASS_RE = re.compile(rb"(?:[a-zA-Z_$][a-zA-Z0-9_$]*/){1,8}[A-Za-z_$][A-Za-z0-9_$]*")
JNI_SIG_RE = re.compile(rb"\((?:\[*(?:[ZBCSIJFDV]|L[A-Za-z0-9_/$]+;))*\)\[*(?:[ZBCSIJFDV]|L[A-Za-z0-9_/$]+;)")

API_PREFIXES = [("OpenGL ES", ("gl",)), ("EGL", ("egl",)), ("OpenSL ES", ("sl", "SL_")),
                ("Android native", ("ANativeWindow", "AAsset", "AInput", "ALooper", "AConfiguration")),
                ("pthread", ("pthread_", "sem_")), ("libc++/stdc++", ("_Z",))]


def so_report(path: str) -> dict:
    from nova3recomp.elf import ElfImage
    data = open(path, "rb").read()
    info = {"size": len(data)}
    try:
        img = ElfImage(path)
    except Exception as e:  # not ARM32
        info["error"] = str(e)
        return info
    info["imports"] = sorted(i.name for i in img.imports)
    info["exports_jni"] = sorted(s.name for s in img.dynsyms if s.defined and s.name.startswith(("Java_", "JNI_On")))
    info["needed"] = [t.needed for t in img.elf.get_section_by_name(".dynamic").iter_tags()
                      if t.entry.d_tag == "DT_NEEDED"] if img.elf.get_section_by_name(".dynamic") else []
    classes = set()
    for m in JNI_CLASS_RE.finditer(data):
        s = m.group().decode()
        if s.count("/") >= 1 and s.split("/")[0] in ("com", "java", "android", "org", "net", "dalvik", "javax"):
            classes.add(s)
    info["java_classes"] = sorted(classes)
    info["jni_signatures"] = sorted({m.group().decode() for m in JNI_SIG_RE.finditer(data)})
    groups = {}
    for imp in info["imports"]:
        for gname, pre in API_PREFIXES:
            if imp.startswith(pre):
                groups.setdefault(gname, []).append(imp)
                break
        else:
            groups.setdefault("libc / other", []).append(imp)
    info["import_groups"] = groups
    info["thumb_funcs"] = sum(1 for s in img.dynsyms if s.defined and s.type == "STT_FUNC" and s.value & 1)
    info["arm_funcs"] = sum(1 for s in img.dynsyms if s.defined and s.type == "STT_FUNC" and not s.value & 1)
    info["exidx_entries"] = len(img.exidx_starts)
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk")
    ap.add_argument("-o", "--out", default="build/inspect")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    z = zipfile.ZipFile(args.apk)
    names = z.namelist()
    libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    abis = sorted({n.split("/")[1] for n in libs})
    rep = [f"# APK inspection: {os.path.basename(args.apk)}\n"]

    if "AndroidManifest.xml" in names:
        tags = axml_attrs(z.read("AndroidManifest.xml"))
        for tag, attrs in tags:
            if tag == "manifest":
                rep.append(f"- package: `{attrs.get('package')}` versionName: `{attrs.get('versionName')}` "
                           f"versionCode: `{attrs.get('versionCode')}`")
            elif tag == "uses-sdk":
                rep.append(f"- minSdk: {attrs.get('minSdkVersion')}  targetSdk: {attrs.get('targetSdkVersion')}")
        acts = [a.get("name") for t, a in tags if t == "activity"]
        rep.append(f"- activities: {', '.join(f'`{a}`' for a in acts[:12])}")
        perms = [a.get("name") for t, a in tags if t == "uses-permission"]
        rep.append(f"- permissions: {', '.join(p.split('.')[-1] for p in perms if isinstance(p, str))}")
        gl = [a for t, a in tags if t == "uses-feature" and "glEsVersion" in a]
        if gl:
            v = gl[0]["glEsVersion"]
            rep.append(f"- OpenGL ES required: {v >> 16}.{v & 0xffff}" if isinstance(v, int) else f"- glEsVersion: {v}")
    rep.append(f"- native ABIs: {', '.join(abis) or 'none'}")
    if "arm64-v8a" in abis:
        rep.append("\n> **This APK already ships arm64-v8a libraries.** It should run natively on 64-bit-only "
                   "devices without recompilation.\n")
    obbs = [n for n in names if n.endswith(".obb")]
    big = sorted(((z.getinfo(n).file_size, n) for n in names), reverse=True)[:8]
    rep.append("- largest entries: " + ", ".join(f"`{n}` ({s // 1024} KiB)" for s, n in big))
    if obbs:
        rep.append(f"- embedded OBB: {obbs}")

    natives = []
    for n in names:
        if re.fullmatch(r"classes\d*\.dex", n):
            natives += dex_natives(z.read(n))
    for m in natives:
        m["symbol"] = "Java_" + jni_mangle(m["class"]) + "_" + jni_mangle(m["name"])
    json.dump(natives, open(os.path.join(args.out, "natives.json"), "w"), indent=1)
    rep.append(f"\n## Java native methods ({len(natives)})\n")
    for m in natives[:400]:
        rep.append(f"- `{m['class'].replace('/', '.')}.{m['name']}{m['sig']}`{' static' if m['static'] else ''}")

    for lib in libs:
        abi = lib.split("/")[1]
        dst = os.path.join(args.out, lib)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(z.read(lib))
        if abi not in ("armeabi", "armeabi-v7a"):
            continue
        info = so_report(dst)
        rep.append(f"\n## {lib} ({info['size'] // 1024} KiB)\n")
        if "error" in info:
            rep.append(f"error: {info['error']}")
            continue
        rep.append(f"- DT_NEEDED: {', '.join(info['needed'])}")
        rep.append(f"- exported functions: {info['thumb_funcs']} Thumb, {info['arm_funcs']} ARM; "
                   f"{info['exidx_entries']} unwind entries")
        rep.append(f"- JNI exports: {', '.join(f'`{e}`' for e in info['exports_jni'][:60])}")
        defined = {m['symbol'] for m in natives}
        missing = [m for m in natives if m["symbol"] not in info["exports_jni"]]
        if natives:
            rep.append(f"- Java natives not exported by this lib (RegisterNatives or other lib): {len(missing)}")
        rep.append("\n### Imported APIs\n")
        for g, lst in sorted(info["import_groups"].items()):
            rep.append(f"- **{g}** ({len(lst)}): " + ", ".join(f"`{x}`" for x in lst[:80]) + (" ..." if len(lst) > 80 else ""))
        rep.append("\n### Java classes referenced from native code\n")
        rep.append(", ".join(f"`{c}`" for c in info["java_classes"][:200]))
        rep.append("\n### JNI method signatures found in native code\n")
        rep.append(", ".join(f"`{s}`" for s in info["jni_signatures"][:200]))
        del defined
    open(os.path.join(args.out, "report.md"), "w").write("\n".join(rep) + "\n")
    print("\n".join(rep[:12]))
    print(f"\n[*] full report: {os.path.join(args.out, 'report.md')}")


if __name__ == "__main__":
    main()

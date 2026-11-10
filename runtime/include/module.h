/* Description of a recompiled guest module, emitted by nova3recomp. */
#ifndef NOVA3_MODULE_H
#define NOVA3_MODULE_H
#include "recomp.h"

typedef struct { uint32_t addr; guest_fn fn; } FuncEntry;
typedef struct { uint32_t vaddr, memsz, offset, filesz, flags; } SegmentInfo;
typedef struct { uint32_t offset; uint32_t type; int32_t import_id; uint32_t symval; int32_t addend; } RelocInfo;
typedef struct { const char *name; int is_func; } ImportInfo;
typedef struct { const char *name; uint32_t value; int is_func; uint32_t size; } ExportInfo;

typedef struct ModuleInfo {
    const char *module;
    const char *filename;
    const char *sha1;
    uint32_t base;
    uint32_t min_vaddr, max_vaddr;
    const FuncEntry *funcs;     uint32_t nfuncs;
    const SegmentInfo *segs;    uint32_t nsegs;
    const RelocInfo *relocs;    uint32_t nrelocs;
    const ImportInfo *imports;  uint32_t nimports;
    const ExportInfo *exports;  uint32_t nexports;
    const uint32_t *init_array; uint32_t ninit;
    uint32_t dt_init;
    guest_fn *import_fns;
} ModuleInfo;
#endif

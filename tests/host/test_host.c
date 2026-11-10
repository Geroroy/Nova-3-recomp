/* Host test driver: load a recompiled module and run its test_main(). */
#include <stdio.h>
#include <stdlib.h>
#include "runtime.h"

extern const ModuleInfo mod_module;

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s original.so\n", argv[0]); return 2; }
    if (rt_load_module_file(&mod_module, argv[1])) return 1;
    rt_run_initializers(&mod_module);
    uint32_t entry = rt_module_symbol(&mod_module, "test_main");
    if (!entry) { fprintf(stderr, "test_main not exported\n"); return 1; }
    int r = (int)guest_call0(entry);
    fflush(stdout);
    return r;
}

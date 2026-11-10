/* Host side of the ISA fuzzer: run the recompiled test_fn on the same input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

extern const ModuleInfo mod_module;

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    rt_load_module_file(&mod_module, argv[1]);
    uint32_t fn = rt_module_symbol(&mod_module, "test_fn");
    uint32_t in = rt_module_symbol(&mod_module, "state_in");
    uint32_t out = rt_module_symbol(&mod_module, "state_out");
    uint32_t size = rt_module_symbol(&mod_module, "state_size");
    uint32_t n = LD32(size);
    guest_call2(fn, in, out);
    fwrite(G2H(out), 1, n, stdout);
    return 0;
}

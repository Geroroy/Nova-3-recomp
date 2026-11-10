#include "runtime.h"

void rt_libc_string_init(void);
void rt_libc_stdio_init(void);
void rt_libc_posix_init(void);
void rt_libc_pthread_init(void);
void rt_libc_math_init(void);

void rt_libc_init(void) {
    rt_libc_string_init();
    rt_libc_stdio_init();
    rt_libc_posix_init();
    rt_libc_pthread_init();
    rt_libc_math_init();
}

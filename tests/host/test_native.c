#include <stdio.h>
int test_main(void);
int main(void) { int r = test_main(); fflush(stdout); return r; }

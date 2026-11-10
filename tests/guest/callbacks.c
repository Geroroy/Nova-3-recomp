#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>

typedef struct Node { int key; char name[12]; struct Node *next; } Node;

static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static int cmp_node(const void *a, const void *b) { return strcmp(((const Node *)a)->name, ((const Node *)b)->name); }

__attribute__((noinline)) int my_log(char *out, int cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, cap, fmt, ap);
    va_end(ap);
    return n;
}

__attribute__((noinline)) int sum_va(int n, ...) {
    va_list ap; va_start(ap, n);
    int s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, int) * (i + 1);
    double d = va_arg(ap, double);
    va_end(ap);
    return s + (int)(d * 10);
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int counter;
static void *worker(void *arg) {
    int id = (int)(long)arg;
    for (int i = 0; i < 10000; i++) { pthread_mutex_lock(&lock); counter += id; pthread_mutex_unlock(&lock); }
    return (void *)(long)(id * 2);
}

int test_main(void) {
    int arr[50];
    for (int i = 0; i < 50; i++) arr[i] = (i * 7919 + 13) % 997;
    qsort(arr, 50, sizeof(int), cmp_int);
    for (int i = 0; i < 50; i += 5) printf("%d ", arr[i]);
    printf("\n");
    int key = arr[17];
    int *f = bsearch(&key, arr, 50, sizeof(int), cmp_int);
    printf("bsearch idx=%d\n", f ? (int)(f - arr) : -1);
    Node nodes[6];
    const char *names[6] = {"zeta", "alpha", "mike", "bravo", "yankee", "echo"};
    for (int i = 0; i < 6; i++) { nodes[i].key = i; strcpy(nodes[i].name, names[i]); }
    qsort(nodes, 6, sizeof(Node), cmp_node);
    for (int i = 0; i < 6; i++) printf("%s:%d ", nodes[i].name, nodes[i].key);
    printf("\n");
    Node *head = NULL;
    for (int i = 0; i < 1000; i++) {
        Node *n = malloc(sizeof *n);
        n->key = i * i % 1009; snprintf(n->name, sizeof n->name, "n%d", i); n->next = head; head = n;
    }
    long total = 0; int cnt = 0;
    while (head) { Node *n = head; head = n->next; total += n->key; cnt += (int)strlen(n->name); free(n); }
    printf("list total=%ld cnt=%d\n", total, cnt);
    char buf[64];
    int n = my_log(buf, sizeof buf, "x=%d y=%s z=%.2f w=%lld", 7, "str", 2.5, 1234567890123ll);
    printf("%s (%d)\n", buf, n);
    printf("sum_va=%d\n", sum_va(5, 1, 2, 3, 4, 5, 3.25));
    void *big = malloc(1 << 20);
    memset(big, 0xab, 1 << 20);
    big = realloc(big, 3 << 20);
    printf("big=%x\n", ((unsigned char *)big)[12345]);
    free(big);
    pthread_t th[4];
    for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, worker, (void *)(long)(i + 1));
    int rs = 0;
    for (int i = 0; i < 4; i++) { void *r; pthread_join(th[i], &r); rs += (int)(long)r; }
    printf("threads counter=%d rs=%d\n", counter, rs);
    return 0;
}

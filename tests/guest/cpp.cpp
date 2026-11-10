#include <stdio.h>
#include <string.h>
#include <new>

struct Shape {
    virtual ~Shape() {}
    virtual float area() const = 0;
    virtual const char *name() const { return "shape"; }
};
struct Rect : Shape {
    float w, h;
    Rect(float w, float h) : w(w), h(h) {}
    float area() const override { return w * h; }
    const char *name() const override { return "rect"; }
};
struct Circle : Shape {
    float r;
    explicit Circle(float r) : r(r) {}
    float area() const override { return 3.14159265f * r * r; }
    const char *name() const override { return "circle"; }
};

template <typename T, int N> struct Ring {
    T data[N]; int head = 0, size = 0;
    void push(const T &v) { data[(head + size) % N] = v; if (size < N) size++; else head = (head + 1) % N; }
    T sum() const { T s = T(); for (int i = 0; i < size; i++) s += data[(head + i) % N]; return s; }
};

struct Global {
    int value;
    Global() : value(0) { for (int i = 1; i <= 10; i++) value += i * i; }
};
static Global g_global;

extern "C" int test_main(void) {
    printf("global ctor=%d\n", g_global.value);
    Shape *shapes[6];
    for (int i = 0; i < 6; i++) {
        if (i & 1) shapes[i] = new Circle(i * 0.5f);
        else shapes[i] = new Rect(i + 1.0f, 2.0f);
    }
    float total = 0;
    for (int i = 0; i < 6; i++) { printf("%s %.3f\n", shapes[i]->name(), shapes[i]->area()); total += shapes[i]->area(); }
    for (int i = 0; i < 6; i++) delete shapes[i];
    printf("total=%.3f\n", total);
    Ring<int, 7> ring;
    for (int i = 0; i < 20; i++) ring.push(i * 3);
    Ring<double, 4> rd;
    for (int i = 0; i < 9; i++) rd.push(i * 0.75);
    printf("ring=%d %.2f\n", ring.sum(), rd.sum());
    int *arr = new int[100];
    for (int i = 0; i < 100; i++) arr[i] = i * i;
    long s = 0; for (int i = 0; i < 100; i++) s += arr[i];
    delete[] arr;
    printf("arr=%ld\n", s);
    return 0;
}

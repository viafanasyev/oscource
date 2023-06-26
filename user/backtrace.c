/* program to cause a breakpoint trap */

#include <inc/lib.h>

typedef const int myint;

struct NestedStruct {
    uint64_t x;
};

struct SomeStruct {
    int x;
    char c;
    const char *str;
    struct NestedStruct nested;
};

struct OtherStruct {
    uint64_t x;
    uint64_t y;
};

void
breakpoint() {
    asm volatile("int $3");
}

void
fourth(
    uint64_t a,
    int b,
    ...
) {
    breakpoint();
}

void
third(
    struct SomeStruct s
) {
    fourth(123, 456, 0, 1, 2);
}

void
second(
    void* ptr1,
    void* ptr2
) {
    struct SomeStruct s = { 456, 'a', "hello", { 42 } };
    third(s);
}

void
first(
    const char * const * const const_ptr_const_ptr_const_char
) {
    second((void*) 0xDEADBEEF, (void*) 0xCAFEBABE);
}

const char *global_str = "123";

void
umain(int argc, char **argv) {
    first(&global_str);
}

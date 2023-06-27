#include <inc/lib.h>

typedef const int myint;

typedef myint* myptr;

enum SomeEnum {
    A,
    B,
    C,
    D,
};

union SomeUnion {
    void* x;
    uint8_t y[8];
};

struct NestedStruct {
    uint64_t x;
};

struct SomeStruct {
    int x;
    float y;
    struct NestedStruct nested;
};

int
some_func(int x, char y) {
    static int static_var = 123;
    static_var++;
    int local_var = 456;
    local_var++;
    return x + static_var + local_var + y;
}

int64_t global_int = -123;
myint global_myint = -456;
myptr global_myptr = &global_myint;
unsigned int global_uint = 321;
const int64_t * const global_ptr = &global_int;
const void * const global_void_ptr = &global_int;
struct SomeStruct global_struct = { 456, 7.89, { 42 } };
struct SomeStruct *global_struct_ptr = &global_struct;
int global_arr[3] = { 1, 2, 3 };
int global_2arr[3][3] = { { 1, 2, 3 }, { 4, 5, 6 }, { 7, 8, 9 } };
int (*global_func_ptr)(int, char) = &some_func;
const char* global_str = "Hello";
const char global_c = 'a';
const char* global_cptr = &global_c;
enum SomeEnum global_enum = C;
union SomeUnion global_union = { (void*)0x00FF00FF };
volatile int64_t global_volatile = 42;
int64_t * restrict global_restrict = NULL;

void
umain(int argc, char **argv) {
    asm volatile("int $3");
}

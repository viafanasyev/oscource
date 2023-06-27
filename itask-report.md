## Backtrace с типизированными аргументами

### Печать глобальных переменных

Для печати глобальных переменных добавлена команда монитора `print_var`.

Поддерживаются следующие типы:
* Целые и вещественные числа
* Структуры
* Массивы
* Перечисления (как значения типа `unsigned`)
* `Union`'ы
* `void`
* `bool`
* Указатели (в т.ч. указатели на функции)
* Модификаторы `const`, `volatile`, `restrict` (модификатор `_Atomic` не поддерживается, т.к. отсутствует в DWARF 4)
* `Typedef` на вышеуказанные типы
* Анонимные вложенные структуры и `union`'ы

При чтении из DWARF, для каждой переменной создаётся структура, хранящая информацию об этой переменной:
```c
struct Dwarf_VarInfo {
    /* Для глобальных переменных - адрес этой переменной в памяти
     * Для полей структур - смещение относительно адреса родителя
     * Для аргументов функций - смещение относительно RBP этой функции
     * В остальных случаях - 0
     */
    int64_t address;

    /* Имя переменной */
    char name[DWARF_BUFSIZ];
 
    /*
     * Вид переменной (см. ниже)
     */
    enum Dwarf_VarKind kind;

    /* Размер типа в байтах */
    uint8_t byte_size;

    /* Полное имя типа переменной */
    char type_name[DWARF_BUFSIZ];

    /* Variadic-параметр функции? */
    bool is_variadic;

    /* Для структур и union'ов - информация о полях
     * Для указателей и массивов - fields[0] содержит нижележащий тип
     */
    struct Dwarf_VarInfo **fields;
};
```

Для корректного вывода значений, нужно отличать виды типов переменных. Имеются следующие виды:
```c
enum Dwarf_VarKind {
    KIND_UNKNOWN,        /* Неизвестный тип */
    KIND_SIGNED_INT,     /* Знаковое целое число */
    KIND_UNSIGNED_INT,   /* Беззнаковое целое число или значение перечисления */
    KIND_FLOATING_POINT, /* Вещественное число */
    KIND_POINTER,        /* Указатель */
    KIND_STRUCT,         /* Структура или union */
    KIND_ARRAY,          /* Массив любой размерности */
};
```

Вывод значения переменной осуществляется в соответствии с её видом (`kind`) и размером (`byte_size`).

Все модификаторы печатаются справа-налево, без сохранения их оригинального порядка.
Т.е. при печати тип `const char* const` прерватится в `char const* const`.

Для печати вещественных чисел была расширена команда `cprintf`.
Используется самый простой формат вывода с последовательным умножением вещественной части на 10
и выводом каждого разряда как целого числа, из-за чего числа выводятся довольно неточно.

Примеры вывода:
```
K> print_var global_int
int global_int = 123;

K> print_var global_str
char const* global_str = 0x008043c8

K> print_var global_enum
SomeEnum global_enum = 2;

K> print_var global_struct
SomeStruct global_struct = {
        int x = 456
        float y = 7.889999866485595703
        NestedStruct nested = {
                uint64_t x = 42
        }
}

K> print_var global_page
Page global_page = {
        <anonymous union> <unnamed field> = {
                <anonymous struct> <unnamed field> = {
                        uint32_t refc = 0
                        uintptr_t class = 0
                        uintptr_t addr = 0
                }
                Page* phy = 0x00000000
        }
}

```

Значения N-мерных массивов выводятся как одномерные:
```
K> print_var global_2arr
int[3][3] global_2arr = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }
```

Также существует возможность вывода значения по указателю:
```
K> print_var *global_ptr
int* *global_ptr = 123;

K> print_var *curenv
Env* *curenv = {
        Trapframe env_tf = {
                PushRegs tf_regs = {
                        uint64_t reg_r15 = 0
                        uint64_t reg_r14 = 0
                        uint64_t reg_r13 = 0
                        uint64_t reg_r12 = 0
                        uint64_t reg_r11 = 0
                        uint64_t reg_r10 = 0
                        uint64_t reg_r9 = 0
                        uint64_t reg_r8 = 0
                        uint64_t reg_rsi = 0
                        uint64_t reg_rdi = 0
                        uint64_t reg_rbp = 549755776944
                        uint64_t reg_rdx = 550288490800
                        uint64_t reg_rcx = 18446744073709551296
                        uint64_t reg_rbx = 0
                        uint64_t reg_rax = 8388752
                }
                uint16_t tf_es = 51
                uint16_t tf_padding1 = 16893
                uint32_t tf_padding2 = 128
                uint16_t tf_ds = 51
                uint16_t tf_padding3 = 16739
                uint32_t tf_padding4 = 0
                uint64_t tf_trapno = 3
                uint64_t tf_err = 0
                uintptr_t tf_rip = 8388768
                uint16_t tf_cs = 43
                uint16_t tf_padding5 = 0
                uint32_t tf_padding6 = 0
                uint64_t tf_rflags = 518
                uintptr_t tf_rsp = 549755776928
                uint16_t tf_ss = 51
                uint16_t tf_padding7 = 0
                uint32_t tf_padding8 = 0
        }
        Env* env_link = 0x8020605260
        envid_t env_id = 4097
        envid_t env_parent_id = 0
        EnvType env_type = 2
        unsigned int env_status = 3
        uint32_t env_runs = 2
        uint8_t* binary = 0x8041f9d938
        AddressSpace address_space = {
                pml4e_t* pml4 = 0x805e781000
                uintptr_t cr3 = 511184896
                Page* root = 0x805e7870d0
        }
        void* env_pgfault_upcall = 0x00000000
        _Bool env_ipc_recving = 0
        uintptr_t env_ipc_dstva = 0
        size_t env_ipc_maxsz = 0
        uint32_t env_ipc_value = 0
        envid_t env_ipc_from = 0
        int env_ipc_perm = 0
}
```

> Добавить поддержку разыменования N уровней указателей довольно просто, слегка модифицировав код в `kern/monitor.c:mon_print_var`.

### Печать типов и значений аргументов в backtrace

В качестве типов поддерживаются те же типы, что и в команде `print_var`.

В случае с GCC, поддерживаются безымянные аргументы.

Variadic-аргументы печатаются как `...`, их значения не выводятся.

Адреса, по которым находятся значения аргументов, читаются из DWARF. Поддерживаются два формата:
* Смещение относительно адреса `rbp` (`DW_AT_frame_base` = `DW_OP_reg6`). Генерируется Clang.
* Смещение относительно стекового фрейма (`DW_AT_frame_base` = `DW_OP_call_frame_cfa`). Генерируется GCC.

Формат вывода схож с выводом команды `bt` в `gdb`. Пример:
```
  ...
  rbp 0x0000007fffff6ec0  rip 0x000000000080005d
    0x0000000000000030 in fourth (uint64_t a=123, int b=456, ...) at user/backtrace.c:34
  rbp 0x0000007fffff6f10  rip 0x0000000000800090
    0x0000000000000030 in third (SomeStruct s={ int x = 456; char c = 97; char const* str = 0x008043c8; NestedStruct nested = { uint64_t x = 42 } }) at user/backtrace.c:41
  rbp 0x0000007fffff6f20  rip 0x00000000008000d9
    0x0000000000000046 in second (void* ptr1=0xdeadbeef, void* ptr2=0xcafebabe) at user/backtrace.c:50
  rbp 0x0000007fffff6f78  rip 0x0000000000800108
    0x0000000000000028 in first (char const* const* const const_ptr_const_ptr_const_char=0x00805000) at user/backtrace.c:57
  ...
```

### Тестирование

Добавлено несколько тестов, запускающихся через `make test-itask`.
В качестве тестовых программ используются `user/printvar.c` и `user/backtrace.c`.

Тест для `user/backtrace.c` проверяет корректность трассы, имён функций и параметров, значений аргументов.

Тесты для `user/printvar.c` проверяют корректность типов и значений глобальных переменных для:
* Целых чисел
* `Typedef` на целые числа
* Указателей на целые числа и их разыменования
* Вещественных чисел
* Структур и вложенных структур
* Указателей на структуры и их разыменования
* Одномерных и двумерных массивов
* `Union`'ов
* Перечислений
* Типа `void`
* `Typedef` на указатели и их разыменования
* Модификаторов `const`, `volatile`, `restrict`
* Анонимных вложенных структур и `union`'ов

Также этот тест проверяет, что локальные (в т.ч. static) переменные не выводятся.
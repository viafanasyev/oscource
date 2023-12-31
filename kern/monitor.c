/* Simple command-line kernel monitor useful for
 * controlling the kernel and exploring the system interactively. */

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/env.h>
#include <inc/x86.h>
#include <inc/dwarf.h>
#include <inc/error.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/tsc.h>
#include <kern/timer.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/kclock.h>
#include <kern/allocator.h>

#define WHITESPACE "\t\r\n "
#define MAXARGS    16

/* Functions implementing monitor commands */
int mon_help(int argc, char **argv, struct Trapframe *tf);
int mon_kerninfo(int argc, char **argv, struct Trapframe *tf);
int mon_backtrace(int argc, char **argv, struct Trapframe *tf);
int mon_hello(int argc, char **argv, struct Trapframe *tf);
int mon_dumpcmos(int argc, char **argv, struct Trapframe *tf);
int mon_start(int argc, char **argv, struct Trapframe *tf);
int mon_stop(int argc, char **argv, struct Trapframe *tf);
int mon_frequency(int argc, char **argv, struct Trapframe *tf);
int mon_memory(int argc, char **argv, struct Trapframe *tf);
int mon_pagetable(int argc, char **argv, struct Trapframe *tf);
int mon_virt(int argc, char **argv, struct Trapframe *tf);
int mon_print_var(int argc, char **argv, struct Trapframe *tf);

struct Command {
    const char *name;
    const char *desc;
    /* return -1 to force monitor to exit */
    int (*func)(int argc, char **argv, struct Trapframe *tf);
};

static struct Command commands[] = {
        {"help", "Display this list of commands", mon_help},
        {"kerninfo", "Display information about the kernel", mon_kerninfo},
        {"backtrace", "Print stack backtrace", mon_backtrace},
        {"hello", "Print 'Hello'", mon_hello},
        {"dumpcmos", "Print CMOS contents", mon_dumpcmos},
        {"timer_start", "Start timer", mon_start},
        {"timer_stop", "Stop timer and print seconds elapsed", mon_stop},
        {"timer_freq", "Print timer frequency", mon_frequency},
        {"memory", "Display free memory pages", mon_memory},
        {"virt", "Display virtual memory tree", mon_virt},
        {"pagetable", "Display page table", mon_pagetable},
        {"print_var", "Print value of the global variable", mon_print_var},
};
#define NCOMMANDS (sizeof(commands) / sizeof(commands[0]))

/* Implementations of basic kernel monitor commands */

int
mon_help(int argc, char **argv, struct Trapframe *tf) {
    for (size_t i = 0; i < NCOMMANDS; i++)
        cprintf("%s - %s\n", commands[i].name, commands[i].desc);
    return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf) {
    extern char _head64[], entry[], etext[], edata[], end[];

    cprintf("Special kernel symbols:\n");
    cprintf("  _head64 %16lx (virt)  %16lx (phys)\n", (unsigned long)_head64, (unsigned long)_head64);
    cprintf("  entry   %16lx (virt)  %16lx (phys)\n", (unsigned long)entry, (unsigned long)entry - KERN_BASE_ADDR);
    cprintf("  etext   %16lx (virt)  %16lx (phys)\n", (unsigned long)etext, (unsigned long)etext - KERN_BASE_ADDR);
    cprintf("  edata   %16lx (virt)  %16lx (phys)\n", (unsigned long)edata, (unsigned long)edata - KERN_BASE_ADDR);
    cprintf("  end     %16lx (virt)  %16lx (phys)\n", (unsigned long)end, (unsigned long)end - KERN_BASE_ADDR);
    cprintf("Kernel executable memory footprint: %luKB\n", (unsigned long)ROUNDUP(end - entry, 1024) / 1024);
    return 0;
}

static void
free_var_info(struct Dwarf_VarInfo *var_info) {
    if (var_info == NULL || var_info->fields == NULL) return;

    size_t i = 0;
    struct Dwarf_VarInfo *current_field = var_info->fields[0];
    while (i < DWARF_MAX_STRUCT_FIELDS && current_field) {
        free_var_info(current_field);
        ++i;
        free(current_field);
        current_field = var_info->fields[i];
    }
    free(var_info->fields);
}

static void
print_var(struct Dwarf_VarInfo *var_info, bool with_deref, uint8_t depth, uintptr_t base_address, bool inline_str);

static void
print_var_value(struct Dwarf_VarInfo *var_info, bool with_deref, uint8_t depth, uintptr_t base_address, bool inline_str);

static void
print_var_value_by_address(struct Dwarf_VarInfo *var_info, bool with_deref, uint8_t depth, uintptr_t address, bool inline_str) {
    if (address == 0) {
        goto unknown_kind;
    }

    switch (var_info->kind) {
    case KIND_SIGNED_INT:
        switch (var_info->byte_size) {
        case sizeof(int8_t):
            cprintf("%d", *(int8_t *)address);
            break;
        case sizeof(int16_t):
            cprintf("%d", *(int16_t *)address);
            break;
        case sizeof(int32_t):
            cprintf("%d", *(int32_t *)address);
            break;
        case sizeof(int64_t):
            cprintf("%ld", *(int64_t *)address);
            break;
        default:
            goto unknown_kind;
        }
        break;
    case KIND_UNSIGNED_INT:
        switch (var_info->byte_size) {
        case sizeof(uint8_t):
            cprintf("%u", *(uint8_t *)address);
            break;
        case sizeof(uint16_t):
            cprintf("%u", *(uint16_t *)address);
            break;
        case sizeof(uint32_t):
            cprintf("%u", *(uint32_t *)address);
            break;
        case sizeof(uint64_t):
            cprintf("%lu", *(uint64_t *)address);
            break;
        default:
            goto unknown_kind;
        }
        break;
    case KIND_FLOATING_POINT:
        switch (var_info->byte_size) {
        case sizeof(float):
            cprintf("%Lf", (long double)*(float *)address);
            break;
        case sizeof(double):
            cprintf("%Lf", (long double)*(double *)address);
            break;
        case sizeof(long double):
            cprintf("%Lf", *(long double *)address);
            break;
        default:
            goto unknown_kind;
        }
        break;
    case KIND_POINTER:
        switch (var_info->byte_size) {
        case sizeof(uintptr_t):
            if (with_deref) {
                print_var_value(var_info->fields[0], 0, depth, *(uintptr_t *)address, inline_str);
            } else {
                cprintf("0x%08lx", *(uintptr_t *)address);
            }
            break;
        default:
            goto unknown_kind;
        }
        break;
    case KIND_STRUCT:
        cprintf("{");
        cprintf(inline_str ? " " : "\n");
        size_t i = 0;
        struct Dwarf_VarInfo *current_field = var_info->fields[0];
        while (i < DWARF_MAX_STRUCT_FIELDS && current_field) {
            print_var(current_field, 0, depth + 1, address, inline_str);
            ++i;
            current_field = var_info->fields[i];
            if (inline_str && i < DWARF_MAX_STRUCT_FIELDS && current_field) cprintf("; ");
        }
        if (!inline_str) for (int i = 0; i < depth; ++i) cprintf("\t");
        if (inline_str) cprintf(" ");
        cprintf("}");
        break;
    case KIND_ARRAY:
        cprintf("{ ");
        struct Dwarf_VarInfo *underlying = var_info->fields[0];
        size_t length = var_info->byte_size / underlying->byte_size;
        for (size_t i = 0; i < length; ++i) {
            print_var_value(underlying, 0, depth, address + i * underlying->byte_size, inline_str);
            if (i != length - 1) cprintf(", ");
        }
        cprintf(" }");
        break;
    case KIND_UNKNOWN:
    default:
    unknown_kind:
        if (inline_str) {
            cprintf("? [Size = %d; Address = 0x%08lx]", var_info->byte_size, address);
        } else {
            cprintf("?\n");
            for (int i = 0; i < depth; ++i) cprintf("\t");
            cprintf("\tSize = %d\n", var_info->byte_size);
            for (int i = 0; i < depth; ++i) cprintf("\t");
            cprintf("\tAddress = 0x%08lx", address);
        }
        break;
    }
}
static void
print_var_value(struct Dwarf_VarInfo *var_info, bool with_deref, uint8_t depth, uintptr_t base_address, bool inline_str) {
    uintptr_t address = base_address + var_info->address;
    if (address < MAX_USER_READABLE) {
        print_var_value_by_address(var_info, with_deref, depth, address, inline_str);
    } else {
        struct AddressSpace *old = switch_address_space(&kspace);
        print_var_value_by_address(var_info, with_deref, depth, address, inline_str);
        switch_address_space(old);
    }
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf) {
    cprintf("Stack backtrace:\n");
    struct Ripdebuginfo info = { 0 };
    uint64_t rbp = read_rbp();
    while (rbp) {
        uint64_t *rbp_as_ptr = (uint64_t*) rbp;
        uint64_t next_rbp = rbp_as_ptr[0];
        uint64_t rip = rbp_as_ptr[1];

        debuginfo_rip(rip, &info);

        cprintf("  rbp 0x%016lx  rip 0x%016lx\n", rbp, rip);
        cprintf("    0x%016lx in %.*s (", rip - info.rip_fn_addr, info.rip_fn_namelen, info.rip_fn_name);

        for (int i = 0; i < info.rip_fn_narg; ++i) {
            struct Dwarf_VarInfo *param = &info.rip_fn_params[i];
            if (param->is_variadic) {
                cprintf("%s", param->name);
            } else if (strlen(param->name) == 0) {
                cprintf("%s=", param->type_name);
                print_var_value(param, false, 0, (uintptr_t) next_rbp, true);
            } else {
                cprintf("%s %s=", param->type_name, param->name);
                print_var_value(param, false, 0, (uintptr_t) next_rbp, true);
            }
            if (i != info.rip_fn_narg - 1) {
                cprintf(", ");
            }
            free_var_info(param);
        }
        cprintf(") at %s:%d\n", info.rip_file, info.rip_line);

        rbp = next_rbp;
    }
    return 0;
}

int
mon_hello(int argc, char **argv, struct Trapframe *tf) {
    cprintf("Hello\n");
    return 0;
}

int
mon_dumpcmos(int argc, char **argv, struct Trapframe *tf) {
    uint8_t addr = 0;
    do {
        cprintf("%02x:", addr);
        cprintf(" %02x %02x %02x %02x", cmos_read8(addr +  0), cmos_read8(addr +  1), cmos_read8(addr +  2), cmos_read8(addr +  3));
        cprintf(" %02x %02x %02x %02x", cmos_read8(addr +  4), cmos_read8(addr +  5), cmos_read8(addr +  6), cmos_read8(addr +  7));
        cprintf(" %02x %02x %02x %02x", cmos_read8(addr +  8), cmos_read8(addr +  9), cmos_read8(addr + 10), cmos_read8(addr + 11));
        cprintf(" %02x %02x %02x %02x", cmos_read8(addr + 12), cmos_read8(addr + 13), cmos_read8(addr + 14), cmos_read8(addr + 15));
        cprintf("\n");
        addr += 16;
    } while (addr < 128);

    return 0;
}

int
mon_start(int argc, char **argv, struct Trapframe *tf) {
    if (argc == 1) {
        timer_start("pit");
    } else {
        timer_start(argv[1]);
    }
    return 0;
}

int
mon_stop(int argc, char **argv, struct Trapframe *tf) {
    timer_stop();
    return 0;
}

int
mon_frequency(int argc, char **argv, struct Trapframe *tf) {
    if (argc == 1) {
        timer_cpu_frequency("pit");
    } else {
        timer_cpu_frequency(argv[1]);
    }
    return 0;
}

int
mon_memory(int argc, char **argv, struct Trapframe *tf) {
    dump_memory_lists();
    return 0;
}

int
mon_virt(int argc, char **argv, struct Trapframe *tf) {
    dump_virtual_tree(kspace.root, MAX_CLASS);
    return 0;
}

int
mon_pagetable(int argc, char **argv, struct Trapframe *tf) {
    dump_page_table(kspace.pml4);
    return 0;
}

static void
print_var(struct Dwarf_VarInfo *var_info, bool with_deref, uint8_t depth, uintptr_t base_address, bool inline_str) {
    if (!inline_str) for (int i = 0; i < depth; ++i) cprintf("\t");

    if (with_deref && var_info->kind != KIND_POINTER) {
        cprintf("Can't deref type ");
        cprintf("%s\n", var_info->type_name);
        return;
    }

    if (with_deref) {
        cprintf("%s *%s = ", var_info->type_name, var_info->name);
    } else {
        cprintf("%s %s = ", var_info->type_name, var_info->name);
    }

    print_var_value(var_info, with_deref, depth, base_address, inline_str);
    if (!inline_str) cprintf("\n");
}

int
mon_print_var(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 2) {
        cprintf("Expected single argument - variable name\n");
        return 0;
    }

    char *var_name = argv[1];
    struct Dwarf_VarInfo var_info = { 0 };
    bool with_deref = 0;
    if (var_name[0] == '*') {
        with_deref = 1;
        strncpy(var_info.name, var_name + 1, DWARF_BUFSIZ);
    } else {
        with_deref = 0;
        strncpy(var_info.name, var_name, DWARF_BUFSIZ);
    }

    int res = var_debuginfo(&var_info, true);
    if (res == -E_NO_ENT) {
        free_var_info(&var_info);
        res = var_debuginfo(&var_info, false);
    }

    if (res == -E_NO_ENT) {
        cprintf("Not found\n");
        goto exit;
    } else if (res < 0) {
        cprintf("Error: %i\n", res);
        goto exit;
    }
    print_var(&var_info, with_deref, 0, 0, false);

exit:
    free_var_info(&var_info);
    return 0;
}

/* Kernel monitor command interpreter */

static int
runcmd(char *buf, struct Trapframe *tf) {
    int argc = 0;
    char *argv[MAXARGS];

    argv[0] = NULL;

    /* Parse the command buffer into whitespace-separated arguments */
    for (;;) {
        /* gobble whitespace */
        while (*buf && strchr(WHITESPACE, *buf)) *buf++ = 0;
        if (!*buf) break;

        /* save and scan past next arg */
        if (argc == MAXARGS - 1) {
            cprintf("Too many arguments (max %d)\n", MAXARGS);
            return 0;
        }
        argv[argc++] = buf;
        while (*buf && !strchr(WHITESPACE, *buf)) buf++;
    }
    argv[argc] = NULL;

    /* Lookup and invoke the command */
    if (!argc) return 0;
    for (size_t i = 0; i < NCOMMANDS; i++) {
        if (strcmp(argv[0], commands[i].name) == 0)
            return commands[i].func(argc, argv, tf);
    }

    cprintf("Unknown command '%s'\n", argv[0]);
    return 0;
}

void
monitor(struct Trapframe *tf) {

    cprintf("Welcome to the JOS kernel monitor!\n");
    cprintf("Type 'help' for a list of commands.\n");

    if (tf) print_trapframe(tf);

    char *buf;
    do buf = readline("K> ");
    while (!buf || runcmd(buf, tf) >= 0);
}

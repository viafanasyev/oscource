/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>
#include <inc/elf.h>

#include <kern/env.h>
#include <kern/monitor.h>
#include <kern/sched.h>
#include <kern/kdebug.h>
#include <kern/macro.h>
#include <kern/traceopt.h>

/* Currently active environment */
struct Env *curenv = NULL;

#ifdef CONFIG_KSPACE
/* All environments */
struct Env env_array[NENV];
struct Env *envs = env_array;
#else
/* All environments */
struct Env *envs = NULL;
#endif

/* Free environment list
 * (linked by Env->env_link) */
static struct Env *env_free_list;


/* NOTE: Should be at least LOGNENV */
#define ENVGENSHIFT 12

struct Segdesc32 gdt[7 + 2 * NCPU] = {
    [0]                                  = SEG_NULL,                                    /* Null descriptor */
    [GD_KT   / sizeof(struct Segdesc32)] = SEG64(STA_X | STA_R, 0x0, 0xffffffff, 0),    /* Kernel code segment */
    [GD_KD   / sizeof(struct Segdesc32)] = SEG64(STA_W, 0x0, 0xffffffff, 0),            /* Kernel data segment */
    [GD_KT32 / sizeof(struct Segdesc32)] = SEG32(STA_X | STA_R, 0x0, 0xffffffff, 0),    /* Kernel code segment 32bit */
    [GD_KD32 / sizeof(struct Segdesc32)] = SEG32(STA_W, 0x0, 0xffffffff, 0),            /* Kernel data segment 32bit */
    [GD_UT   / sizeof(struct Segdesc32)] = SEG64(STA_X | STA_R, 0x0, 0xffffffff, 3),    /* User code segment */
    [GD_UD   / sizeof(struct Segdesc32)] = SEG64(STA_W, 0x0, 0xffffffff, 3),            /* User data segment */
    [GD_TSS0 / sizeof(struct Segdesc32)] = SEG_NULL, /* TODO */                         /* Task state segment */
};

struct Pseudodesc gdt_pd = {
	sizeof(gdt) - 1,    /* Limit */
    (unsigned long) gdt /* Address */
};

/* Converts an envid to an env pointer.
 * If checkperm is set, the specified environment must be either the
 * current environment or an immediate child of the current environment.
 *
 * RETURNS
 *     0 on success, -E_BAD_ENV on error.
 *   On success, sets *env_store to the environment.
 *   On error, sets *env_store to NULL. */
int
envid2env(envid_t envid, struct Env **env_store, bool need_check_perm) {
    struct Env *env;

    /* If envid is zero, return the current environment. */
    if (!envid) {
        *env_store = curenv;
        return 0;
    }

    /* Look up the Env structure via the index part of the envid,
     * then check the env_id field in that struct Env
     * to ensure that the envid is not stale
     * (i.e., does not refer to a _previous_ environment
     * that used the same slot in the envs[] array). */
    env = &envs[ENVX(envid)];
    if (env->env_status == ENV_FREE || env->env_id != envid) {
        *env_store = NULL;
        return -E_BAD_ENV;
    }

    /* Check that the calling environment has legitimate permission
     * to manipulate the specified environment.
     * If checkperm is set, the specified environment
     * must be either the current environment
     * or an immediate child of the current environment. */
    if (need_check_perm && env != curenv && env->env_parent_id != curenv->env_id) {
        *env_store = NULL;
        return -E_BAD_ENV;
    }

    *env_store = env;
    return 0;
}

/* Mark all environments in 'envs' as free, set their env_ids to 0,
 * and insert them into the env_free_list.
 * Make sure the environments are in the free list in the same order
 * they are in the envs array (i.e., so that the first call to
 * env_alloc() returns envs[0]).
 */
void
env_init(void) {
    assert(envs);

    /* Set up envs array */
    env_free_list = NULL;
    for (int32_t i = NENV - 1; i >= 0; --i) {
        envs[i].env_link = env_free_list;
        env_free_list = &envs[i];
        envs[i].env_status = ENV_FREE;
        envs[i].env_parent_id = 0;
        envs[i].env_id = 0;
        envs[i].env_runs = 0;
    }

    /* Set up GDT and set initial values for segment registers */

	lgdt(&gdt_pd);

	/* Kernel doesn't use GS or FS, so preload user segments */
	asm volatile("movw %%ax, %%gs" : : "a" (GD_UD | 3));
	asm volatile("movw %%ax, %%fs" : : "a" (GD_UD | 3));

    /* Load kernel ES, DS, SS and CS */
	asm volatile("movw %%ax, %%es" : : "a" (GD_KD));
	asm volatile("movw %%ax, %%ds" : : "a" (GD_KD));
	asm volatile("movw %%ax, %%ss" : : "a" (GD_KD));
    asm volatile(
            "pushq %%rbx        \n"
            "movabs $1f, %%rax  \n"
            "pushq %%rax        \n"
            "lretq              \n"
            "1:                 \n"
            :
            : "b"(GD_KT)
            : "cc", "memory"
    );
}

/* Allocates and initializes a new environment.
 * On success, the new environment is stored in *newenv_store.
 *
 * Returns
 *     0 on success, < 0 on failure.
 * Errors
 *    -E_NO_FREE_ENV if all NENVS environments are allocated
 *    -E_NO_MEM on memory exhaustion
 */
int
env_alloc(struct Env **newenv_store, envid_t parent_id, enum EnvType type) {

    struct Env *env;
    if (!(env = env_free_list))
        return -E_NO_FREE_ENV;

    /* Generate an env_id for this environment */
    int32_t generation = (env->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
    /* Don't create a negative env_id */
    if (generation <= 0) generation = 1 << ENVGENSHIFT;
    env->env_id = generation | (env - envs);

    /* Set the basic status variables */
    env->env_parent_id = parent_id;
#ifdef CONFIG_KSPACE
    env->env_type = ENV_TYPE_KERNEL;
#else
    env->env_type = type;
#endif
    env->env_status = ENV_RUNNABLE;
    env->env_runs = 0;

    /* Clear out all the saved register state,
     * to prevent the register values
     * of a prior environment inhabiting this Env structure
     * from "leaking" into our new environment */
    memset(&env->env_tf, 0, sizeof(env->env_tf));

    /* Set up appropriate initial values for the segment registers.
     * GD_UD is the user data (KD - kernel data) segment selector in the GDT, and
     * GD_UT is the user text (KT - kernel text) segment selector (see inc/memlayout.h).
     * The low 2 bits of each segment register contains the
     * Requestor Privilege Level (RPL); 3 means user mode, 0 - kernel mode.  When
     * we switch privilege levels, the hardware does various
     * checks involving the RPL and the Descriptor Privilege Level
     * (DPL) stored in the descriptors themselves */

#ifdef CONFIG_KSPACE
    env->env_tf.tf_ds = GD_KD;
    env->env_tf.tf_es = GD_KD;
    env->env_tf.tf_ss = GD_KD;
    env->env_tf.tf_cs = GD_KT;

    static uintptr_t stack_top = 0x2000000;
    env->env_tf.tf_rsp = stack_top - 2 * PAGE_SIZE * (env - envs);
#else
    env->env_tf.tf_ds = GD_UD | 3;
    env->env_tf.tf_es = GD_UD | 3;
    env->env_tf.tf_ss = GD_UD | 3;
    env->env_tf.tf_cs = GD_UT | 3;
    env->env_tf.tf_rsp = USER_STACK_TOP;
#endif

    /* Commit the allocation */
    env_free_list = env->env_link;
    *newenv_store = env;

    if (trace_envs) cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, env->env_id);
    return 0;
}

/* Pass the original ELF image to binary/size and bind all the symbols within
 * its loaded address space specified by image_start/image_end.
 * Make sure you understand why you need to check that each binding
 * must be performed within the image_start/image_end range.
 */
static int
bind_functions(struct Env *env, uint8_t *binary, size_t size, uintptr_t image_start, uintptr_t image_end) {
    assert(env);
    assert(binary);

    struct Elf *elf = (struct Elf *) binary;

    struct Secthdr *sh_start = (struct Secthdr *) (binary + elf->e_shoff);
    struct Secthdr *sh_end = sh_start + elf->e_shnum;
    char *shstr = (char *) binary + sh_start[elf->e_shstrndx].sh_offset;

    //
    // Find Symbol Table and String Table
    //
    struct Secthdr *symtab = NULL;
    struct Secthdr *strtab = NULL;
    for (struct Secthdr *sh = sh_start; sh < sh_end; ++sh) {
        if (sh->sh_type == ELF_SHT_SYMTAB && !strcmp(".symtab", shstr + sh->sh_name)) {
            if (symtab) {
                cprintf("Symbol table is met twice\n");
                return -E_INVALID_EXE;
            }
            symtab = sh;
        } else if (sh->sh_type == ELF_SHT_STRTAB && !strcmp(".strtab", shstr + sh->sh_name)) {
            if (strtab) {
                cprintf("String table is met twice\n");
                return -E_INVALID_EXE;
            }
            strtab = sh;
        }
    }

    if (!symtab) {
        cprintf("Symbol table not found\n");
        return -E_INVALID_EXE;
    }
    if (!strtab) {
        cprintf("String table not found\n");
        return -E_INVALID_EXE;
    }

    //
    // Bind symbols
    //
    uint64_t num_entries = symtab->sh_size / symtab->sh_entsize;
    for (uint64_t i = 0; i < num_entries; ++i) {
        struct Elf64_Sym *sym = (struct Elf64_Sym *) (binary + symtab->sh_offset + symtab->sh_entsize * i);
        if (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL) {
            const char *fname = (const char*) (binary + strtab->sh_offset + sym->st_name);
            uintptr_t offset = find_function(fname);
            if (offset != 0 && sym->st_value >= image_start && sym->st_value < image_end) {
                *(uintptr_t *)(sym->st_value) = offset;
                cprintf("Rebinded symbol '%s' with offset %lu\n", fname, offset);
            }
        }
    }

    return 0;
}

/* Set up the initial program binary, stack, and processor flags
 * for a user process.
 * This function is ONLY called during kernel initialization,
 * before running the first environment.
 *
 * This function loads all loadable segments from the ELF binary image
 * into the environment's user memory, starting at the appropriate
 * virtual addresses indicated in the ELF program header.
 * At the same time it clears to zero any portions of these segments
 * that are marked in the program header as being mapped
 * but not actually present in the ELF file - i.e., the program's bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk.  Take a look at
 * LoaderPkg/Loader/Bootloader.c to get ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 *
 * load_icode returns -E_INVALID_EXE if it encounters problems.
 *  - How might load_icode fail?  What might be wrong with the given input?
 *
 * Hints:
 *   Load each program segment into memory
 *   at the address specified in the ELF section header.
 *   You should only load segments with ph->p_type == ELF_PROG_LOAD.
 *   Each segment's address can be found in ph->p_va
 *   and its size in memory can be found in ph->p_memsz.
 *   The ph->p_filesz bytes from the ELF binary, starting at
 *   'binary + ph->p_offset', should be copied to address
 *   ph->p_va.  Any remaining memory bytes should be cleared to zero.
 *   (The ELF header should have ph->p_filesz <= ph->p_memsz.)
 *
 *   All page protection bits should be user read/write for now.
 *   ELF segments are not necessarily page-aligned, but you can
 *   assume for this function that no two segments will touch
 *   the same page.
 *
 *   You must also do something with the program's entry point,
 *   to make sure that the environment starts executing there.
 *   What?  (See env_run() and env_pop_tf() below.) */
static int
load_icode(struct Env *env, uint8_t *binary, size_t size) {
    assert(env);
    assert(binary);

    struct Elf *elf = (struct Elf *) binary;

    //
    // Verify ELF header
    //

    if (elf->e_magic != ELF_MAGIC) {
        cprintf("ELF has magic %08X instead of %08X\n", elf->e_magic, ELF_MAGIC);
        return -E_INVALID_EXE;
    }

    if (elf->e_shentsize != sizeof(struct Secthdr)) {
        cprintf("ELF has sections of %u bytes instead of %u\n", elf->e_shentsize, (uint32_t) sizeof(struct Secthdr));
        return -E_INVALID_EXE;
    }

    if (elf->e_shstrndx >= elf->e_shnum) {
        cprintf("ELF string section has invalid index %u out of %u entries\n", elf->e_shstrndx, elf->e_shnum);
        return -E_INVALID_EXE;
    }

    if (elf->e_phentsize != sizeof(struct Proghdr)) {
        cprintf("ELF has program headers of %u bytes instead of %u\n", elf->e_phentsize, (uint32_t) sizeof(struct Proghdr));
        return -E_INVALID_EXE;
    }

    //
    // Read program segments
    //
    for (uint32_t i = 0; i < elf->e_phnum; ++i) {
        struct Proghdr *ph = (struct Proghdr *) (binary + elf->e_phoff + sizeof(struct Proghdr) * i);
        if (ph->p_type != ELF_PROG_LOAD) {
            cprintf("Skipped program segment %u/%u\n", (i + 1), elf->e_phnum);
            continue;
        }

        if (ph->p_filesz > ph->p_memsz) {
            cprintf("Invalid filesz %lu for program segment %u with memsz %lu\n", ph->p_filesz, (i + 1), ph->p_memsz);
            return -E_INVALID_EXE;
        }

        memset((void *) ph->p_va, 0, ph->p_memsz);
        memcpy((void *) ph->p_va, binary + ph->p_offset, ph->p_filesz);

        int res = bind_functions(env, binary, size, ph->p_va, ph->p_va + ph->p_memsz);
        if (res) {
            cprintf("Failed binding functions for program segment %u/%u\n", (i + 1), elf->e_phnum);
            return res;
        }

        cprintf("Read program segment %u/%u\n", (i + 1), elf->e_phnum);
    }

    env->env_tf.tf_rip = elf->e_entry;

    return 0;
}

/* Allocates a new env with env_alloc, loads the named elf
 * binary into it with load_icode, and sets its env_type.
 * This function is ONLY called during kernel initialization,
 * before running the first user-mode environment.
 * The new env's parent ID is set to 0.
 */
void
env_create(uint8_t *binary, size_t size, enum EnvType type) {
    assert(binary);

    struct Env *env = NULL;
    int res = 0;

    res = env_alloc(&env, 0, type);
    if (res) {
        if (env) env_free(env);
        panic("Failed to create env: %i\n", res);
    }

    res = load_icode(env, binary, size);
    if (res) {
        if (env) env_free(env);
        panic("Failed to load binary: %i\n", res);
    }
}


/* Frees env and all memory it uses */
void
env_free(struct Env *env) {

    /* Note the environment's demise. */
    if (trace_envs) cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, env->env_id);

    /* Return the environment to the free list */
    env->env_status = ENV_FREE;
    env->env_link = env_free_list;
    env_free_list = env;
}

/* Frees environment env
 *
 * If env was the current one, then runs a new environment
 * (and does not return to the caller)
 */
void
env_destroy(struct Env *env) {
    /* If env is currently running on other CPUs, we change its state to
     * ENV_DYING. A zombie environment will be freed the next time
     * it traps to the kernel. */

    if (env->env_status == ENV_RUNNING && env != curenv) {
        env->env_status = ENV_DYING;
        return;
    }

    env_free(env);

    if (env == curenv) {
        sched_yield();
    }
}

#ifdef CONFIG_KSPACE
void
csys_exit(void) {
    if (!curenv) panic("curenv = NULL");
    env_destroy(curenv);
}

void
csys_yield(struct Trapframe *tf) {
    memcpy(&curenv->env_tf, tf, sizeof(struct Trapframe));
    sched_yield();
}
#endif

/* Restores the register values in the Trapframe with the 'ret' instruction.
 * This exits the kernel and starts executing some environment's code.
 *
 * This function does not return.
 */

_Noreturn void
env_pop_tf(struct Trapframe *tf) {

    /* Push RIP on program stack */
    tf->tf_rsp -= sizeof(uintptr_t);
    *((uintptr_t *)tf->tf_rsp) = tf->tf_rip;
    /* Push RFLAGS on program stack */
    tf->tf_rsp -= sizeof(uintptr_t);
    *((uintptr_t *)tf->tf_rsp) = tf->tf_rflags;

    asm volatile(
            "movq %0, %%rsp\n"
            "movq 0(%%rsp), %%r15\n"
            "movq 8(%%rsp), %%r14\n"
            "movq 16(%%rsp), %%r13\n"
            "movq 24(%%rsp), %%r12\n"
            "movq 32(%%rsp), %%r11\n"
            "movq 40(%%rsp), %%r10\n"
            "movq 48(%%rsp), %%r9\n"
            "movq 56(%%rsp), %%r8\n"
            "movq 64(%%rsp), %%rsi\n"
            "movq 72(%%rsp), %%rdi\n"
            "movq 80(%%rsp), %%rbp\n"
            "movq 88(%%rsp), %%rdx\n"
            "movq 96(%%rsp), %%rcx\n"
            "movq 104(%%rsp), %%rbx\n"
            "movq 112(%%rsp), %%rax\n"
            "movw 120(%%rsp), %%es\n"
            "movw 128(%%rsp), %%ds\n"
            "movq (128+48)(%%rsp), %%rsp\n"
            "popfq; ret" ::"g"(tf)
            : "memory");

    /* Mostly to placate the compiler */
    panic("Reached unrecheble\n");
}

/* Context switch from curenv to env.
 * This function does not return.
 *
 * Step 1: If this is a context switch (a new environment is running):
 *       1. Set the current environment (if any) back to
 *          ENV_RUNNABLE if it is ENV_RUNNING (think about
 *          what other states it can be in),
 *       2. Set 'curenv' to the new environment,
 *       3. Set its status to ENV_RUNNING,
 *       4. Update its 'env_runs' counter,
 * Step 2: Use env_pop_tf() to restore the environment's
 *       registers and starting execution of process.

 * Hints:
 *    If this is the first call to env_run, curenv is NULL.
 *
 *    This function loads the new environment's state from
 *    env->env_tf.  Go back through the code you wrote above
 *    and make sure you have set the relevant parts of
 *    env->env_tf to sensible values.
 */
_Noreturn void
env_run(struct Env *env) {
    assert(env);

    if (trace_envs_more) {
        const char *state[] = {"FREE", "DYING", "RUNNABLE", "RUNNING", "NOT_RUNNABLE"};
        if (curenv) cprintf("[%08X] env stopped: %s\n", curenv->env_id, state[curenv->env_status]);
        cprintf("[%08X] env started: %s\n", env->env_id, state[env->env_status]);
    }

    if (curenv && curenv->env_status == ENV_RUNNING) {
        curenv->env_status = ENV_RUNNABLE;
    }

    if (env->env_status != ENV_RUNNABLE) {
        panic("Can't switch context to non-runnable process\n");
    }

    curenv = env;
    curenv->env_status = ENV_RUNNING;
    curenv->env_runs++;

    env_pop_tf(&curenv->env_tf);

    while(1) {}
}

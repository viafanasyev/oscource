#include <inc/types.h>
#include <inc/assert.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/stdio.h>
#include <inc/x86.h>
#include <inc/uefi.h>
#include <kern/timer.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/trap.h>
#include <kern/pmap.h>

#define kilo      (1000ULL)
#define Mega      (kilo * kilo)
#define Giga      (kilo * Mega)
#define Tera      (kilo * Giga)
#define Peta      (kilo * Tera)
#define ULONG_MAX ~0UL

#if LAB <= 6
/* Early variant of memory mapping that does 1:1 aligned area mapping
 * in 2MB pages. You will need to reimplement this code with proper
 * virtual memory mapping in the future. */
void *
mmio_map_region(physaddr_t pa, size_t size) {
    void map_addr_early_boot(uintptr_t addr, uintptr_t addr_phys, size_t sz);
    const physaddr_t base_2mb = 0x200000;
    uintptr_t org = pa;
    size += pa & (base_2mb - 1);
    size += (base_2mb - 1);
    pa &= ~(base_2mb - 1);
    size &= ~(base_2mb - 1);
    map_addr_early_boot(pa, pa, size);
    return (void *)org;
}
void *
mmio_remap_last_region(physaddr_t pa, void *addr, size_t oldsz, size_t newsz) {
    return mmio_map_region(pa, newsz);
}
#endif

struct Timer timertab[MAX_TIMERS];
struct Timer *timer_for_schedule;

struct Timer timer_hpet0 = {
        .timer_name = "hpet0",
        .timer_init = hpet_init,
        .get_cpu_freq = hpet_cpu_frequency,
        .enable_interrupts = hpet_enable_interrupts_tim0,
        .handle_interrupts = hpet_handle_interrupts_tim0,
};

struct Timer timer_hpet1 = {
        .timer_name = "hpet1",
        .timer_init = hpet_init,
        .get_cpu_freq = hpet_cpu_frequency,
        .enable_interrupts = hpet_enable_interrupts_tim1,
        .handle_interrupts = hpet_handle_interrupts_tim1,
};

struct Timer timer_acpipm = {
        .timer_name = "pm",
        .timer_init = acpi_enable,
        .get_cpu_freq = pmtimer_cpu_frequency,
};

void
acpi_enable(void) {
    FADT *fadt = get_fadt();
    outb(fadt->SMI_CommandPort, fadt->AcpiEnable);
    while ((inw(fadt->PM1aControlBlock) & 1) == 0) /* nothing */
        ;
}

static uint8_t
count_rsdp_checksum(const RSDP *rsdp) {
    uint8_t checksum = 0;
    if (rsdp->Revision == 0) {
        /* ACPI Version 1.0 */
        checksum += rsdp->Signature[0];
        checksum += rsdp->Signature[1];
        checksum += rsdp->Signature[2];
        checksum += rsdp->Signature[3];
        checksum += rsdp->Signature[4];
        checksum += rsdp->Signature[5];
        checksum += rsdp->Signature[6];
        checksum += rsdp->Signature[7];
        checksum += rsdp->Checksum;
        checksum += rsdp->OEMID[0];
        checksum += rsdp->OEMID[1];
        checksum += rsdp->OEMID[2];
        checksum += rsdp->OEMID[3];
        checksum += rsdp->OEMID[4];
        checksum += rsdp->OEMID[5];
        checksum += rsdp->Revision;
        checksum += (uint8_t) (rsdp->RsdtAddress >>  0);
        checksum += (uint8_t) (rsdp->RsdtAddress >>  8);
        checksum += (uint8_t) (rsdp->RsdtAddress >> 16);
        checksum += (uint8_t) (rsdp->RsdtAddress >> 24);
    } else {
        /* ACPI Version >= 2.0 */
        for (uint32_t i = 0; i < rsdp->Length; ++i) {
            checksum += ((uint8_t *) rsdp)[i];
        }
    }
    return checksum;
}

static void *
acpi_find_table(const char *sign) {
    RSDP *rsdp = (RSDP *) uefi_lp->ACPIRoot;
    uint8_t checksum = count_rsdp_checksum(rsdp);
    if (checksum != 0) {
        panic("Invalid RSDP checksum: %x, but should be 0\n", checksum);
    }

    size_t sign_len = strlen(sign);
    if (rsdp->Revision == 0) {
        /* ACPI Version 1.0 */
        RSDT *rsdt = (RSDT *) mmio_map_region(rsdp->RsdtAddress, sizeof(*rsdt));
        uint32_t entries = (rsdt->h.Length - sizeof(rsdt->h)) / sizeof(uint32_t);
        for (uint32_t i = 0; i < entries; ++i) {
            ACPISDTHeader *h = (ACPISDTHeader *) mmio_map_region(rsdt->PointerToOtherSDT[i], sizeof(*h));
            if (!strncmp(h->Signature, sign, sign_len)) {
                return (void *) h;
            }
        }
        return NULL;
    } else {
        /* ACPI Version >= 2.0 */
        XSDT *xsdt = (XSDT *) mmio_map_region(rsdp->XsdtAddress, sizeof(*xsdt));
        uint32_t entries = (xsdt->h.Length - sizeof(xsdt->h)) / sizeof(uint64_t);
        for (uint32_t i = 0; i < entries; ++i) {
            ACPISDTHeader *h = (ACPISDTHeader *) mmio_map_region(xsdt->PointerToOtherSDT[i], sizeof(*h));
            if (!strncmp(h->Signature, sign, sign_len)) {
                return (void *) h;
            }
        }
        return NULL;
    }
}

/* Obtain and map FADT ACPI table address. */
FADT *
get_fadt(void) {
    static FADT *kfadt = NULL;
    if (!kfadt) kfadt = (FADT *) acpi_find_table("FACP");
    return kfadt;
}

/* Obtain and map RSDP ACPI table address. */
HPET *
get_hpet(void) {
    static HPET *khpet = NULL;
    if (!khpet) khpet = (HPET *) acpi_find_table("HPET");
    return khpet;
}

/* Getting physical HPET timer address from its table. */
HPETRegister *
hpet_register(void) {
    HPET *hpet_timer = get_hpet();
    if (!hpet_timer->address.address) panic("hpet is unavailable\n");

    uintptr_t paddr = hpet_timer->address.address;
    return mmio_map_region(paddr, sizeof(HPETRegister));
}

/* Debug HPET timer state. */
void
hpet_print_struct(void) {
    HPET *hpet = get_hpet();
    assert(hpet != NULL);
    cprintf("signature = %s\n", (hpet->h).Signature);
    cprintf("length = %08x\n", (hpet->h).Length);
    cprintf("revision = %08x\n", (hpet->h).Revision);
    cprintf("checksum = %08x\n", (hpet->h).Checksum);

    cprintf("oem_revision = %08x\n", (hpet->h).OEMRevision);
    cprintf("creator_id = %08x\n", (hpet->h).CreatorID);
    cprintf("creator_revision = %08x\n", (hpet->h).CreatorRevision);

    cprintf("hardware_rev_id = %08x\n", hpet->hardware_rev_id);
    cprintf("comparator_count = %08x\n", hpet->comparator_count);
    cprintf("counter_size = %08x\n", hpet->counter_size);
    cprintf("reserved = %08x\n", hpet->reserved);
    cprintf("legacy_replacement = %08x\n", hpet->legacy_replacement);
    cprintf("pci_vendor_id = %08x\n", hpet->pci_vendor_id);
    cprintf("hpet_number = %08x\n", hpet->hpet_number);
    cprintf("minimum_tick = %08x\n", hpet->minimum_tick);

    cprintf("address_structure:\n");
    cprintf("address_space_id = %08x\n", (hpet->address).address_space_id);
    cprintf("register_bit_width = %08x\n", (hpet->address).register_bit_width);
    cprintf("register_bit_offset = %08x\n", (hpet->address).register_bit_offset);
    cprintf("address = %08lx\n", (unsigned long)(hpet->address).address);
}

static volatile HPETRegister *hpetReg;
/* HPET timer period (in femtoseconds) */
static uint64_t hpetFemto = 0;
/* HPET timer frequency */
static uint64_t hpetFreq = 0;

/* HPET timer initialisation */
void
hpet_init() {
    if (hpetReg == NULL) {
        nmi_disable();
        hpetReg = hpet_register();
        uint64_t cap = hpetReg->GCAP_ID;
        hpetFemto = (uintptr_t)(cap >> 32);
        if (!(cap & HPET_LEG_RT_CAP)) panic("HPET has no LegacyReplacement mode");

        /* cprintf("hpetFemto = %llu\n", hpetFemto); */
        hpetFreq = (1 * Peta) / hpetFemto;
        /* cprintf("HPET: Frequency = %d.%03dMHz\n", (uintptr_t)(hpetFreq / Mega), (uintptr_t)(hpetFreq % Mega)); */
        /* Enable ENABLE_CNF bit to enable timer */
        hpetReg->GEN_CONF |= HPET_ENABLE_CNF;
        nmi_enable();
    }
}

/* HPET register contents debugging. */
void
hpet_print_reg(void) {
    cprintf("GCAP_ID = %016lx\n", (unsigned long)hpetReg->GCAP_ID);
    cprintf("GEN_CONF = %016lx\n", (unsigned long)hpetReg->GEN_CONF);
    cprintf("GINTR_STA = %016lx\n", (unsigned long)hpetReg->GINTR_STA);
    cprintf("MAIN_CNT = %016lx\n", (unsigned long)hpetReg->MAIN_CNT);
    cprintf("TIM0_CONF = %016lx\n", (unsigned long)hpetReg->TIM0_CONF);
    cprintf("TIM0_COMP = %016lx\n", (unsigned long)hpetReg->TIM0_COMP);
    cprintf("TIM0_FSB = %016lx\n", (unsigned long)hpetReg->TIM0_FSB);
    cprintf("TIM1_CONF = %016lx\n", (unsigned long)hpetReg->TIM1_CONF);
    cprintf("TIM1_COMP = %016lx\n", (unsigned long)hpetReg->TIM1_COMP);
    cprintf("TIM1_FSB = %016lx\n", (unsigned long)hpetReg->TIM1_FSB);
    cprintf("TIM2_CONF = %016lx\n", (unsigned long)hpetReg->TIM2_CONF);
    cprintf("TIM2_COMP = %016lx\n", (unsigned long)hpetReg->TIM2_COMP);
    cprintf("TIM2_FSB = %016lx\n", (unsigned long)hpetReg->TIM2_FSB);
}

/* HPET main timer counter value. */
uint64_t
hpet_get_main_cnt(void) {
    return hpetReg->MAIN_CNT;
}

void
hpet_enable_interrupts_tim0(void) {
    if (!(hpetReg->TIM0_CONF & HPET_TN_PER_INT_CAP)) panic("Periodic mode is not supported by timer 0");
    hpetReg->GEN_CONF |= HPET_LEG_RT_CNF; // Use LegacyReplacement
    hpetReg->TIM0_CONF |= HPET_TN_TYPE_CNF; // Enable periodic mode
    hpetReg->TIM0_CONF |= HPET_TN_SIZE_CAP; // Set timer to 64-bit mode
    hpetReg->TIM0_CONF |= HPET_TN_VAL_SET_CNF; // Allow writing to periodic timer's accumulator
    hpetReg->TIM0_COMP = hpetFreq * 0.5;
    hpetReg->TIM0_CONF |= HPET_TN_INT_ENB_CNF; // Enable triggering of interrupts
    pic_irq_unmask(IRQ_TIMER);
}

void
hpet_enable_interrupts_tim1(void) {
    if (!(hpetReg->TIM1_CONF & HPET_TN_PER_INT_CAP)) panic("Periodic mode is not supported by timer 1");
    hpetReg->GEN_CONF |= HPET_LEG_RT_CNF; // Use LegacyReplacement
    hpetReg->TIM1_CONF |= HPET_TN_TYPE_CNF; // Enable periodic mode
    hpetReg->TIM1_CONF |= HPET_TN_SIZE_CAP; // Set timer to 64-bit mode
    hpetReg->TIM1_CONF |= HPET_TN_VAL_SET_CNF; // Allow writing to periodic timer's accumulator
    hpetReg->TIM1_COMP = hpetFreq * 1.5;
    hpetReg->TIM1_CONF |= HPET_TN_INT_ENB_CNF; // Enable triggering of interrupts
    pic_irq_unmask(IRQ_CLOCK);
}

void
hpet_handle_interrupts_tim0(void) {
    pic_send_eoi(IRQ_TIMER);
}

void
hpet_handle_interrupts_tim1(void) {
    pic_send_eoi(IRQ_CLOCK);
}

uint64_t
hpet_cpu_frequency(void) {
    static uint64_t cpu_freq = 0;

    if (cpu_freq == 0) {
        uint64_t interrupts_enabled = read_rflags() & FL_IF;
        asm volatile("cli");

        uint64_t t1 = hpet_get_main_cnt();
        uint64_t tsc1 = read_tsc();
        asm volatile("pause");
        uint64_t t2 = hpet_get_main_cnt();
        uint64_t tsc2 = read_tsc();

        if (interrupts_enabled) {
            asm volatile("sti");
        }

        uint64_t timer_delta = 0;
        if (t2 > t1) {
            /* No overflow */
            timer_delta = t2 - t1;
        } else if (t1 - t2 <= UINT32_MAX) {
            /* Overflow, 32 bit */
            timer_delta = UINT32_MAX - t1 + t2;
        } else {
            /* Overflow, 64 bit */
            timer_delta = ULONG_MAX - t1 + t2;
        }
        uint64_t tsc_delta = 0;
        if (tsc2 > tsc1) {
            /* No overflow */
            tsc_delta = tsc2 - tsc1;
        } else {
            /* Overflow */
            tsc_delta = ULONG_MAX - tsc1 + tsc2;
        }
        cpu_freq = (tsc_delta * hpetFreq) / timer_delta;
    }

    return cpu_freq;
}

uint32_t
pmtimer_get_timeval(void) {
    FADT *fadt = get_fadt();
    return inl(fadt->PMTimerBlock);
}

uint64_t
pmtimer_cpu_frequency(void) {
    static uint64_t cpu_freq = 0;

    if (cpu_freq == 0) {
        uint64_t interrupts_enabled = read_rflags() & FL_IF;
        asm volatile("cli");

        uint64_t t1 = pmtimer_get_timeval();
        uint64_t tsc1 = read_tsc();
        asm volatile("pause");
        uint64_t t2 = pmtimer_get_timeval();
        uint64_t tsc2 = read_tsc();

        if (interrupts_enabled) {
            asm volatile("sti");
        }

        uint64_t timer_delta = 0;
        if (t2 > t1) {
            /* No overflow */
            timer_delta = t2 - t1;
        } else if (t1 - t2 <= 0x00FFFFFF) {
            /* Overflow, 24-bit */
            timer_delta = 0x00FFFFFF - t1 + t2;
        } else {
            /* Overflow, 32-bit */
            timer_delta = UINT32_MAX - t1 + t2;
        }
        uint64_t tsc_delta = 0;
        if (tsc2 > tsc1) {
            /* No overflow */
            tsc_delta = tsc2 - tsc1;
        } else {
            /* Overflow */
            tsc_delta = ULONG_MAX - tsc1 + tsc2;
        }
        cpu_freq = (tsc_delta * PM_FREQ) / timer_delta;
    }

    return cpu_freq;
}

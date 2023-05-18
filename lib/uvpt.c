/* User virtual page table helpers */

#include <inc/lib.h>
#include <inc/mmu.h>

extern volatile pte_t uvpt[];     /* VA of "virtual page table" */
extern volatile pde_t uvpd[];     /* VA of current page directory */
extern volatile pdpe_t uvpdp[];   /* VA of current page directory pointer */
extern volatile pml4e_t uvpml4[]; /* VA of current page map level 4 */

pte_t
get_uvpt_entry(void *va) {
    if (!(uvpml4[VPML4(va)] & PTE_P)) return uvpml4[VPML4(va)];
    if (!(uvpdp[VPDP(va)] & PTE_P) || (uvpdp[VPDP(va)] & PTE_PS)) return uvpdp[VPDP(va)];
    if (!(uvpd[VPD(va)] & PTE_P) || (uvpd[VPD(va)] & PTE_PS)) return uvpd[VPD(va)];
    return uvpt[VPT(va)];
}

int
get_prot(void *va) {
    pte_t pte = get_uvpt_entry(va);
    int prot = pte & PTE_AVAIL & ~PTE_SHARE;
    if (pte & PTE_P) prot |= PROT_R;
    if (pte & PTE_W) prot |= PROT_W;
    if (!(pte & PTE_NX)) prot |= PROT_X;
    if (pte & PTE_SHARE) prot |= PROT_SHARE;
    return prot;
}

bool
is_page_dirty(void *va) {
    pte_t pte = get_uvpt_entry(va);
    return pte & PTE_D;
}

bool
is_page_present(void *va) {
    return get_uvpt_entry(va) & PTE_P;
}

int
foreach_shared_region(int (*fun)(void *start, void *end, void *arg), void *arg) {
    for (uintptr_t pml4i = 0; pml4i < MAX_USER_ADDRESS; pml4i += (1LL << PML4_SHIFT)) {
        if (!(uvpml4[VPML4(pml4i)] & PTE_P)) continue;
        for (uintptr_t pdpi = pml4i; pdpi < pml4i + (1LL << PML4_SHIFT); pdpi += (1LL << PDP_SHIFT)) {
            if (!(uvpdp[VPDP(pdpi)] & PTE_P)) continue;
            for (uintptr_t pdi = pdpi; pdi < pdpi + (1LL << PDP_SHIFT); pdi += (1LL << PD_SHIFT)) {
                if (!(uvpd[VPD(pdi)] & PTE_P)) continue;
                for (uintptr_t pti = pdi; pti < pdi + (1LL << PD_SHIFT); pti += (1LL << PT_SHIFT)) {
                    if (!(uvpt[VPT(pti)] & PTE_P && uvpt[VPT(pti)] & PTE_SHARE)) continue;
                    fun((void*)pti, (void *)(pti + PAGE_SIZE), arg);
                }
            }
        }
    }
    return 0;
}

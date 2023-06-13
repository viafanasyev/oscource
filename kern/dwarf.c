#include <inc/assert.h>
#include <inc/error.h>
#include <inc/dwarf.h>
#include <inc/string.h>
#include <inc/types.h>
#include <inc/stdio.h>

#include <kern/pmap.h>

struct Slice {
    const void *mem;
    int len;
};

static int
info_by_address_debug_aranges(const struct Dwarf_Addrs *addrs, uintptr_t p, Dwarf_Off *store) {
    const uint8_t *set = addrs->aranges_begin;
    while ((unsigned char *)set < addrs->aranges_end) {
        int count = 0;
        unsigned long len;
        const uint8_t *header = set;
        set += dwarf_entry_len(set, &len);
        if (!count) return -E_BAD_DWARF;
        const uint8_t *set_end = set + len;

        /* Parse compilation unit header */
        Dwarf_Half version = get_unaligned(set, Dwarf_Half);
        assert(version == 2);
        set += sizeof(Dwarf_Half);
        Dwarf_Off offset = get_unaligned(set, uint32_t);
        set += sizeof(uint32_t);
        Dwarf_Small address_size = get_unaligned(set, Dwarf_Small);
        assert(address_size == 8);
        set += sizeof(Dwarf_Small);
        Dwarf_Small segment_size = get_unaligned(set, Dwarf_Small);
        set += sizeof(Dwarf_Small);
        assert(!segment_size);

        void *addr = NULL;
        uint32_t entry_size = 2 * address_size + segment_size;
        uint32_t remainder = (set - header) % entry_size;
        if (remainder) set += 2 * address_size - remainder;

        Dwarf_Off size = 0;
        do {
            addr = (void *)get_unaligned(set, uintptr_t);
            set += address_size;
            size = get_unaligned(set, uint32_t);
            set += address_size;
            if ((uintptr_t)addr <= p && p <= (uintptr_t)addr + size) {
                *store = offset;
                return 0;
            }
        } while (set < set_end);
        assert(set == set_end);
    }
    return -E_BAD_DWARF;
}

/* Read value from .debug_abbrev table in buf. Returns number of bytes read */
static int
dwarf_read_abbrev_entry(const void *entry, unsigned form, void *buf, int bufsize, size_t address_size) {
    int bytes = 0;
    switch (form) {
    case DW_FORM_addr: {
        uintptr_t data = 0;
        memcpy(&data, entry, address_size);
        entry += address_size;
        if (buf && bufsize >= sizeof(uintptr_t))
            put_unaligned(data, (uintptr_t *)buf);
        bytes = address_size;
    } break;
    case DW_FORM_block2: {
        Dwarf_Half length = get_unaligned(entry, Dwarf_Half);
        entry += sizeof(Dwarf_Half);
        struct Slice slice = {
                .mem = entry,
                .len = length,
        };
        if (buf) memcpy(buf, &slice, sizeof(struct Slice));
        entry += length;
        bytes = sizeof(Dwarf_Half) + length;
    } break;
    case DW_FORM_block4: {
        uint32_t length = get_unaligned(entry, uint32_t);
        entry += sizeof(uint32_t);
        struct Slice slice = {
                .mem = entry,
                .len = length,
        };
        if (buf) memcpy(buf, &slice, sizeof(struct Slice));
        entry += length;
        bytes = sizeof(uint32_t) + length;
    } break;
    case DW_FORM_data2: {
        Dwarf_Half data = get_unaligned(entry, Dwarf_Half);
        entry += sizeof(Dwarf_Half);
        if (buf && bufsize >= sizeof(Dwarf_Half))
            put_unaligned(data, (Dwarf_Half *)buf);
        bytes = sizeof(Dwarf_Half);
    } break;
    case DW_FORM_data4: {
        uint32_t data = get_unaligned(entry, uint32_t);
        entry += sizeof(uint32_t);
        if (buf && bufsize >= sizeof(uint32_t))
            put_unaligned(data, (uint32_t *)buf);
        bytes = sizeof(uint32_t);
    } break;
    case DW_FORM_data8: {
        uint64_t data = get_unaligned(entry, uint64_t);
        entry += sizeof(uint64_t);
        if (buf && bufsize >= sizeof(uint64_t))
            put_unaligned(data, (uint64_t *)buf);
        bytes = sizeof(uint64_t);
    } break;
    case DW_FORM_string: {
        if (buf && bufsize >= sizeof(char *))
            memcpy(buf, &entry, sizeof(char *));
        bytes = strlen(entry) + 1;
    } break;
    case DW_FORM_block: {
        uint64_t length = 0;
        uint32_t count = dwarf_read_uleb128(entry, &length);
        entry += count;
        struct Slice slice = {
                .mem = entry,
                .len = length,
        };
        if (buf) memcpy(buf, &slice, sizeof(struct Slice));
        entry += length;
        bytes = count + length;
    } break;
    case DW_FORM_block1: {
        uint32_t length = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        struct Slice slice = {
                .mem = entry,
                .len = length,
        };
        if (buf) memcpy(buf, &slice, sizeof(struct Slice));
        entry += length;
        bytes = length + sizeof(Dwarf_Small);
    } break;
    case DW_FORM_data1: {
        Dwarf_Small data = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        if (buf && bufsize >= sizeof(Dwarf_Small)) {
            put_unaligned(data, (Dwarf_Small *)buf);
        }
        bytes = sizeof(Dwarf_Small);
    } break;
    case DW_FORM_flag: {
        bool data = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        if (buf && bufsize >= sizeof(bool)) {
            put_unaligned(data, (bool *)buf);
        }
        bytes = sizeof(Dwarf_Small);
    } break;
    case DW_FORM_sdata: {
        int64_t data = 0;
        uint32_t count = dwarf_read_leb128(entry, &data);
        entry += count;
        if (buf && bufsize >= sizeof(int32_t))
            put_unaligned(data, (int32_t *)buf);
        bytes = count;
    } break;
    case DW_FORM_strp: {
        uint64_t length = 0;
        uint32_t count = dwarf_entry_len(entry, &length);
        entry += count;
        if (buf && bufsize >= sizeof(uint64_t))
            put_unaligned(length, (uint64_t *)buf);
        bytes = count;
    } break;
    case DW_FORM_udata: {
        uint64_t data = 0;
        uint32_t count = dwarf_read_uleb128(entry, &data);
        entry += count;
        if (buf && bufsize >= sizeof(uint32_t))
            put_unaligned(data, (uint32_t *)buf);
        bytes = count;
    } break;
    case DW_FORM_ref_addr: {
        uint64_t length = 0;
        uint32_t count = dwarf_entry_len(entry, &length);
        entry += count;
        if (buf && bufsize >= sizeof(uint64_t))
            put_unaligned(length, (uint64_t *)buf);
        bytes = count;
    } break;
    case DW_FORM_ref1: {
        Dwarf_Small data = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        if (buf && bufsize >= sizeof(Dwarf_Small))
            put_unaligned(data, (Dwarf_Small *)buf);
        bytes = sizeof(Dwarf_Small);
    } break;
    case DW_FORM_ref2: {
        Dwarf_Half data = get_unaligned(entry, Dwarf_Half);
        entry += sizeof(Dwarf_Half);
        if (buf && bufsize >= sizeof(Dwarf_Half))
            put_unaligned(data, (Dwarf_Half *)buf);
        bytes = sizeof(Dwarf_Half);
    } break;
    case DW_FORM_ref4: {
        uint32_t data = get_unaligned(entry, uint32_t);
        entry += sizeof(uint32_t);
        if (buf && bufsize >= sizeof(uint32_t))
            put_unaligned(data, (uint32_t *)buf);
        bytes = sizeof(uint32_t);
    } break;
    case DW_FORM_ref8: {
        uint64_t data = get_unaligned(entry, uint64_t);
        entry += sizeof(uint64_t);
        if (buf && bufsize >= sizeof(uint64_t))
            put_unaligned(data, (uint64_t *)buf);
        bytes = sizeof(uint64_t);
    } break;
    case DW_FORM_ref_udata: {
        uint64_t data = 0;
        uint32_t count = dwarf_read_uleb128(entry, &data);
        entry += count;
        if (buf && bufsize >= sizeof(unsigned int))
            put_unaligned(data, (unsigned int *)buf);
        bytes = count;
    } break;
    case DW_FORM_indirect: {
        uint64_t form = 0;
        uint32_t count = dwarf_read_uleb128(entry, &form);
        entry += count;
        uint32_t read = dwarf_read_abbrev_entry(entry, form, buf, bufsize, address_size);
        bytes = count + read;
    } break;
    case DW_FORM_sec_offset: {
        uint64_t length = 0;
        uint32_t count = dwarf_entry_len(entry, &length);
        entry += count;
        if (buf && bufsize >= sizeof(unsigned long))
            put_unaligned(length, (unsigned long *)buf);
        bytes = count;
    } break;
    case DW_FORM_exprloc: {
        uint64_t length = 0;
        uint64_t count = dwarf_read_uleb128(entry, &length);
        entry += count;
        if (buf) memcpy(buf, entry, MIN(length, bufsize));
        entry += length;
        bytes = count + length;
    } break;
    case DW_FORM_flag_present:
        if (buf && sizeof(buf) >= sizeof(bool)) {
            put_unaligned(true, (bool *)buf);
        }
        bytes = 0;
        break;
    case DW_FORM_ref_sig8: {
        uint64_t data = get_unaligned(entry, uint64_t);
        entry += sizeof(uint64_t);
        if (buf && bufsize >= sizeof(uint64_t))
            put_unaligned(data, (uint64_t *)buf);
        bytes = sizeof(uint64_t);
    } break;
    }
    return bytes;
}

/* Find a compilation unit, which contains given address from .debug_info section */
static int
info_by_address_debug_info(const struct Dwarf_Addrs *addrs, uintptr_t p, Dwarf_Off *store) {
    const uint8_t *entry = addrs->info_begin;

    while (entry < addrs->info_end) {
        const uint8_t *header = entry;

        uint32_t count;
        uint64_t len = 0;
        entry += count = dwarf_entry_len(entry, &len);
        if (!count) return -E_BAD_DWARF;

        const uint8_t *entry_end = entry + len;

        /* Parse compilation unit header */
        Dwarf_Half version = get_unaligned(entry, Dwarf_Half);
        entry += sizeof(Dwarf_Half);
        assert(version == 4 || version == 2);
        Dwarf_Off abbrev_offset = get_unaligned(entry, uint32_t);
        entry += sizeof(uint32_t);
        Dwarf_Small address_size = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        assert(address_size == sizeof(uintptr_t));

        /* Read abbreviation code */
        uint64_t abbrev_code = 0;
        entry += dwarf_read_uleb128(entry, &abbrev_code);
        assert(abbrev_code);

        /* Read abbreviations table */
        const uint8_t *abbrev_entry = addrs->abbrev_begin + abbrev_offset;
        uint64_t table_abbrev_code = 0;
        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &table_abbrev_code);
        assert(table_abbrev_code == abbrev_code);
        uint64_t tag = 0;
        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &tag);
        assert(tag == DW_TAG_compile_unit);
        abbrev_entry += sizeof(Dwarf_Small);

        uint64_t name = 0, form = 0;
        uintptr_t low_pc = 0, high_pc = 0;
        do {
            abbrev_entry += dwarf_read_uleb128(abbrev_entry, &name);
            abbrev_entry += dwarf_read_uleb128(abbrev_entry, &form);
            if (name == DW_AT_low_pc) {
                entry += dwarf_read_abbrev_entry(entry, form, &low_pc, sizeof(low_pc), address_size);
            } else if (name == DW_AT_high_pc) {
                entry += dwarf_read_abbrev_entry(entry, form, &high_pc, sizeof(high_pc), address_size);
                if (form != DW_FORM_addr) high_pc += low_pc;
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);

        if (p >= low_pc && p <= high_pc) {
            *store = (const unsigned char *)header - addrs->info_begin;
            return 0;
        }

        entry = entry_end;
    }
    return -E_NO_ENT;
}

int
info_by_address(const struct Dwarf_Addrs *addrs, uintptr_t addr, Dwarf_Off *store) {
    int res = info_by_address_debug_aranges(addrs, addr, store);
    if (res < 0) res = info_by_address_debug_info(addrs, addr, store);
    return res;
}

int
file_name_by_info(const struct Dwarf_Addrs *addrs, Dwarf_Off offset, char **buf, Dwarf_Off *line_off) {
    if (offset > addrs->info_end - addrs->info_begin) return -E_INVAL;

    const uint8_t *entry = addrs->info_begin + offset;
    uint32_t count;
    uint64_t len = 0;
    entry += count = dwarf_entry_len(entry, &len);
    if (!count) return -E_BAD_DWARF;

    /* Parse compilation unit header */
    Dwarf_Half version = get_unaligned(entry, Dwarf_Half);
    entry += sizeof(Dwarf_Half);
    assert(version == 4 || version == 2);
    Dwarf_Off abbrev_offset = get_unaligned(entry, uint32_t);
    entry += sizeof(uint32_t);
    Dwarf_Small address_size = get_unaligned(entry, Dwarf_Small);
    entry += sizeof(Dwarf_Small);
    assert(address_size == sizeof(uintptr_t));

    /* Read abbreviation code */
    uint64_t abbrev_code = 0;
    entry += dwarf_read_uleb128(entry, &abbrev_code);
    assert(abbrev_code);

    /* Read abbreviations table */
    const uint8_t *abbrev_entry = addrs->abbrev_begin + abbrev_offset;
    uint64_t table_abbrev_code = 0;
    abbrev_entry += dwarf_read_uleb128(abbrev_entry, &table_abbrev_code);
    assert(table_abbrev_code == abbrev_code);
    uint64_t tag = 0;
    abbrev_entry += dwarf_read_uleb128(abbrev_entry, &tag);
    assert(tag == DW_TAG_compile_unit);
    abbrev_entry += sizeof(Dwarf_Small);

    uint64_t name = 0, form = 0;
    do {
        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &name);
        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &form);
        if (name == DW_AT_name) {
            if (form == DW_FORM_strp) {
                uint64_t offset = 0;
                entry += dwarf_read_abbrev_entry(entry, form, &offset, sizeof(uint64_t), address_size);
                if (buf) put_unaligned((const uint8_t *)addrs->str_begin + offset, buf);
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, buf, sizeof(char *), address_size);
            }
        } else if (name == DW_AT_stmt_list) {
            entry += dwarf_read_abbrev_entry(entry, form, line_off, sizeof(Dwarf_Off), address_size);
        } else {
            entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
        }
    } while (name || form);

    return 0;
}

static int
parse_array_size(const struct Dwarf_Addrs *addrs, Dwarf_Off cu_offset, Dwarf_Off abbrev_offset, Dwarf_Small address_size, const void **entry) {

    /* Read info abbreviation code */
    uint64_t abbrev_code = 0;
    *entry += dwarf_read_uleb128(*entry, &abbrev_code);
    if (!abbrev_code) return INT32_MIN;

    const uint8_t *curr_abbrev_entry = addrs->abbrev_begin + abbrev_offset;
    uint64_t table_abbrev_code = 0;
    uint64_t name = 0, form = 0, tag = 0;

    /* Find abbreviation in abbrev section */
    /* UNSAFE Needs to be replaced */
    while (curr_abbrev_entry < addrs->abbrev_end) {
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
        curr_abbrev_entry += sizeof(Dwarf_Small);
        if (table_abbrev_code == abbrev_code) break;

        /* Skip attributes */
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
        } while (name != 0 || form != 0);
    }

    if (table_abbrev_code != abbrev_code) return INT32_MIN;

    if (tag == DW_TAG_subrange_type) {
        uint64_t array_size = 0;
        bool found = 0;
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_upper_bound) {
                if (form == DW_FORM_data1 || form == DW_FORM_data2 || form == DW_FORM_data4 || form == DW_FORM_data8) {
                    *entry += dwarf_read_abbrev_entry(*entry, form, &array_size, sizeof(array_size), address_size);
                    ++array_size;
                    found = 1;
                } else {
                    *entry += dwarf_read_abbrev_entry(*entry, form, NULL, 0, address_size);
                }
            } else if (name == DW_AT_count) {
                if (form == DW_FORM_data1 || form == DW_FORM_data2 || form == DW_FORM_data4 || form == DW_FORM_data8) {
                    *entry += dwarf_read_abbrev_entry(*entry, form, &array_size, sizeof(array_size), address_size);
                    found = 1;
                } else {
                    *entry += dwarf_read_abbrev_entry(*entry, form, NULL, 0, address_size);
                }
            } else {
                *entry += dwarf_read_abbrev_entry(*entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        if (found) {
            return array_size;
        } else {
            return -E_NO_ENT;
        }
    } else {
        return INT32_MIN;
    }
}

static void
append_itos(unsigned int value, char *dst) {
    static const char *digits = "0123456789";
    size_t len = strlen(dst);

    unsigned int tmp_value = value;
    do {
        ++len;
        tmp_value /= 10;
    } while(tmp_value > 0);

    dst[len] = '\0';

    do {
        dst[--len] = digits[value % 10];
        value /= 10;
    } while (value > 0);
}

static int
parse_type_name(const struct Dwarf_Addrs *addrs, Dwarf_Off cu_offset, Dwarf_Off abbrev_offset, Dwarf_Small address_size, Dwarf_Off type_offset, char *buf) {
    assert(addrs);
    assert(buf);

    strncpy(buf, UNKNOWN_TYPE, DWARF_BUFSIZ);

    const void *entry = addrs->info_begin + cu_offset + type_offset;

    /* Read info abbreviation code */
    uint64_t abbrev_code = 0;
    entry += dwarf_read_uleb128(entry, &abbrev_code);
    if (!abbrev_code) return -E_BAD_DWARF;

    const uint8_t *curr_abbrev_entry = addrs->abbrev_begin + abbrev_offset;
    uint64_t table_abbrev_code = 0;
    uint64_t name = 0, form = 0, tag = 0;

    /* Find abbreviation in abbrev section */
    /* UNSAFE Needs to be replaced */
    while (curr_abbrev_entry < addrs->abbrev_end) {
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
        curr_abbrev_entry += sizeof(Dwarf_Small);
        if (table_abbrev_code == abbrev_code) break;

        /* Skip attributes */
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
        } while (name != 0 || form != 0);
    }

    if (table_abbrev_code != abbrev_code) return -E_NO_ENT;

    if (
        tag == DW_TAG_base_type
            || tag == DW_TAG_typedef
            || tag == DW_TAG_enumeration_type
            || tag == DW_TAG_structure_type
            || tag == DW_TAG_union_type
    ) {
         do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_name) {
                if (form == DW_FORM_strp) {
                    uint64_t str_offset = 0;
                    (void)dwarf_read_abbrev_entry(entry, form, &str_offset, sizeof(str_offset), address_size);
                    const char *tmp_buf = NULL;
                    put_unaligned((const char *)addrs->str_begin + str_offset, &tmp_buf);
                    strncpy(buf, tmp_buf, DWARF_BUFSIZ);
                } else {
                    const char *tmp_buf = NULL;
                    (void)dwarf_read_abbrev_entry(entry, form, &tmp_buf, sizeof(tmp_buf), address_size);
                    strncpy(buf, tmp_buf, DWARF_BUFSIZ);
                }
                return 0;
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        return 0;
    } else if (
        tag == DW_TAG_pointer_type
            || tag == DW_TAG_const_type
            || tag == DW_TAG_volatile_type
            || tag == DW_TAG_restrict_type
    ) {
        const char *qualifier;
        switch (tag) {
            case DW_TAG_pointer_type:
                qualifier = "*";
                break;
            case DW_TAG_const_type:
                qualifier = " const";
                break;
            case DW_TAG_volatile_type:
                qualifier = " volatile";
                break;
            case DW_TAG_restrict_type:
                qualifier = " restrict";
                break;
            default:
                qualifier = UNKNOWN_QUALIFIER;
                break;
        }
        int parse_res = 0;
        bool has_underlying_type = 0;
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_type) {
                if (form == DW_FORM_ref1 || form == DW_FORM_ref2 || form == DW_FORM_ref4 || form == DW_FORM_ref8) {
                    Dwarf_Off type_offset = 0;
                    (void)dwarf_read_abbrev_entry(entry, form, &type_offset, sizeof(type_offset), address_size);
                    parse_res = parse_type_name(addrs, cu_offset, abbrev_offset, address_size, type_offset, buf);
                } else {
                    (void)dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    strncpy(buf, UNKNOWN_TYPE, DWARF_BUFSIZ);
                }
                has_underlying_type = 1;
                break;
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        if (!has_underlying_type) {
            // There's no void type in DWARF - it is represented with absence of underlying DW_AT_type
            // So we make it by hand
            strncpy(buf, "void", sizeof("void"));
        }
        strlcat(buf, qualifier, DWARF_BUFSIZ);
        return parse_res;
    } else if (tag == DW_TAG_array_type) {
        int parse_res = 0;
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_type) {
                if (form == DW_FORM_ref1 || form == DW_FORM_ref2 || form == DW_FORM_ref4 || form == DW_FORM_ref8) {
                    Dwarf_Off type_offset = 0;
                    entry += dwarf_read_abbrev_entry(entry, form, &type_offset, sizeof(type_offset), address_size);
                    parse_res = parse_type_name(addrs, cu_offset, abbrev_offset, address_size, type_offset, buf);
                } else {
                    entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    strncpy(buf, UNKNOWN_TYPE, DWARF_BUFSIZ);
                }
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);

        if (parse_res) {
            strlcat(buf, "[?]", DWARF_BUFSIZ);
            return parse_res;
        }

        int array_size = 0;
        do {
            array_size = parse_array_size(addrs, cu_offset, abbrev_offset, address_size, &entry);
            if (array_size >= 0) {
                strlcat(buf, "[", DWARF_BUFSIZ);
                append_itos(array_size, buf);
                strlcat(buf, "]", DWARF_BUFSIZ);
            }
        } while (array_size >= 0);
        if (array_size != INT32_MIN) {
            strlcat(buf, "[?]", DWARF_BUFSIZ);
            return array_size;
        }
        return 0;
    } else {
        return 0;
    }
}

static int
parse_var_info(const struct Dwarf_Addrs *addrs, Dwarf_Off cu_offset, Dwarf_Off abbrev_offset, Dwarf_Small address_size, Dwarf_Off type_offset, enum Dwarf_VarKind *kind, uint8_t *byte_size, struct Dwarf_VarInfo **fields);

static int
parse_struct_member(const struct Dwarf_Addrs *addrs, Dwarf_Off cu_offset, Dwarf_Off abbrev_offset, Dwarf_Small address_size, const void **entry, struct Dwarf_VarInfo *member_info) {
    assert(entry);
    assert(member_info);

    /* Read info abbreviation code */
    uint64_t abbrev_code = 0;
    *entry += dwarf_read_uleb128(*entry, &abbrev_code);
    if (!abbrev_code) return -E_NO_ENT;

    const uint8_t *curr_abbrev_entry = addrs->abbrev_begin + abbrev_offset;
    uint64_t table_abbrev_code = 0;
    uint64_t name = 0, form = 0, tag = 0;

    /* Find abbreviation in abbrev section */
    /* UNSAFE Needs to be replaced */
    while (curr_abbrev_entry < addrs->abbrev_end) {
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
        curr_abbrev_entry += sizeof(Dwarf_Small);
        if (table_abbrev_code == abbrev_code) break;

        /* Skip attributes */
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
        } while (name != 0 || form != 0);
    }

    if (table_abbrev_code != abbrev_code) return -E_NO_ENT;

    if (tag == DW_TAG_member) {
        bool found_name = 0;
        bool found_offset = 0;
        bool found_type = 0;
        uint64_t offset = 0;
        enum Dwarf_VarKind kind = KIND_UNKNOWN;
        uint8_t byte_size = 0;
        char type_name[DWARF_BUFSIZ];
        struct Dwarf_VarInfo *fields[DWARF_MAX_STRUCT_FIELDS] = { 0 };
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_name) {
                if (form == DW_FORM_strp) {
                    uint64_t str_offset = 0;
                    *entry += dwarf_read_abbrev_entry(*entry, form, &str_offset, sizeof(str_offset), address_size);
                    char *tmp_buf = NULL;
                    put_unaligned((const char *)addrs->str_begin + str_offset, &tmp_buf);
                    strncpy(member_info->name, tmp_buf, DWARF_BUFSIZ);
                    found_name = 1;
                } else {
                    char *tmp_buf = NULL;
                    *entry += dwarf_read_abbrev_entry(*entry, form, &tmp_buf, sizeof(tmp_buf), address_size);
                    strncpy(member_info->name, tmp_buf, DWARF_BUFSIZ);
                    found_name = 1;
                }
            } else if (name == DW_AT_data_member_location) {
                *entry += dwarf_read_abbrev_entry(*entry, form, &offset, sizeof(offset), address_size);
                found_offset = 1;
            } else if (name == DW_AT_type) {
                if (form == DW_FORM_ref1 || form == DW_FORM_ref2 || form == DW_FORM_ref4 || form == DW_FORM_ref8) {
                    Dwarf_Off type_offset = 0;
                    *entry += dwarf_read_abbrev_entry(*entry, form, &type_offset, sizeof(type_offset), address_size);
                    int parse_res = parse_var_info(addrs, cu_offset, abbrev_offset, address_size, type_offset, &kind, &byte_size, fields);
                    if (parse_res < 0) {
                        kind = KIND_UNKNOWN;
                        byte_size = 0;
                    }

                    parse_res = parse_type_name(addrs, cu_offset, abbrev_offset, address_size, type_offset, type_name);
                    if (parse_res < 0) {
                        strncpy(type_name, UNKNOWN_TYPE, sizeof(type_name));
                    }

                    found_type = 1;
                } else {
                    *entry += dwarf_read_abbrev_entry(*entry, form, NULL, 0, address_size);
                }
            } else {
                *entry += dwarf_read_abbrev_entry(*entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        if (found_name && found_offset && found_type) {
            member_info->address = offset;
            member_info->kind = kind;
            member_info->byte_size = byte_size;
            strncpy(member_info->type_name, type_name, DWARF_BUFSIZ);
            memcpy(member_info->fields, fields, sizeof(member_info->fields));
            return 0;
        } else {
            return -E_BAD_DWARF;
        }
    } else {
        return -E_NO_ENT;
    }
}

static int
parse_var_info(const struct Dwarf_Addrs *addrs, Dwarf_Off cu_offset, Dwarf_Off abbrev_offset, Dwarf_Small address_size, Dwarf_Off type_offset, enum Dwarf_VarKind *kind, uint8_t *byte_size, struct Dwarf_VarInfo **fields) {
    assert(addrs);
    assert(kind);
    assert(byte_size);
    assert(fields);

    const void *entry = addrs->info_begin + cu_offset + type_offset;

    /* Read info abbreviation code */
    uint64_t abbrev_code = 0;
    entry += dwarf_read_uleb128(entry, &abbrev_code);
    if (!abbrev_code) return -E_BAD_DWARF;

    const uint8_t *curr_abbrev_entry = addrs->abbrev_begin + abbrev_offset;
    uint64_t table_abbrev_code = 0;
    uint64_t name = 0, form = 0, tag = 0;

    /* Find abbreviation in abbrev section */
    /* UNSAFE Needs to be replaced */
    while (curr_abbrev_entry < addrs->abbrev_end) {
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
        curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
        curr_abbrev_entry += sizeof(Dwarf_Small);
        if (table_abbrev_code == abbrev_code) break;

        /* Skip attributes */
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
        } while (name != 0 || form != 0);
    }

    if (table_abbrev_code != abbrev_code) return -E_NO_ENT;

    if (tag == DW_TAG_base_type) {
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_encoding) {
                uint64_t encoding = 0;
                entry += dwarf_read_abbrev_entry(entry, form, &encoding, sizeof(encoding), address_size);
                switch (encoding) {
                case DW_ATE_signed:
                case DW_ATE_signed_char:
                case DW_ATE_boolean:
                    *kind = KIND_SIGNED_INT;
                    break;
                case DW_ATE_unsigned:
                case DW_ATE_unsigned_char:
                    *kind = KIND_UNSIGNED_INT;
                    break;
                case DW_ATE_float:
                    *kind = KIND_FLOATING_POINT;
                    break;
                default:
                    *kind = KIND_UNKNOWN;
                    break;
                }
            } else if (name == DW_AT_byte_size) {
                entry += dwarf_read_abbrev_entry(entry, form, byte_size, sizeof(*byte_size), address_size);
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        return 0;
    } else if (tag == DW_TAG_pointer_type) {
        *kind = KIND_POINTER;
        *byte_size = sizeof(uintptr_t); // Clang dumps pointer type without byte_size, so we assume it has default size of uintptr_t
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_byte_size) {
                (void)dwarf_read_abbrev_entry(entry, form, byte_size, sizeof(*byte_size), address_size);
                break;
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        return 0;
    } else if (
        tag == DW_TAG_typedef
            || tag == DW_TAG_const_type
            || tag == DW_TAG_volatile_type
            || tag == DW_TAG_restrict_type
    ) {
        int parse_res = 0;
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_type) {
                if (form == DW_FORM_ref1 || form == DW_FORM_ref2 || form == DW_FORM_ref4 || form == DW_FORM_ref8) {
                    Dwarf_Off type_offset = 0;
                    entry += dwarf_read_abbrev_entry(entry, form, &type_offset, sizeof(type_offset), address_size);
                    parse_res = parse_var_info(addrs, cu_offset, abbrev_offset, address_size, type_offset, kind, byte_size, fields);
                } else {
                    entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    *kind = KIND_UNKNOWN;
                    *byte_size = 0;
                }
                (void)entry;
                break;
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        return parse_res;
    } else if (tag == DW_TAG_structure_type) {
        *kind = KIND_STRUCT;
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_byte_size) {
                entry += dwarf_read_abbrev_entry(entry, form, byte_size, sizeof(*byte_size), address_size);
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);

        int res = 0;
        size_t current_field = 0;
        do {
            struct Dwarf_VarInfo *field_info = kzalloc_region(sizeof(struct Dwarf_VarInfo)); // FIXME: Call free
            res = parse_struct_member(addrs, cu_offset, abbrev_offset, address_size, &entry, field_info);
            if (res == 0) {
                fields[current_field] = field_info;
            }
            ++current_field;
        } while (res == 0 && current_field < DWARF_MAX_STRUCT_FIELDS);
        if (res != -E_NO_ENT) {
            return res;
        }

        return 0;
    } else {
        *kind = KIND_UNKNOWN;
        do {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            if (name == DW_AT_byte_size) {
                (void)dwarf_read_abbrev_entry(entry, form, byte_size, sizeof(*byte_size), address_size);
                break;
            } else {
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            }
        } while (name || form);
        return 0;
    }
}

int
function_by_info(const struct Dwarf_Addrs *addrs, uintptr_t p, Dwarf_Off cu_offset, char **buf, uintptr_t *offset, struct Dwarf_FuncParameter *params, int *nparams) {
    assert(params);
    assert(nparams);

    uint64_t len = 0;
    uint32_t count;

    const void *entry = addrs->info_begin + cu_offset;
    entry += count = dwarf_entry_len(entry, &len);
    if (!count) return -E_BAD_DWARF;

    const void *entry_end = entry + len;

    /* Parse compilation unit header */
    Dwarf_Half version = get_unaligned(entry, Dwarf_Half);
    entry += sizeof(Dwarf_Half);
    assert(version == 4 || version == 2);
    Dwarf_Off abbrev_offset = get_unaligned(entry, uint32_t);
    entry += sizeof(uint32_t);
    Dwarf_Small address_size = get_unaligned(entry, Dwarf_Small);
    entry += sizeof(Dwarf_Small);
    assert(address_size == sizeof(uintptr_t));

    /* Parse abbrev and info sections */
    uint64_t abbrev_code = 0;
    uint64_t table_abbrev_code = 0;
    const uint8_t *abbrev_entry = addrs->abbrev_begin + abbrev_offset;

    bool is_after_subprogram = 0;

    while (entry < entry_end) {
        /* Read info abbreviation code */
        entry += dwarf_read_uleb128(entry, &abbrev_code);
        if (!abbrev_code) continue;

        const uint8_t *curr_abbrev_entry = abbrev_entry;
        uint64_t name = 0, form = 0, tag = 0;

        /* Find abbreviation in abbrev section */
        /* UNSAFE Needs to be replaced */
        while (curr_abbrev_entry < addrs->abbrev_end) {
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
            curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
            curr_abbrev_entry += sizeof(Dwarf_Small);
            if (table_abbrev_code == abbrev_code) break;

            /* Skip attributes */
            do {
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
            } while (name != 0 || form != 0);
        }

        if (is_after_subprogram) {
            if (tag == DW_TAG_formal_parameter) {
                /* Parse parameter */
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                    if (name == DW_AT_name) {
                        if (form == DW_FORM_strp) {
                            uint64_t str_offset = 0;
                            entry += dwarf_read_abbrev_entry(entry, form, &str_offset, sizeof(str_offset), address_size);
                            char *tmp_buf = NULL;
                            put_unaligned((const char *)addrs->str_begin + str_offset, &tmp_buf);
                            strncpy(params[*nparams].name, tmp_buf, sizeof(params[*nparams].name));
                        } else {
                            char *tmp_buf = NULL;
                            entry += dwarf_read_abbrev_entry(entry, form, &tmp_buf, sizeof(tmp_buf), address_size);
                            strncpy(params[*nparams].name, tmp_buf, sizeof(params[*nparams].name));
                        }
                    } else if (name == DW_AT_type) {
                        if (form == DW_FORM_ref1 || form == DW_FORM_ref2 || form == DW_FORM_ref4 || form == DW_FORM_ref8) {
                            Dwarf_Off type_offset = 0;
                            entry += dwarf_read_abbrev_entry(entry, form, &type_offset, sizeof(type_offset), address_size);
                            char tmp_buf[DWARF_BUFSIZ];
                            int parse_res = parse_type_name(addrs, cu_offset, abbrev_offset, address_size, type_offset, tmp_buf);
                            if (parse_res) {
                                strncpy(params[*nparams].type_name, UNKNOWN_TYPE, sizeof(params[*nparams].type_name));
                            } else {
                                strncpy(params[*nparams].type_name, tmp_buf, sizeof(params[*nparams].type_name));
                            }
                        } else {
                            entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                            strncpy(params[*nparams].type_name, UNKNOWN_TYPE, sizeof(params[*nparams].type_name));
                        }
                    } else {
                        entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    }
                } while (name || form);

                *nparams = *nparams + 1;
            } else if (tag == DW_TAG_unspecified_parameters) {
                /* Parse variadic parameter */
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                    entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                } while (name || form);

                strncpy(params[*nparams].name, "...", sizeof(params[*nparams].name));
                strncpy(params[*nparams].type_name, UNKNOWN_TYPE, sizeof(params[*nparams].type_name));
                params[*nparams].is_variadic = 1;
                *nparams = *nparams + 1;
            } else {
                /* Parameters ended - just exit */
                return 0;
            }
        } else if (tag == DW_TAG_subprogram) {
            /* Parse subprogram DIE */
            uintptr_t low_pc = 0, high_pc = 0;
            const uint8_t *fn_name_entry = 0;
            uint64_t name_form = 0;
            do {
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                if (name == DW_AT_low_pc) {
                    entry += dwarf_read_abbrev_entry(entry, form, &low_pc, sizeof(low_pc), address_size);
                } else if (name == DW_AT_high_pc) {
                    entry += dwarf_read_abbrev_entry(entry, form, &high_pc, sizeof(high_pc), address_size);
                    if (form != DW_FORM_addr) high_pc += low_pc;
                } else {
                    if (name == DW_AT_name) {
                        fn_name_entry = entry;
                        name_form = form;
                    }
                    entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                }
            } while (name || form);

            /* Load info and finish if address is inside of the function */
            if (p >= low_pc && p <= high_pc) {
                *offset = low_pc;
                if (name_form == DW_FORM_strp) {
                    uintptr_t str_offset = 0;
                    (void)dwarf_read_abbrev_entry(fn_name_entry, name_form, &str_offset, sizeof(uintptr_t), address_size);
                    if (buf) put_unaligned((const uint8_t *)addrs->str_begin + str_offset, buf);
                } else {
                    (void)dwarf_read_abbrev_entry(fn_name_entry, name_form, buf, sizeof(uint8_t *), address_size);
                }
                is_after_subprogram = 1;
                *nparams = 0;
            }
        } else {
            /* Skip if not a subprogram */
            do {
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
            } while (name || form);
        }
    }
    return -E_NO_ENT;
}

int
address_by_fname(const struct Dwarf_Addrs *addrs, const char *fname, uintptr_t *offset) {
    const int flen = strlen(fname);
    if (!flen) return -E_INVAL;

    const uint8_t *pubnames_entry = addrs->pubnames_begin;
    uint32_t count = 0;
    uint64_t len = 0;
    Dwarf_Off cu_offset = 0, func_offset = 0;

    /* parse pubnames section */
    while (pubnames_entry < addrs->pubnames_end) {
        count = dwarf_entry_len(pubnames_entry, &len);
        if (!count) return -E_BAD_DWARF;
        pubnames_entry += count;

        const uint8_t *pubnames_entry_end = pubnames_entry + len;
        Dwarf_Half version = get_unaligned(pubnames_entry, Dwarf_Half);
        assert(version == 2);
        pubnames_entry += sizeof(Dwarf_Half);
        cu_offset = get_unaligned(pubnames_entry, uint32_t);
        pubnames_entry += sizeof(uint32_t);
        count = dwarf_entry_len(pubnames_entry, &len);
        pubnames_entry += count;

        while (pubnames_entry < pubnames_entry_end) {
            func_offset = get_unaligned(pubnames_entry, uint32_t);
            pubnames_entry += sizeof(uint32_t);

            if (!func_offset) break;

            if (!strcmp(fname, (const char *)pubnames_entry)) {
                /* Parse compilation unit header */
                const uint8_t *entry = addrs->info_begin + cu_offset;
                const uint8_t *func_entry = entry + func_offset;
                entry += count = dwarf_entry_len(entry, &len);
                if (!count) return -E_BAD_DWARF;

                Dwarf_Half version = get_unaligned(entry, Dwarf_Half);
                assert(version == 4 || version == 2);
                entry += sizeof(Dwarf_Half);
                Dwarf_Off abbrev_offset = get_unaligned(entry, uint32_t);
                entry += sizeof(uint32_t);
                const uint8_t *abbrev_entry = addrs->abbrev_begin + abbrev_offset;
                Dwarf_Small address_size = get_unaligned(entry, Dwarf_Small);
                assert(address_size == sizeof(uintptr_t));

                entry = func_entry;
                uint64_t abbrev_code = 0, table_abbrev_code = 0;
                entry += dwarf_read_uleb128(entry, &abbrev_code);
                uint64_t name = 0, form = 0, tag = 0;

                /* Find abbreviation in abbrev section */
                /* UNSAFE Needs to be replaced */
                while (abbrev_entry < addrs->abbrev_end) {
                    abbrev_entry += dwarf_read_uleb128(abbrev_entry, &table_abbrev_code);
                    abbrev_entry += dwarf_read_uleb128(abbrev_entry, &tag);
                    abbrev_entry += sizeof(Dwarf_Small);
                    if (table_abbrev_code == abbrev_code) break;

                    /* skip attributes */
                    do {
                        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &name);
                        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &form);
                    } while (name || form);
                }
                /* Find low_pc */
                if (tag == DW_TAG_subprogram) {
                    /* At this point entry points to the beginning of function's DIE attributes
                     * and abbrev_entry points to abbreviation table entry corresponding to this DIE.
                     * Abbreviation table entry consists of pairs of unsigned LEB128 numbers, the first
                     * encodes name of attribute and the second encodes its form. Attribute entry ends
                     * with a pair where both name and form equal zero.
                     * Address of a function is encoded in attribute with name DW_AT_low_pc.
                     * To find it, we need to scan both abbreviation table and attribute values.
                     * You can read unsigned LEB128 number using dwarf_read_uleb128 function.
                     * Attribute value can be obtained using dwarf_read_abbrev_entry function. */
                    uintptr_t low_pc = 0;
                    do {
                        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &name);
                        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &form);
                        if (name == DW_AT_low_pc) {
                            entry += dwarf_read_abbrev_entry(entry, form, &low_pc, sizeof(low_pc), address_size);
                        } else {
                            entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                        }
                    } while (name || form);
                    *offset = low_pc;
                } else {
                    /* Skip if not a subprogram or label */
                    do {
                        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &name);
                        abbrev_entry += dwarf_read_uleb128(abbrev_entry, &form);
                        entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    } while (name || form);
                }
                return 0;
            }
            pubnames_entry += strlen((const char *)pubnames_entry) + 1;
        }
    }
    return -E_NO_ENT;
}

int
naive_address_by_fname(const struct Dwarf_Addrs *addrs, const char *fname, uintptr_t *offset) {
    const int flen = strlen(fname);
    if (!flen) return -E_INVAL;

    for (const uint8_t *entry = addrs->info_begin; (const unsigned char *)entry < addrs->info_end;) {
        uint64_t len = 0;
        uint32_t count = dwarf_entry_len(entry, &len);
        entry += count;
        if (!count) return -E_BAD_DWARF;

        const uint8_t *entry_end = entry + len;

        /* Parse compilation unit header */
        Dwarf_Half version = get_unaligned(entry, Dwarf_Half);
        entry += sizeof(Dwarf_Half);
        assert(version == 4 || version == 2);
        Dwarf_Off abbrev_offset = get_unaligned(entry, uint32_t);
        /**/ entry += sizeof(uint32_t);
        Dwarf_Small address_size = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        assert(address_size == sizeof(uintptr_t));

        /* Parse related DIE's */
        uint64_t abbrev_code = 0, table_abbrev_code = 0;
        const uint8_t *abbrev_entry = addrs->abbrev_begin + abbrev_offset;

        while (entry < entry_end) {
            /* Read info abbreviation code */
            count = dwarf_read_uleb128(entry, &abbrev_code);
            entry += count;
            if (!abbrev_code) continue;

            /* Find abbreviation in abbrev section */
            /* UNSAFE, Needs to be replaced */
            const uint8_t *curr_abbrev_entry = abbrev_entry;
            uint64_t name = 0, form = 0, tag = 0;
            while ((const unsigned char *)curr_abbrev_entry < addrs->abbrev_end) {
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
                curr_abbrev_entry += sizeof(Dwarf_Small);
                if (table_abbrev_code == abbrev_code) break;

                /* skip attributes */
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                } while (name || form);
            }
            /* parse subprogram or label DIE */
            if (tag == DW_TAG_subprogram || tag == DW_TAG_label) {
                uintptr_t low_pc = 0;
                bool found = 0;
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                    if (name == DW_AT_low_pc) {
                        entry += dwarf_read_abbrev_entry(entry, form, &low_pc, sizeof(low_pc), address_size);
                    } else if (name == DW_AT_name) {
                        if (form == DW_FORM_strp) {
                            uint64_t str_offset = 0;
                            entry += dwarf_read_abbrev_entry(entry, form, &str_offset, sizeof(uint64_t), address_size);
                            if (!strcmp(fname, (const char *)addrs->str_begin + str_offset)) found = 1;
                        } else {
                            if (!strcmp(fname, (const char *)entry)) found = 1;
                            entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                        }
                    } else
                        entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                } while (name || form);
                if (found) {
                    /* finish if fname found */
                    *offset = low_pc;
                    return 0;
                }
            } else {
                /* Skip if not a subprogram or label */
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                    entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                } while (name || form);
            }
        }
    }

    return -E_NO_ENT;
}

int
global_variable_by_name(const struct Dwarf_Addrs *addrs, const char *var_name, struct Dwarf_VarInfo *var_info) {
    assert(addrs);
    assert(var_name);
    assert(var_info);

    if (strlen(var_name) == 0) return -E_INVAL;

    for (const uint8_t *entry = addrs->info_begin; (const unsigned char *)entry < addrs->info_end;) {
        Dwarf_Off cu_offset = entry - addrs->info_begin;

        uint64_t len = 0;
        uint32_t count = dwarf_entry_len(entry, &len);
        entry += count;
        if (!count) return -E_BAD_DWARF;

        const uint8_t *entry_end = entry + len;

        /* Parse compilation unit header */
        Dwarf_Half version = get_unaligned(entry, Dwarf_Half);
        entry += sizeof(Dwarf_Half);
        assert(version == 4 || version == 2);
        Dwarf_Off abbrev_offset = get_unaligned(entry, uint32_t);
        /**/ entry += sizeof(uint32_t);
        Dwarf_Small address_size = get_unaligned(entry, Dwarf_Small);
        entry += sizeof(Dwarf_Small);
        assert(address_size == sizeof(uintptr_t));

        /* Parse related DIE's */
        uint64_t abbrev_code = 0, table_abbrev_code = 0;
        const uint8_t *abbrev_entry = addrs->abbrev_begin + abbrev_offset;

        while (entry < entry_end) {
            /* Read info abbreviation code */
            count = dwarf_read_uleb128(entry, &abbrev_code);
            entry += count;
            if (!abbrev_code) continue;

            /* Find abbreviation in abbrev section */
            /* UNSAFE, Needs to be replaced */
            const uint8_t *curr_abbrev_entry = abbrev_entry;
            uint64_t name = 0, form = 0, tag = 0;
            while ((const unsigned char *)curr_abbrev_entry < addrs->abbrev_end) {
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &table_abbrev_code);
                curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &tag);
                curr_abbrev_entry += sizeof(Dwarf_Small);
                if (table_abbrev_code == abbrev_code) break;

                /* skip attributes */
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                } while (name || form);
            }

            if (tag == DW_TAG_variable) {
                bool found_name = 0;
                bool found_address = 0;
                uint64_t type_form = 0;
                const uint8_t* type_entry = NULL;
                uintptr_t address = 0;
                enum Dwarf_VarKind kind = KIND_UNKNOWN;
                uint8_t byte_size = 0;
                struct Dwarf_VarInfo *fields[DWARF_MAX_STRUCT_FIELDS] = { 0 };
                char type_name[DWARF_BUFSIZ];
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                    if (name == DW_AT_name) {
                        if (form == DW_FORM_strp) {
                            uint64_t str_offset = 0;
                            entry += dwarf_read_abbrev_entry(entry, form, &str_offset, sizeof(uint64_t), address_size);
                            if (!strcmp(var_name, (const char *)addrs->str_begin + str_offset)) found_name = 1;
                        } else {
                            if (!strcmp(var_name, (const char *)entry)) found_name = 1;
                            entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                        }
                    } else if (name == DW_AT_location) {
                        if (form == DW_FORM_exprloc) {
                            uint8_t buf[5];
                            entry += dwarf_read_abbrev_entry(entry, form, &buf, sizeof(buf), address_size);
                            if (buf[0] == DW_OP_addr) {
                                address = (buf[1] <<  0)
                                              + (buf[2] <<  8)
                                              + (buf[3] << 16)
                                              + (buf[4] << 24);
                                found_address = 1;
                            }
                        } else {
                            entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                        }
                    } else if (name == DW_AT_type) {
                        type_form = form;
                        type_entry = entry;
                        entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    } else {
                        entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                    }
                } while (name || form);
                if (found_name && found_address && type_entry != NULL) {
                    if (type_form == DW_FORM_ref1 || type_form == DW_FORM_ref2 || type_form == DW_FORM_ref4 || type_form == DW_FORM_ref8) {
                        Dwarf_Off type_offset = 0;
                        type_entry += dwarf_read_abbrev_entry(type_entry, type_form, &type_offset, sizeof(type_offset), address_size);
                        int parse_res = parse_var_info(addrs, cu_offset, abbrev_offset, address_size, type_offset, &kind, &byte_size, fields);
                        if (parse_res < 0) {
                            kind = KIND_UNKNOWN;
                            byte_size = 0;
                        }

                        parse_res = parse_type_name(addrs, cu_offset, abbrev_offset, address_size, type_offset, type_name);
                        if (parse_res < 0) {
                            strncpy(type_name, UNKNOWN_TYPE, sizeof(type_name));
                        }
                    } else {
                        (void)dwarf_read_abbrev_entry(type_entry, type_form, NULL, 0, address_size);
                        kind = KIND_UNKNOWN;
                        byte_size = 0;
                        strncpy(type_name, UNKNOWN_TYPE, sizeof(type_name));
                    }

                    var_info->address = address;
                    var_info->kind = kind;
                    var_info->byte_size = byte_size;
                    strncpy(var_info->type_name, type_name, DWARF_BUFSIZ);
                    memcpy(var_info->fields, fields, sizeof(var_info->fields));
                    return 0;
                }
            } else {
                do {
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &name);
                    curr_abbrev_entry += dwarf_read_uleb128(curr_abbrev_entry, &form);
                    entry += dwarf_read_abbrev_entry(entry, form, NULL, 0, address_size);
                } while (name || form);
            }
        }
    }

    return -E_NO_ENT;
}

/*
 * crunch-ld - a small, GNU-ld-compatible static linker for x86-64 Linux ELF.
 *
 *   cc -O2 -Wall -iquote ../../include -iquote ../../build -o crunch-ld crunch-ld.c
 *   ./crunch-ld -o prog start.o file1.o file2.o -T script.ld
 */
#define _GNU_SOURCE
#include "version.h"
#include "crunch-linker-config.h"
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef CRUNCH_DEFAULT_CONF_FILE
#define CRUNCH_DEFAULT_CONF_FILE "/etc/crunch/crunch.conf"
#endif
#ifndef CRUNCH_DEFAULT_RUNTIME_DIR
#define CRUNCH_DEFAULT_RUNTIME_DIR "/usr/local/lib/crunch"
#endif

#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX 41
#endif
#ifndef R_X86_64_REX_GOTPCRELX
#define R_X86_64_REX_GOTPCRELX 42
#endif

#ifndef SHT_X86_64_UNWIND
#define SHT_X86_64_UNWIND 0x70000001
#endif
#ifndef SHF_GNU_RETAIN
#define SHF_GNU_RETAIN 0x200000
#endif

#define PAGE 0x1000ULL
#define NBUCKET 16384

/* ------------------------------------------------------------------ util */

static const char *prog = "crunch-ld";
static int nerrors;
static int nostdlib = 0;
static int use_crt0 = 0;
static int is_pie = 0;
static int is_shared = 0;
static int is_dynamic = 0;
static int relocatable = 0;
static int relro = 0;
static int warn_abi_mismatch = 0;
static const char *dynamic_linker = NULL;
static int gc_enabled, print_gc, strip_level = 0;

/*
 * Print error message to stderr and exit with failure status 1.
 * Inputs: fmt - format string, ... - format arguments
 * Outputs: None (terminates process)
 */
static void die(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s: error: ", prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/*
 * Record a linker error, increment nerrors counter, and print message to stderr.
 * Inputs: fmt - format string, ... - format arguments
 * Outputs: None
 */
static void error(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s: error: ", prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    nerrors++;
}

/*
 * Print a warning message to stderr.
 * Inputs: fmt - format string, ... - format arguments
 * Outputs: None
 */
static void warn(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s: warning: ", prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/*
 * Allocate zero-initialized memory safely, aborting on allocation failure.
 * Inputs: n - number of elements, s - size of each element
 * Outputs: Pointer to allocated memory buffer
 */
static void *xcalloc(size_t n, size_t s) {
    void *p = calloc(n ? n : 1, s ? s : 1);
    if (!p) die("out of memory");
    return p;
}
/*
 * Reallocate memory buffer safely, aborting on allocation failure.
 * Inputs: p - existing buffer pointer, n - new size in bytes
 * Outputs: Pointer to resized memory buffer
 */
static void *xrealloc(void *p, size_t n) {
    p = realloc(p, n ? n : 1);
    if (!p) die("out of memory");
    return p;
}
/*
 * Duplicate a null-terminated string safely.
 * Inputs: s - source string
 * Outputs: Newly allocated copy of the string
 */
static char *xstrdup(const char *s) {
    char *r = xcalloc(strlen(s) + 1, 1);
    return strcpy(r, s);
}

#define GROW(arr, n, cap)                                          \
    do {                                                           \
        if ((n) >= (cap)) {                                        \
            (cap) = (cap) ? (cap) * 2 : 16;                        \
            (arr) = xrealloc((arr), (size_t)(cap) * sizeof(*(arr))); \
        }                                                          \
    } while (0)

/*
 * Align a numeric value up to the nearest multiple of alignment a.
 * Inputs: v - value to align, a - alignment boundary
 * Outputs: Aligned 64-bit unsigned integer
 */
static uint64_t align_up(uint64_t v, uint64_t a) {
    if (a <= 1) return v;
    return (v + a - 1) & ~(a - 1);
}

/*
 * Read an entire file into memory safely with bounds checks.
 * Inputs: path - file path, len - pointer to store read file length
 * Outputs: Pointer to allocated file content buffer
 */
static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    size_t sz = (size_t)n;
    if (sz > SIZE_MAX - 16) die("%s: file too large", path);
    uint8_t *b = xcalloc(sz + 8, 1);
    if (sz > 0 && fread(b, 1, sz, f) != sz) die("%s: read error", path);
    fclose(f);
    *len = sz;
    return b;
}

typedef struct { uint8_t *p; size_t n, cap; } Buf;

/*
 * Append binary data to a dynamic buffer structure.
 * Inputs: b - pointer to Buf structure, d - data pointer, n - size in bytes
 * Outputs: Offset where data was added within buffer
 */
static size_t buf_add(Buf *b, const void *d, size_t n) {
    if (n > SIZE_MAX - b->n) die("output too large");
    size_t need = b->n + n;
    if (need > b->cap) {
        b->cap = need <= (SIZE_MAX - 64) / 2 ? need * 2 + 64 : need;
        b->p = xrealloc(b->p, b->cap);
    }
    if (n) memcpy(b->p + b->n, d, n);
    size_t r = b->n;
    b->n += n;
    return r;
}

/* ------------------------------------------------------------ data model */

enum { C_TEXT, C_RODATA, C_CRUNCH_ABI, C_EHFRAME, C_TDATA, C_TBSS, C_INITARR, C_FINIARR,
       C_CRUNCH_INIT, C_CRUNCH_STATIC, C_GOT, C_DATA_REL_RO, C_DATA, C_BSS, C_COMMENT, NCLS };
static const char *cls_name[NCLS] = {".text", ".rodata", "__crunch_abi", ".eh_frame", ".tdata", ".tbss", ".init_array", ".fini_array",
                                     "__crunch_init_array", "__crunch_static_arrays",
                                     ".got", ".data.rel.ro", ".data", ".bss", ".comment"};

typedef struct {
    uint64_t addr, off, size, align;
    int shndx;
} OutSec;
static OutSec out[NCLS];
static OutSec shared_dynsym, shared_dynstr, shared_hash, shared_dynamic, shared_rela, shared_plt;
static Buf shared_strings, shared_hash_data;

/* Preserve the process-entry registers and stack while calling constructors. */
static const uint8_t executable_init_code[] = {
    0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x4c, 0x8d, 0x64, 0x24, 0x78,       /* original stack -> r12 */
    0x48, 0x83, 0xe4, 0xf0,             /* align stack for calls */
    0x4c, 0x8d, 0x2d, 0, 0, 0, 0,       /* array start -> r13 */
    0x4c, 0x8d, 0x35, 0, 0, 0, 0,       /* array end -> r14 */
    0x4d, 0x39, 0xf5, 0x73, 0x18,       /* loop until r13 >= r14 */
    0x49, 0x8b, 0x3c, 0x24,             /* argc */
    0x49, 0x8d, 0x74, 0x24, 0x08,       /* argv */
    0x48, 0x8d, 0x54, 0xfe, 0x08,       /* envp */
    0x41, 0xff, 0x55, 0x00,             /* call *(r13) */
    0x49, 0x83, 0xc5, 0x08, 0xeb, 0xe3,
    0x49, 0x8d, 0x64, 0x24, 0x88,       /* restore saved-register stack */
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c,
    0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
    0x5f, 0x5e, 0x5d, 0x5b, 0x5a, 0x59, 0x58,
    0xe9, 0, 0, 0, 0                    /* jump to original entry */
};
enum { EXEC_INIT_START = 0x23, EXEC_INIT_END = 0x2a, EXEC_INIT_ENTRY = 0x68 };
_Static_assert(sizeof executable_init_code == 0x6c, "executable init code size");
static uint64_t executable_init_offset;

/* A guarded, ABI-preserving reverse traversal of the executable fini array. */
static const uint8_t executable_fini_code[] = {
    0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xec, 0x08,
    0x48, 0x8d, 0x05, 0, 0, 0, 0,      /* guard address */
    0xb9, 0x01, 0, 0, 0, 0x86, 0x08,    /* atomically mark as run */
    0x84, 0xc9, 0x75, 0x1d,
    0x4c, 0x8d, 0x25, 0, 0, 0, 0,      /* array end -> r12 */
    0x4c, 0x8d, 0x2d, 0, 0, 0, 0,      /* array start -> r13 */
    0x4d, 0x39, 0xec, 0x76, 0x0a,
    0x49, 0x83, 0xec, 0x08, 0x41, 0xff, 0x14, 0x24, 0xeb, 0xf1,
    0x48, 0x83, 0xc4, 0x08, 0x41, 0x5d, 0x41, 0x5c, 0xc3
};
enum { EXEC_FINI_GUARD = 0x0b, EXEC_FINI_END = 0x1d, EXEC_FINI_START = 0x24 };
_Static_assert(sizeof executable_fini_code == 0x40, "executable fini code size");
static uint64_t executable_fini_offset, executable_fini_guard;

typedef struct Obj Obj;
typedef struct EhInfo EhInfo;
/*  */

typedef struct {
    Obj *obj;
    Elf64_Shdr *sh;
    int live, cls, discarded, group;
    int marked;     
    int rela;       
    EhInfo *eh;     
    uint64_t off;   
    uint64_t addr;  
    uint64_t foff;  
} InSec;

enum { S_UNDEF, S_DEF, S_COMMON };

typedef struct GSym GSym;
typedef struct AbiRecord AbiRecord;
struct GSym {
    const char *name;
    GSym *next;
    int state, weak, strong_ref, shared_ref, linker, reported, got, keep_undefined;
    int dynamic_defined, dynamic_definitions, dynamic_last_input, required, datarel;
    int runtime_guard_input, runtime_guard_shared;
    int abi_shared_epoch, abi_shared_flags;
    Obj *obj;
    unsigned shndx;
    uint64_t value, size, align;
    uint8_t type;
    uint8_t visibility;
    uint64_t addr;
    uint32_t output_index;
    uint32_t shared_index;
    int plt;
    const Elf64_Sym *original;
    AbiRecord *abi_defs;
};

struct Obj {
    const char *name;
    uint8_t *buf;
    size_t size;
    Elf64_Ehdr *eh;
    Elf64_Shdr *sh;
    int nsh;
    Elf64_Sym *syms;
    int nsyms, first_global;
    const char *strtab;
    size_t strtabsz;
    const char *shstr;
    uint64_t shstrsz;
    InSec *secs;
    GSym **gs;  
    int *got;   
    uint32_t *section_map;
    uint32_t *symbol_map;
};

typedef struct { Obj *o; int si; } GotEnt;

static GSym *symtab[NBUCKET], *comdats[NBUCKET];
static GSym **allsyms;
static int nall, capall;
static GSym **shared_symbols;
static uint32_t *shared_names;
static size_t shared_count;
static int shared_plt_count;
static int shared_datarel_count, shared_datarel_written;
typedef struct { InSec *sec; unsigned priority; int unnumbered, order; } SharedArray;
static SharedArray *shared_arrays;
static int nshared_arrays, capshared_arrays, shared_init, shared_fini;
typedef struct { char *name; uint32_t string_offset; } Needed;
static Needed *shared_needed;
static int nshared_needed, capshared_needed;
static const char *shared_soname;
static uint32_t shared_soname_offset;
static Buf shared_runpath;
static uint32_t shared_runpath_offset;
static GSym *executable_fini_symbol;

/*
 * Test whether the output requires dynamic linker metadata.
 * Inputs: None
 * Outputs: Nonzero for shared objects and dynamic executables.
 */
static int dynamic_output(void) { return is_shared || is_dynamic; }

/*
 * Decide whether a symbol must be resolved by the dynamic loader.
 * Inputs: g - global symbol or NULL for a local symbol.
 * Outputs: Nonzero for undefined symbols and preemptible shared definitions.
 */
static int dynamic_preemptible(GSym *g) {
    return g && (g->state == S_UNDEF || (is_shared && g->visibility == STV_DEFAULT));
}

/*
 * Identify symbols whose values move with the output image.
 * Inputs: o - input object; si - symbol-table index.
 * Outputs: Nonzero for a defined, image-relative symbol.
 */
static int image_relative_symbol(Obj *o, uint32_t si) {
    if ((int)si >= o->first_global) {
        GSym *g = o->gs[si];
        return g && (g->state == S_COMMON ||
                     (g->state == S_DEF && (g->linker || g->shndx != SHN_ABS)));
    }
    return o->syms[si].st_shndx != SHN_ABS && o->syms[si].st_shndx != SHN_UNDEF;
}

/*
 * Identify linker-provided Crunch module registry boundary symbols.
 * Inputs: name - symbol name.
 * Outputs: Nonzero for a registry boundary.
 */
static int crunch_registry_symbol(const char *name) {
    return !strcmp(name, "__start___crunch_init_array") ||
           !strcmp(name, "__stop___crunch_init_array") ||
           !strcmp(name, "__start___crunch_static_arrays") ||
           !strcmp(name, "__stop___crunch_static_arrays");
}

static Obj **objs;
static int nobjs, capobjs;
typedef struct {
    Obj *obj;
    uint64_t nsyms;
    const Elf64_Half *versions;
} SharedAbiInput;
static SharedAbiInput *abi_shared_inputs;
static int nabi_shared_inputs, capabi_shared_inputs;

static int ngot;
static GotEnt *got_entries;
static int capgot;

static const char *script_entry_sym = NULL;
static uint64_t script_base_addr = 0;
static int has_script_base = 0;

static GSym *lookup(GSym **tab, const char *name, int create) {
    uint32_t h = 2166136261u;
    for (const char *p = name; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
    GSym **b = &tab[h % NBUCKET];
    for (GSym *g = *b; g; g = g->next)
        if (!strcmp(g->name, name)) return g;
    if (!create) return NULL;
    GSym *g = xcalloc(1, sizeof *g);
    g->name = xstrdup(name);
    g->next = *b;
    *b = g;
    if (tab == symtab) { GROW(allsyms, nall, capall); allsyms[nall++] = g; }
    return g;
}

static void *at(Obj *o, uint64_t off, uint64_t len) {
    if (off > o->size || len > o->size - off) die("%s: file truncated or corrupt", o->name);
    return o->buf + off;
}

/*
 * Register an ELF shared input, its loader name, and its visible definitions.
 * Inputs: path - input path; buf/size - file contents; searched - found by -l.
 * Outputs: Adds one ordered dependency and records symbols for archive selection;
 *          returns nonzero if the buffer is retained for ABI diagnostics.
 */
static int add_shared_input(const char *path, uint8_t *buf, size_t size, int searched) {
    Obj file = {.name = path, .buf = buf, .size = size};
    Elf64_Ehdr eh;
    memcpy(&eh, at(&file, 0, sizeof eh), sizeof eh);
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_version != EV_CURRENT || eh.e_type != ET_DYN || eh.e_machine != EM_X86_64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || !eh.e_phnum ||
        eh.e_shentsize != sizeof(Elf64_Shdr) || !eh.e_shnum)
        die("%s: unsupported ELF shared object", path);
    at(&file, eh.e_phoff, (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr));
    at(&file, eh.e_shoff, (uint64_t)eh.e_shnum * sizeof(Elf64_Shdr));
    Elf64_Phdr dynamic = {0};
    int found_dynamic = 0;
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, at(&file, eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph), sizeof ph);
        if (ph.p_type == PT_LOAD) at(&file, ph.p_offset, ph.p_filesz);
        if (ph.p_type == PT_DYNAMIC) {
            if (found_dynamic++) die("%s: multiple dynamic segments", path);
            dynamic = ph;
        }
    }
    if (!found_dynamic || dynamic.p_filesz % sizeof(Elf64_Dyn))
        die("%s: invalid shared dynamic segment", path);
    at(&file, dynamic.p_offset, dynamic.p_filesz);
    uint64_t straddr = 0, strsize = 0, symaddr = 0, syment = 0, soname = 0;
    int have_straddr = 0, have_strsize = 0, have_symaddr = 0, have_syment = 0;
    int have_soname = 0, terminated = 0;
    for (uint64_t off = 0; off < dynamic.p_filesz; off += sizeof(Elf64_Dyn)) {
        Elf64_Dyn d;
        memcpy(&d, at(&file, dynamic.p_offset + off, sizeof d), sizeof d);
        if (d.d_tag == DT_NULL) { terminated = 1; break; }
        if (d.d_tag == DT_STRTAB) {
            if (have_straddr++) die("%s: duplicate dynamic string table", path);
            straddr = d.d_un.d_ptr;
        } else if (d.d_tag == DT_STRSZ) {
            if (have_strsize++) die("%s: duplicate dynamic string size", path);
            strsize = d.d_un.d_val;
        } else if (d.d_tag == DT_SYMTAB) {
            if (have_symaddr++) die("%s: duplicate dynamic symbol table", path);
            symaddr = d.d_un.d_ptr;
        } else if (d.d_tag == DT_SYMENT) {
            if (have_syment++) die("%s: duplicate dynamic symbol size", path);
            syment = d.d_un.d_val;
        } else if (d.d_tag == DT_SONAME) {
            if (have_soname++) die("%s: duplicate SONAME", path);
            soname = d.d_un.d_val;
        } else if (d.d_tag == DT_FLAGS_1 && (d.d_un.d_val & DF_1_PIE))
            die("%s: dynamic executables are not supported as inputs", path);
    }
    if (!terminated || !have_straddr || !have_strsize || !strsize ||
        !have_symaddr || !have_syment || syment != sizeof(Elf64_Sym))
        die("%s: invalid shared dynamic string table", path);
    const char *strings = NULL;
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, at(&file, eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph), sizeof ph);
        if (ph.p_type != PT_LOAD || straddr < ph.p_vaddr) continue;
        uint64_t offset = straddr - ph.p_vaddr;
        if (offset <= ph.p_filesz && strsize <= ph.p_filesz - offset) {
            strings = at(&file, ph.p_offset + offset, strsize);
            break;
        }
    }
    if (!strings || strings[0] || strings[strsize - 1])
        die("%s: invalid shared dynamic strings", path);
    const char *fallback = searched ? strrchr(path, '/') : NULL;
    const char *needed = searched && fallback ? fallback + 1 : path;
    if (have_soname) {
        if (soname >= strsize || !strings[soname] || !memchr(strings + soname, 0, strsize - soname))
            die("%s: invalid SONAME", path);
        needed = strings + soname;
    }
    for (int i = 0; i < nshared_needed; i++)
        if (!strcmp(shared_needed[i].name, needed)) return 0;

    Elf64_Shdr symtab_sh = {0};
    unsigned symtab_index = 0;
    for (unsigned i = 1; i < eh.e_shnum; i++) {
        Elf64_Shdr sh;
        memcpy(&sh, at(&file, eh.e_shoff + (uint64_t)i * sizeof sh, sizeof sh), sizeof sh);
        if (sh.sh_type != SHT_DYNSYM) continue;
        if (symtab_index) die("%s: multiple dynamic symbol tables", path);
        symtab_index = i;
        symtab_sh = sh;
    }
    if (!symtab_index || symtab_sh.sh_addr != symaddr ||
        symtab_sh.sh_entsize != sizeof(Elf64_Sym) ||
        symtab_sh.sh_size % sizeof(Elf64_Sym) || symtab_sh.sh_link >= eh.e_shnum)
        die("%s: unsupported shared dynamic symbol table", path);
    at(&file, symtab_sh.sh_offset, symtab_sh.sh_size);
    int mapped_symbols = 0;
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, at(&file, eh.e_phoff + (uint64_t)i * sizeof ph, sizeof ph), sizeof ph);
        if (ph.p_type != PT_LOAD || symaddr < ph.p_vaddr) continue;
        uint64_t offset = symaddr - ph.p_vaddr;
        if (offset <= ph.p_filesz && symtab_sh.sh_size <= ph.p_filesz - offset &&
            ph.p_offset + offset == symtab_sh.sh_offset) mapped_symbols = 1;
    }
    if (!mapped_symbols) die("%s: dynamic symbols are not mapped by a load segment", path);
    Elf64_Shdr symstrings;
    memcpy(&symstrings, at(&file, eh.e_shoff + (uint64_t)symtab_sh.sh_link * sizeof symstrings,
                           sizeof symstrings), sizeof symstrings);
    const char *names = at(&file, symstrings.sh_offset, symstrings.sh_size);
    if (symstrings.sh_type != SHT_STRTAB || symstrings.sh_addr != straddr ||
        symstrings.sh_size != strsize || !symstrings.sh_size ||
        names != strings || names[0] || names[symstrings.sh_size - 1])
        die("%s: invalid shared symbol strings", path);
    Elf64_Shdr versions = {0};
    int have_versions = 0;
    for (unsigned i = 1; i < eh.e_shnum; i++) {
        Elf64_Shdr sh;
        memcpy(&sh, at(&file, eh.e_shoff + (uint64_t)i * sizeof sh, sizeof sh), sizeof sh);
        if (sh.sh_type != SHT_GNU_versym || sh.sh_link != symtab_index) continue;
        if (have_versions++) die("%s: multiple symbol version tables", path);
        versions = sh;
    }
    uint64_t nsym = symtab_sh.sh_size / sizeof(Elf64_Sym);
    if (have_versions) {
        if (versions.sh_size != nsym * sizeof(Elf64_Half))
            die("%s: invalid symbol version table", path);
        at(&file, versions.sh_offset, versions.sh_size);
    }
    int has_runtime_guard = 0;
    for (uint64_t i = 1; i < nsym; i++) {
        Elf64_Sym sym;
        memcpy(&sym, at(&file, symtab_sh.sh_offset + i * sizeof sym, sizeof sym), sizeof sym);
        if (sym.st_name >= symstrings.sh_size ||
            !memchr(names + sym.st_name, 0, symstrings.sh_size - sym.st_name))
            die("%s: invalid dynamic symbol name", path);
        unsigned bind = ELF64_ST_BIND(sym.st_info), visibility = ELF64_ST_VISIBILITY(sym.st_other);
        if (!names[sym.st_name] || sym.st_shndx == SHN_UNDEF ||
            (bind != STB_GLOBAL && bind != STB_WEAK && bind != STB_GNU_UNIQUE) ||
            (visibility != STV_DEFAULT && visibility != STV_PROTECTED)) continue;
        if (have_versions) {
            Elf64_Half version;
            memcpy(&version, at(&file, versions.sh_offset + i * sizeof version, sizeof version), sizeof version);
            if ((version & 0x8000) || (version & 0x7fff) == 0) continue;
        }
        GSym *g = lookup(symtab, names + sym.st_name, 1);
        g->dynamic_defined = 1;
        if (g->dynamic_last_input != nshared_needed + 1) {
            g->dynamic_last_input = nshared_needed + 1;
            g->dynamic_definitions++;
        }
        static const char prefix[] = "__crunch_dso_guard_";
        const char *symbol = names + sym.st_name;
        if (!strncmp(symbol, prefix, sizeof prefix - 1) && symbol[sizeof prefix - 1]) {
            lookup(symtab, symbol + sizeof prefix - 1, 1)->runtime_guard_input =
                nshared_needed + 1;
            has_runtime_guard = 1;
        }
    }
    for (unsigned i = 1; i < eh.e_shnum; i++) {
        Elf64_Shdr symbols, strtab;
        memcpy(&symbols, at(&file, eh.e_shoff + (uint64_t)i * sizeof symbols, sizeof symbols),
               sizeof symbols);
        if (symbols.sh_type != SHT_SYMTAB || symbols.sh_entsize != sizeof(Elf64_Sym) ||
            symbols.sh_size % sizeof(Elf64_Sym) || symbols.sh_link >= eh.e_shnum ||
            symbols.sh_offset > file.size || symbols.sh_size > file.size - symbols.sh_offset)
            continue;
        memcpy(&strtab, at(&file, eh.e_shoff + (uint64_t)symbols.sh_link * sizeof strtab,
                           sizeof strtab), sizeof strtab);
        if (strtab.sh_type != SHT_STRTAB || strtab.sh_offset > file.size ||
            strtab.sh_size > file.size - strtab.sh_offset)
            continue;
        const char *static_names = (const char *)file.buf + strtab.sh_offset;
        static const char prefix[] = "__crunch_dso_guard_";
        for (uint64_t j = 1; j < symbols.sh_size / sizeof(Elf64_Sym); j++) {
            Elf64_Sym sym;
            memcpy(&sym, at(&file, symbols.sh_offset + j * sizeof sym, sizeof sym), sizeof sym);
            if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= eh.e_shnum ||
                sym.st_name >= strtab.sh_size)
                continue;
            const char *symbol = static_names + sym.st_name;
            if (!memchr(symbol, 0, strtab.sh_size - sym.st_name) ||
                strncmp(symbol, prefix, sizeof prefix - 1) || !symbol[sizeof prefix - 1])
                continue;
            Elf64_Shdr target;
            memcpy(&target, at(&file, eh.e_shoff + (uint64_t)sym.st_shndx * sizeof target,
                               sizeof target), sizeof target);
            if (!(target.sh_flags & SHF_ALLOC))
                continue;
            lookup(symtab, symbol + sizeof prefix - 1, 1)->runtime_guard_input =
                nshared_needed + 1;
            has_runtime_guard = 1;
        }
    }
    if (eh.e_shstrndx < eh.e_shnum) {
        Elf64_Shdr shnames;
        memcpy(&shnames, at(&file, eh.e_shoff + (uint64_t)eh.e_shstrndx * sizeof shnames,
                            sizeof shnames), sizeof shnames);
        if (shnames.sh_type == SHT_STRTAB &&
            shnames.sh_offset <= file.size && shnames.sh_size <= file.size - shnames.sh_offset) {
            const char *section_names = (const char *)file.buf + shnames.sh_offset;
            for (unsigned i = 1; i < eh.e_shnum; i++) {
                Elf64_Shdr sh;
                memcpy(&sh, at(&file, eh.e_shoff + (uint64_t)i * sizeof sh, sizeof sh), sizeof sh);
                if (sh.sh_name >= shnames.sh_size ||
                    !memchr(section_names + sh.sh_name, 0, shnames.sh_size - sh.sh_name) ||
                    strcmp(section_names + sh.sh_name, "__crunch_abi") ||
                    sh.sh_type != SHT_PROGBITS || !(sh.sh_flags & SHF_ALLOC))
                    continue;
                const char *data = at(&file, sh.sh_offset, sh.sh_size);
                size_t pos = 0;
                while (pos < sh.sh_size) {
                    const char *end = memchr(data + pos, '\n', sh.sh_size - pos);
                    if (!end)
                        break;
                    size_t length = (size_t)(end - (data + pos));
                    if (length > 8 && length < 136 && !memcmp(data + pos, "CABI1 G ", 8)) {
                        char name[128];
                        size_t n = length - 8;
                        int valid = (data[pos + 8] >= 'A' && data[pos + 8] <= 'Z') ||
                                    (data[pos + 8] >= 'a' && data[pos + 8] <= 'z') ||
                                    data[pos + 8] == '_';
                        for (size_t j = 0; valid && j < n; j++) {
                            unsigned char c = (unsigned char)data[pos + 8 + j];
                            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                  (c >= '0' && c <= '9') || c == '_'))
                                valid = 0;
                        }
                        if (valid) {
                            memcpy(name, data + pos + 8, n);
                            name[n] = 0;
                            lookup(symtab, name, 1)->runtime_guard_input = nshared_needed + 1;
                            has_runtime_guard = 1;
                        }
                    }
                    pos += length + 1;
                }
            }
        }
    }
    for (uint64_t i = 1; has_runtime_guard && i < nsym; i++) {
        Elf64_Sym sym;
        memcpy(&sym, at(&file, symtab_sh.sh_offset + i * sizeof sym, sizeof sym), sizeof sym);
        if (sym.st_shndx != SHN_UNDEF || sym.st_name >= symstrings.sh_size)
            continue;
        GSym *g = lookup(symtab, names + sym.st_name, 0);
        if (g && g->runtime_guard_input == nshared_needed + 1)
            g->runtime_guard_shared = 1;
    }
    for (unsigned i = 1; has_runtime_guard && i < eh.e_shnum; i++) {
        Elf64_Shdr sh;
        memcpy(&sh, at(&file, eh.e_shoff + (uint64_t)i * sizeof sh, sizeof sh), sizeof sh);
        if (sh.sh_type != SHT_RELA || sh.sh_link != symtab_index || !(sh.sh_flags & SHF_ALLOC))
            continue;
        if (sh.sh_entsize != sizeof(Elf64_Rela) || sh.sh_size % sizeof(Elf64_Rela))
            die("%s: invalid shared dynamic relocations", path);
        at(&file, sh.sh_offset, sh.sh_size);
        for (uint64_t j = 0; j < sh.sh_size / sizeof(Elf64_Rela); j++) {
            Elf64_Rela rel;
            memcpy(&rel, at(&file, sh.sh_offset + j * sizeof rel, sizeof rel), sizeof rel);
            uint64_t index = ELF64_R_SYM(rel.r_info);
            if (!index || index >= nsym)
                continue;
            Elf64_Sym sym;
            memcpy(&sym, at(&file, symtab_sh.sh_offset + index * sizeof sym, sizeof sym),
                   sizeof sym);
            if (sym.st_shndx == SHN_UNDEF || ELF64_ST_VISIBILITY(sym.st_other) != STV_DEFAULT)
                continue;
            GSym *g = lookup(symtab, names + sym.st_name, 0);
            if (g && g->runtime_guard_input == nshared_needed + 1)
                g->runtime_guard_shared = 1;
        }
    }
    GROW(shared_needed, nshared_needed, capshared_needed);
    shared_needed[nshared_needed++] = (Needed){xstrdup(needed), 0};
    if (warn_abi_mismatch) {
        Obj *saved = xcalloc(1, sizeof *saved);
        saved->name = xstrdup(path);
        saved->buf = buf;
        saved->size = size;
        saved->nsh = eh.e_shnum;
        saved->sh = at(saved, eh.e_shoff, (uint64_t)eh.e_shnum * sizeof(Elf64_Shdr));
        if (eh.e_shstrndx < eh.e_shnum) {
            Elf64_Shdr *shnames = &saved->sh[eh.e_shstrndx];
            if (shnames->sh_type == SHT_STRTAB && shnames->sh_offset <= size &&
                shnames->sh_size <= size - shnames->sh_offset) {
                saved->shstr = at(saved, shnames->sh_offset, shnames->sh_size);
                saved->shstrsz = shnames->sh_size;
            }
        }
        saved->syms = at(saved, symtab_sh.sh_offset, symtab_sh.sh_size);
        saved->strtab = names;
        saved->strtabsz = symstrings.sh_size;
        GROW(abi_shared_inputs, nabi_shared_inputs, capabi_shared_inputs);
        abi_shared_inputs[nabi_shared_inputs++] = (SharedAbiInput){
            saved, nsym, have_versions ? at(saved, versions.sh_offset, versions.sh_size) : NULL
        };
        return 1;
    }
    return 0;
}

/* --------------------------------------------------------- linker script parser */

typedef struct {
    char name[32];
    uint64_t origin;
    uint64_t length;
} MemRegion;

static MemRegion mem_regions[8];
static int nmem_regions = 0;


typedef struct {
    char name[64];
    uint64_t value;
    int is_align;
} ScriptSymDef;

static ScriptSymDef script_syms[32];
static int nscript_syms = 0;
static int parse_linker_script(const char *path, const char *text) {
    (void)path;
    const char *p = text;
    int recognized = 0;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (p[0] == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/')) p++;
            if (*p) p += 2;
            continue;
        }

        if (!strncmp(p, "ENTRY", 5)) {
            const char *next = p + 5;
            while (isspace((unsigned char)*next)) next++;
            if (*next == '(') recognized = 1;
            p += 5;
            while (*p && *p != '(') p++;
            if (*p == '(') p++;
            while (*p && isspace((unsigned char)*p)) p++;
            const char *start = p;
            while (*p && *p != ')' && !isspace((unsigned char)*p)) p++;
            size_t len = p - start;
            char *sym = xcalloc(len + 1, 1);
            memcpy(sym, start, len);
            script_entry_sym = sym;
            while (*p && *p != ')') p++;
            if (*p == ')') p++;
            continue;
        }

        if (!strncmp(p, "MEMORY", 6)) {
            const char *next = p + 6;
            while (isspace((unsigned char)*next)) next++;
            if (*next == '{') recognized = 1;
            p += 6;
            while (*p && *p != '{') p++;
            if (*p == '{') p++;
            while (*p) {
                while (*p && isspace((unsigned char)*p)) p++;
                if (*p == '}') { p++; break; }
                if (!*p) break;
                const char *rstart = p;
                while (*p && !isspace((unsigned char)*p) && *p != '(' && *p != ':') p++;
                size_t rlen = p - rstart;
                if (rlen >= 32) rlen = 31;
                char rname[32];
                memcpy(rname, rstart, rlen);
                rname[rlen] = 0;

                while (*p && *p != ':') p++;
                if (*p == ':') p++;

                uint64_t orig = 0, len_val = 0;
                while (*p && *p != '}') {
                    if (!strncmp(p, "ORIGIN", 6)) {
                        p += 6;
                        while (*p && *p != '=') p++;
                        if (*p == '=') p++;
                        while (*p && isspace((unsigned char)*p)) p++;
                        orig = strtoull(p, (char **)&p, 0);
                    } else if (!strncmp(p, "LENGTH", 6)) {
                        p += 6;
                        while (*p && *p != '=') p++;
                        if (*p == '=') p++;
                        while (*p && isspace((unsigned char)*p)) p++;
                        len_val = strtoull(p, (char **)&p, 0);
                        while (*p && isspace((unsigned char)*p)) p++;
                        if (*p == 'K' || *p == 'k') { len_val *= 1024; p++; }
                        else if (*p == 'M' || *p == 'm') { len_val *= 1024 * 1024; p++; }
                    }
                    p++;
                }
                if (nmem_regions < 8) {
                    strcpy(mem_regions[nmem_regions].name, rname);
                    mem_regions[nmem_regions].origin = orig;
                    mem_regions[nmem_regions].length = len_val;
                    nmem_regions++;
                }
                while (*p && *p != '}' && *p != ';') p++;
                if (*p == ';') p++;
            }
            continue;
        }

        if (p[0] == '.' && p[1] == '=') {
            recognized = 1;
            p += 2;
            while (*p && isspace((unsigned char)*p)) p++;
            script_base_addr = strtoull(p, (char **)&p, 0);
            has_script_base = 1;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        if (isalpha((unsigned char)*p) || *p == '_') {
            const char *sstart = p;
            while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
            size_t slen = p - sstart;
            if (slen == 8 && !strncmp(sstart, "SECTIONS", slen)) {
                const char *next = p;
                while (isspace((unsigned char)*next)) next++;
                if (*next == '{') recognized = 1;
            }
            if (slen < 64) {
                char symname[64];
                memcpy(symname, sstart, slen);
                symname[slen] = 0;
                
                while (*p && isspace((unsigned char)*p)) p++;
                if (*p == '=') {
                    recognized = 1;
                    p++;
                    while (*p && isspace((unsigned char)*p)) p++;
                    uint64_t val = 0;
                    int is_align = 0;
                    if (!strncmp(p, "ALIGN", 5)) {
                        p += 5;
                        while (*p && *p != '(') p++;
                        if (*p == '(') p++;
                        val = strtoull(p, (char **)&p, 0);
                        while (*p && *p != ')') p++;
                        if (*p == ')') p++;
                        is_align = 1;
                    } else if (*p == '.') {
                        val = 0; // relative to current section / base
                        p++;
                    } else {
                        val = strtoull(p, (char **)&p, 0);
                    }
                    if (nscript_syms < 32) {
                        strcpy(script_syms[nscript_syms].name, symname);
                        script_syms[nscript_syms].value = val;
                        script_syms[nscript_syms].is_align = is_align;
                        nscript_syms++;
                    }
                    while (*p && *p != ';') p++;
                    if (*p == ';') p++;
                    continue;
                }
            }
        }

        p++;
    }
    return recognized;
}

/* --------------------------------------------------------- object loading */

/*
 * Classify an ELF section into linker internal section categories.
 * Inputs: sh - ELF section header pointer, name - section name string
 * Outputs: Internal section class enum index
 */
static int classify(Elf64_Shdr *sh, const char *name) {
    if (sh->sh_flags & SHF_TLS) return sh->sh_type == SHT_NOBITS ? C_TBSS : C_TDATA;
    if (sh->sh_type == SHT_NOBITS) return C_BSS;
    if (!strcmp(name, "__crunch_abi") && sh->sh_type == SHT_PROGBITS &&
        (sh->sh_flags & ~SHF_GNU_RETAIN) == SHF_ALLOC) return C_CRUNCH_ABI;
    if (!strcmp(name, "__crunch_init_array")) return C_CRUNCH_INIT;
    if (!strcmp(name, "__crunch_static_arrays")) return C_CRUNCH_STATIC;
    if (sh->sh_type == SHT_INIT_ARRAY) return C_INITARR;
    if (sh->sh_type == SHT_FINI_ARRAY) return C_FINIARR;
    if (sh->sh_type == SHT_X86_64_UNWIND || !strcmp(name, ".eh_frame")) return C_EHFRAME;
    if (sh->sh_flags & SHF_EXECINSTR) return C_TEXT;
    if (relro && dynamic_output() && (sh->sh_flags & SHF_WRITE) &&
        !strncmp(name, ".data.rel.ro", 12) && (!name[12] || name[12] == '.'))
        return C_DATA_REL_RO;
    if (sh->sh_flags & SHF_WRITE) return C_DATA;
    return C_RODATA;
}

static size_t reloc_width(uint32_t t);

typedef struct {
    size_t input, output, size;
    int cie, terminator, discard;
} EhRecord;

/*
 * Find the frame record containing an input offset.
 * Inputs: records - parsed frame records, count - record count, offset - input offset.
 * Outputs: Record index, or -1 if the offset is outside all records.
 */
static int eh_record_at(EhRecord *records, int count, uint64_t offset) {
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (offset < records[mid].input) hi = mid;
        else if (offset - records[mid].input >= records[mid].size) lo = mid + 1;
        else return mid;
    }
    return -1;
}

/*
 * Remove unwind FDEs belonging to discarded COMDAT code.
 * Inputs: o - object whose section groups have been selected.
 * Outputs: Compacts frame records and their relocations, or rejects unsupported layouts.
 */
static void discard_comdat_frames(Obj *o) {
    for (int i = 1; i < o->nsh; i++) {
        InSec *s = &o->secs[i];
        if (!s->live || !s->rela || s->sh->sh_name >= o->shstrsz) continue;
        const char *section_name = o->shstr + s->sh->sh_name;
        if (!memchr(section_name, 0, o->shstrsz - s->sh->sh_name))
            die("%s: invalid section name", o->name);
        if (strcmp(section_name, ".eh_frame")) continue;
        Elf64_Shdr *r = &o->sh[s->rela - 1];
        if (r->sh_size % sizeof(Elf64_Rela)) die("%s: invalid frame relocations", o->name);
        Elf64_Rela *rel = at(o, r->sh_offset, r->sh_size);
        size_t nrel = r->sh_size / sizeof *rel;
        int needs_filter = 0;
        for (size_t j = 0; j < nrel; j++) {
            uint32_t si = ELF64_R_SYM(rel[j].r_info);
            if (ELF64_R_TYPE(rel[j].r_info) == R_X86_64_NONE) continue;
            if (si >= (uint32_t)o->nsyms) die("%s: bad symbol index in frame relocation", o->name);
            if (si && o->syms[si].st_shndx < (unsigned)o->nsh &&
                o->secs[o->syms[si].st_shndx].discarded) needs_filter = 1;
        }
        if (!needs_filter) continue;
        if (s->sh->sh_type == SHT_NOBITS || (s->sh->sh_flags & SHF_COMPRESSED) ||
            s->sh->sh_size > SIZE_MAX)
            die("%s: unsupported .eh_frame containing discarded COMDAT references", o->name);
        uint8_t *input = at(o, s->sh->sh_offset, s->sh->sh_size);
        size_t size = (size_t)s->sh->sh_size;
        EhRecord *records = NULL;
        int count = 0, capacity = 0;
        for (size_t pos = 0; pos < size;) {
            if (size - pos < 4) die("%s: truncated .eh_frame", o->name);
            uint32_t length;
            memcpy(&length, input + pos, sizeof length);
            EhRecord record = {.input = pos};
            if (!length) {
                record.terminator = 1;
                record.size = size - pos;
            } else {
                if (length == UINT32_MAX || length < 4 || length > size - pos - 4)
                    die("%s: unsupported .eh_frame record", o->name);
                record.size = (size_t)length + 4;
                uint32_t id;
                memcpy(&id, input + pos + 4, sizeof id);
                record.cie = id == 0;
            }
            GROW(records, count, capacity);
            records[count++] = record;
            pos += record.size;
        }
        for (size_t j = 0; j < nrel; j++) {
            uint32_t si = ELF64_R_SYM(rel[j].r_info);
            if (ELF64_R_TYPE(rel[j].r_info) == R_X86_64_NONE || !si ||
                o->syms[si].st_shndx >= (unsigned)o->nsh ||
                !o->secs[o->syms[si].st_shndx].discarded) continue;
            int record = eh_record_at(records, count, rel[j].r_offset);
            if (record < 0) die("%s: invalid frame relocation offset", o->name);
            if (!records[record].cie && !records[record].terminator &&
                rel[j].r_offset == records[record].input + 8)
                records[record].discard = 1;
        }
        for (size_t j = 0; j < nrel; j++) {
            uint32_t si = ELF64_R_SYM(rel[j].r_info);
            if (ELF64_R_TYPE(rel[j].r_info) == R_X86_64_NONE || !si ||
                o->syms[si].st_shndx >= (unsigned)o->nsh ||
                !o->secs[o->syms[si].st_shndx].discarded) continue;
            int record = eh_record_at(records, count, rel[j].r_offset);
            if (record < 0 || !records[record].discard)
                die("%s: unsupported .eh_frame reference to discarded COMDAT", o->name);
        }
        Buf filtered = {0};
        for (int j = 0; j < count; j++) {
            EhRecord *record = &records[j];
            if (record->discard) continue;
            record->output = filtered.n;
            buf_add(&filtered, input + record->input, record->size);
        }
        for (int j = 0; j < count; j++) {
            EhRecord *record = &records[j];
            if (record->discard || record->cie || record->terminator) continue;
            uint32_t distance;
            memcpy(&distance, input + record->input + 4, sizeof distance);
            if (distance > record->input + 4) die("%s: invalid .eh_frame CIE reference", o->name);
            size_t cie_offset = record->input + 4 - distance;
            int cie = eh_record_at(records, count, cie_offset);
            if (cie < 0 || !records[cie].cie || records[cie].input != cie_offset ||
                record->output + 4 < records[cie].output ||
                record->output + 4 - records[cie].output > UINT32_MAX)
                die("%s: invalid .eh_frame CIE reference", o->name);
            distance = (uint32_t)(record->output + 4 - records[cie].output);
            memcpy(filtered.p + record->output + 4, &distance, sizeof distance);
        }
        size_t kept = 0;
        for (size_t j = 0; j < nrel; j++) {
            int record = eh_record_at(records, count, rel[j].r_offset);
            if (record < 0 || records[record].terminator)
                die("%s: invalid frame relocation offset", o->name);
            if (records[record].discard) continue;
            Elf64_Rela moved = rel[j];
            unsigned type = ELF64_R_TYPE(moved.r_info);
            size_t within = (size_t)(moved.r_offset - records[record].input);
            if (type != R_X86_64_NONE) {
                size_t width = reloc_width(type);
                if (!width || within < 8 || width > records[record].size - within)
                    die("%s: unsupported .eh_frame relocation", o->name);
            }
            moved.r_offset = records[record].output + (moved.r_offset - records[record].input);
            rel[kept++] = moved;
        }
        if (filtered.n) memcpy(input, filtered.p, filtered.n);
        s->sh->sh_size = filtered.n;
        r->sh_size = kept * sizeof *rel;
        free(filtered.p);
        free(records);
    }
}

/*
 * Validate and discard a GNU x86 CET feature note for dynamic output.
 * Inputs: o - input object, index - property section index.
 * Outputs: Marks the section non-live; rejects unsupported properties or references.
 */
static void discard_cet_property(Obj *o, int index) {
    InSec *s = &o->secs[index];
    Elf64_Shdr *sh = s->sh;
    uint32_t words[8];
    if (sh->sh_type != SHT_NOTE || sh->sh_flags != SHF_ALLOC ||
        sh->sh_addralign != 8 || sh->sh_size != sizeof words ||
        sh->sh_link || sh->sh_info || s->rela || s->group)
        die("%s: unsupported GNU property note", o->name);
    memcpy(words, at(o, sh->sh_offset, sizeof words), sizeof words);
    if (words[0] != 4 || words[1] != 16 || words[2] != 5 ||
        memcmp((const uint8_t *)words + 12, "GNU\0", 4) ||
        words[4] != 0xc0000002U || words[5] != 4 ||
        (words[6] & ~3U) || words[7])
        die("%s: unsupported GNU property note", o->name);
    for (int i = 1; i < o->nsyms; ++i) {
        Elf64_Sym *sym = &o->syms[i];
        if (sym->st_shndx == (unsigned)index && i >= o->first_global)
            die("%s: symbols in GNU property notes are unsupported", o->name);
    }
    for (int i = 0; i < o->nsh; ++i) {
        Elf64_Shdr *r = &o->sh[i];
        if (r->sh_type != SHT_RELA) continue;
        Elf64_Rela *rel = at(o, r->sh_offset, r->sh_size);
        for (size_t j = 0; j < r->sh_size / sizeof *rel; ++j) {
            uint32_t symbol = ELF64_R_SYM(rel[j].r_info);
            if (symbol >= (unsigned)o->nsyms)
                die("%s: bad symbol index in relocation", o->name);
            if (symbol && o->syms[symbol].st_shndx == (unsigned)index)
                die("%s: references to GNU property notes are unsupported", o->name);
        }
    }
    if (words[6])
        warn("%s: discarding GNU CET properties; output does not retain IBT or SHSTK protection",
             o->name);
    s->live = 0;
}

/*
 * Parse and load a relocatable ELF object file, symbols, and sections.
 * Inputs: name - object name/path, buf - file buffer, size - file size in bytes
 * Outputs: None
 */
static void add_object(const char *name, uint8_t *buf, size_t size) {
    Obj *o = xcalloc(1, sizeof *o);
    o->name = name; o->buf = buf; o->size = size;

    if (size < sizeof(Elf64_Ehdr) || memcmp(buf, ELFMAG, SELFMAG))
        die("%s: file format not recognized", name);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_machine != EM_X86_64)
        die("%s: not a 64-bit little-endian x86-64 ELF file", name);
    if (eh->e_type != ET_REL) die("%s: not a relocatable object file", name);
    if ((relocatable || dynamic_output()) && (eh->e_shentsize != sizeof(Elf64_Shdr) ||
                        eh->e_shstrndx >= eh->e_shnum))
        die("%s: unsupported section header table", name);
    o->eh = eh;
    o->nsh = eh->e_shnum;
    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        die("%s: invalid section header table offset or count", name);
    if (eh->e_shoff > size ||
        (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > size - eh->e_shoff)
        die("%s: section header table overflows file size", name);
    size_t shsize = (size_t)o->nsh * sizeof(Elf64_Shdr);
    o->sh = xcalloc((size_t)o->nsh, sizeof(Elf64_Shdr));
    memcpy(o->sh, at(o, eh->e_shoff, shsize), shsize);
    o->secs = xcalloc((size_t)o->nsh + 1, sizeof(InSec));
    if (eh->e_shstrndx < o->nsh) {
        Elf64_Shdr *ss = &o->sh[eh->e_shstrndx];
        o->shstr = at(o, ss->sh_offset, ss->sh_size);
        o->shstrsz = ss->sh_size;
        if (dynamic_output() && (ss->sh_type != SHT_STRTAB || !ss->sh_size ||
                          o->shstr[0] || o->shstr[ss->sh_size - 1]))
            die("%s: invalid shared section name table", name);
    }

    Elf64_Shdr *symsh = NULL;
    for (int i = 0; i < o->nsh; i++) {
        Elf64_Shdr *sh = &o->sh[i];
        InSec *s = &o->secs[i];
        if (dynamic_output() && sh->sh_name >= o->shstrsz)
            die("%s: invalid shared section name", name);
        s->obj = o; s->sh = sh;
        if (sh->sh_type == SHT_RELA && sh->sh_info < (unsigned)o->nsh) {
            if (dynamic_output() && o->secs[sh->sh_info].rela)
                die("%s: multiple relocation sections for one target are unsupported", name);
            o->secs[sh->sh_info].rela = i + 1;
        }
        if (sh->sh_type == SHT_REL) die("%s: SHT_REL sections are not supported", name);
        if ((relocatable || dynamic_output()) && sh->sh_type == SHT_SYMTAB && symsh)
            die("%s: multiple symbol tables are not supported", name);
        if (sh->sh_type == SHT_SYMTAB) symsh = sh;
        if (sh->sh_type == SHT_NULL || sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_STRTAB ||
            sh->sh_type == SHT_RELA || sh->sh_type == SHT_GROUP ||
            (!relocatable && !(sh->sh_flags & SHF_ALLOC)))
            continue;
        if (sh->sh_type != SHT_NOBITS) at(o, sh->sh_offset, sh->sh_size);
        s->live = 1;
        s->cls = classify(sh, sh->sh_name < o->shstrsz ? o->shstr + sh->sh_name : "");
    }

    if (symsh) {
        if ((relocatable || dynamic_output()) && (symsh->sh_entsize != sizeof(Elf64_Sym) ||
                            symsh->sh_size % sizeof(Elf64_Sym)))
            die("%s: invalid symbol table", name);
        o->nsyms = (int)(symsh->sh_size / sizeof(Elf64_Sym));
        o->syms = at(o, symsh->sh_offset, (uint64_t)o->nsyms * sizeof(Elf64_Sym));
        o->first_global = (int)symsh->sh_info;
        if (symsh->sh_link >= (unsigned)o->nsh || o->first_global > o->nsyms)
            die("%s: corrupt symbol table", name);
        Elf64_Shdr *st = &o->sh[symsh->sh_link];
        if ((relocatable || dynamic_output()) && st->sh_type != SHT_STRTAB)
            die("%s: invalid symbol string table", name);
        o->strtab = at(o, st->sh_offset, st->sh_size);
        o->strtabsz = st->sh_size;
        if (!st->sh_size || o->strtab[st->sh_size - 1]) die("%s: corrupt string table", name);
        if (relocatable || dynamic_output()) {
            if (!o->nsyms || o->first_global < 1)
                die("%s: invalid symbol table", name);
            for (int i = 0; i < o->nsyms; i++) {
                Elf64_Sym *s = &o->syms[i];
                if (s->st_name >= o->strtabsz ||
                    (s->st_shndx < SHN_LORESERVE && s->st_shndx >= o->nsh))
                    die("%s: invalid symbol table entry", name);
                int bind = ELF64_ST_BIND(s->st_info);
                if ((i < o->first_global && bind != STB_LOCAL) ||
                    (i >= o->first_global && bind != STB_GLOBAL && bind != STB_WEAK))
                    die("%s: unsupported symbol binding", name);
            }
        }
        if (dynamic_output()) {
            for (int i = 0; i < o->nsh; i++) {
                Elf64_Shdr *sh = &o->sh[i];
                if (sh->sh_type != SHT_RELA) continue;
                if (!symsh || sh->sh_link >= (unsigned)o->nsh || &o->sh[sh->sh_link] != symsh ||
                    !sh->sh_info || sh->sh_info >= (unsigned)o->nsh ||
                    sh->sh_entsize != sizeof(Elf64_Rela) || sh->sh_size % sizeof(Elf64_Rela))
                    die("%s: invalid shared relocation section", name);
                at(o, sh->sh_offset, sh->sh_size);
            }
            for (int i = 1; i < o->first_global; i++)
                if (ELF64_ST_TYPE(o->syms[i].st_info) == STT_GNU_IFUNC)
                    die("%s: local indirect functions are unsupported in shared output", name);
        }
    }
    if (relocatable) {
        for (int i = 1; i < o->nsh; i++) {
            Elf64_Shdr *sh = &o->sh[i];
            if (sh->sh_type == SHT_STRTAB && i != o->eh->e_shstrndx &&
                (!symsh || i != (int)symsh->sh_link)) {
                at(o, sh->sh_offset, sh->sh_size);
                o->secs[i].live = 1;
            }
        }
    }
    o->gs = xcalloc((size_t)o->nsyms + 1, sizeof(GSym *));
    o->got = xcalloc((size_t)o->nsyms + 1, sizeof(int));

    for (int i = 0; i < o->nsh; i++) {
        Elf64_Shdr *sh = &o->sh[i];
        if (sh->sh_type != SHT_GROUP) continue;
        if (!symsh || sh->sh_link >= (unsigned)o->nsh ||
            &o->sh[sh->sh_link] != symsh || sh->sh_info == 0 ||
            sh->sh_info >= (unsigned)o->nsyms || sh->sh_entsize != 4 ||
            sh->sh_size < 8 || sh->sh_size % 4)
            die("%s: invalid section group", name);
        uint32_t *g = at(o, sh->sh_offset, sh->sh_size);
        size_t n = sh->sh_size / 4;
        if (g[0] & ~GRP_COMDAT) die("%s: unsupported section group flags", name);
        Elf64_Sym *signature = &o->syms[sh->sh_info];
        if (signature->st_name >= o->strtabsz) die("%s: invalid group signature", name);
        const char *signature_name = o->strtab + signature->st_name;
        if (!*signature_name && ELF64_ST_TYPE(signature->st_info) == STT_SECTION &&
            signature->st_shndx < (unsigned)o->nsh &&
            o->sh[signature->st_shndx].sh_name < o->shstrsz) {
            if (!memchr(o->shstr + o->sh[signature->st_shndx].sh_name, 0,
                        o->shstrsz - o->sh[signature->st_shndx].sh_name))
                die("%s: invalid group signature section name", name);
            signature_name = o->shstr + o->sh[signature->st_shndx].sh_name;
        }
        if (!*signature_name) die("%s: empty group signature", name);
        int discard = 0;
        if (g[0] & GRP_COMDAT) {
            GSym *c = lookup(comdats, signature_name, 1);
            discard = c->state != S_UNDEF;
            c->state = S_DEF;
        }
        o->secs[i].discarded = discard;
        for (size_t k = 1; k < n; k++) {
            uint32_t member = g[k];
            if (!member || member >= (unsigned)o->nsh || member == (unsigned)i ||
                o->secs[member].group || !(o->sh[member].sh_flags & SHF_GROUP) ||
                o->sh[member].sh_type == SHT_GROUP)
                die("%s: invalid section group member", name);
            o->secs[member].group = i + 1;
            if (discard) {
                o->secs[member].discarded = 1;
                o->secs[member].live = 0;
            }
        }
    }
    for (int i = 1; i < o->nsh; i++)
        if ((o->sh[i].sh_flags & SHF_GROUP) && !o->secs[i].group)
            die("%s: section has no group", name);
    discard_comdat_frames(o);

    if (dynamic_output()) {
        for (int i = 1; i < o->nsh; ++i) {
            Elf64_Shdr *sh = &o->sh[i];
            const char *nm = o->shstr + sh->sh_name;
            if (o->secs[i].live &&
                !strcmp(nm, ".note.gnu.property"))
                discard_cet_property(o, i);
        }
    }

    for (int i = o->first_global; i < o->nsyms; i++) {
        Elf64_Sym *s = &o->syms[i];
        const char *nm = o->strtab + s->st_name;
        int bind = ELF64_ST_BIND(s->st_info);
        if (s->st_shndx == SHN_XINDEX) die("%s: extended section indices unsupported", name);
        GSym *g = lookup(symtab, nm, 1);
        o->gs[i] = g;
        if (!g->original) g->original = s;
        unsigned visibility = ELF64_ST_VISIBILITY(s->st_other);
        if (visibility != STV_DEFAULT &&
            (g->visibility == STV_DEFAULT || visibility < g->visibility))
            g->visibility = (uint8_t)visibility;

        if (s->st_shndx == SHN_UNDEF) {
            g->keep_undefined = 1;
            if (bind != STB_WEAK) g->strong_ref = 1;
            continue;
        }
        if (s->st_shndx == SHN_COMMON) {
            if (g->state == S_DEF && !g->weak) continue;
            if (g->state != S_COMMON) {
                g->state = S_COMMON; g->type = STT_OBJECT; g->weak = 0;
                g->size = g->align = 0; g->original = s;
            }
            if (s->st_size > g->size) g->size = s->st_size;
            if (s->st_value > g->align) g->align = s->st_value;
            continue;
        }
        if (s->st_shndx < SHN_LORESERVE && !o->secs[s->st_shndx].live) continue;

        int weak = (bind == STB_WEAK);
        if (g->state == S_COMMON && weak) continue;
        if (g->state == S_DEF) {
            if (!g->weak && !weak) {
                error("multiple definition of `%s'; defined in %s and %s", nm,
                      g->obj ? g->obj->name : "<linker>", name);
                continue;
            }
            if (g->weak && !weak) { }
            else continue;
        }
        g->state = S_DEF; g->weak = weak; g->obj = o; g->shndx = s->st_shndx;
        g->value = s->st_value; g->size = s->st_size; g->type = ELF64_ST_TYPE(s->st_info); g->original = s;
    }

    for (int i = 1; i < o->nsh; i++) {
        Elf64_Shdr *r = &o->sh[i];
        if (r->sh_type != SHT_RELA || r->sh_info >= (unsigned)o->nsh ||
            !o->secs[r->sh_info].live || o->secs[i].discarded) continue;
        Elf64_Rela *rel = at(o, r->sh_offset, r->sh_size);
        for (size_t j = 0; j < r->sh_size / sizeof *rel; j++) {
            uint32_t si = ELF64_R_SYM(rel[j].r_info);
            if (ELF64_R_TYPE(rel[j].r_info) == R_X86_64_NONE) continue;
            if (si >= (uint32_t)o->nsyms) die("%s: bad symbol index in relocation", name);
            if (!si) continue;
            Elf64_Sym *s = &o->syms[si];
            if (s->st_shndx >= SHN_LORESERVE || s->st_shndx >= (unsigned)o->nsh ||
                !o->secs[s->st_shndx].discarded) continue;
            if ((int)si >= o->first_global) {
                GSym *g = o->gs[si];
                g->keep_undefined = 1;
                if (ELF64_ST_BIND(s->st_info) != STB_WEAK) g->strong_ref = 1;
            } else {
                const char *section_name = r->sh_info < (unsigned)o->nsh &&
                    o->sh[r->sh_info].sh_name < o->shstrsz
                    ? o->shstr + o->sh[r->sh_info].sh_name : "";
                if (relocatable && !strncmp(section_name, ".debug", 6)) continue;
                error("%s: relocation in `%s' references a local symbol in a discarded section",
                      name, section_name);
            }
        }
    }

    GROW(objs, nobjs, capobjs);
    objs[nobjs++] = o;
}

/* --------------------------------------------------------------- archives */

typedef struct { const char *name; uint8_t *buf; size_t size; int loaded; } Member;
static Member *members;
static int nmembers, capmem;

/*
 * Parse and index an static library archive (.a file).
 * Inputs: path - archive file path, buf - archive buffer, size - archive size in bytes
 * Outputs: None
 */
static void add_archive(const char *path, uint8_t *buf, size_t size) {
    size_t pos = 8;
    const char *longnames = NULL;
    size_t longlen = 0;
    while (pos + 60 <= size) {
        const char *h = (const char *)buf + pos;
        char szs[11];
        memcpy(szs, h + 48, 10); szs[10] = 0;
        size_t sz = strtoull(szs, NULL, 10);
        if (pos + 60 + sz > size) die("%s: corrupt archive", path);
        uint8_t *data = buf + pos + 60;

        if (!memcmp(h, "//", 2)) {
            longnames = (const char *)data; longlen = sz;
        } else if (h[0] == '/' && (h[1] == ' ' || !memcmp(h, "/SYM64/", 7))) {
        } else {
            char nm[256];
            size_t nl = 0;
            if (h[0] == '/' && isdigit((unsigned char)h[1])) {
                size_t off = strtoul(h + 1, NULL, 10);
                if (!longnames || off >= longlen) die("%s: bad long member name", path);
                while (off + nl < longlen && longnames[off + nl] != '/' && longnames[off + nl] != '\n') nl++;
                memcpy(nm, longnames + off, nl < 255 ? nl : 255);
            } else {
                while (nl < 16 && h[nl] != '/') nl++;
                memcpy(nm, h, nl);
            }
            nm[nl < 255 ? nl : 255] = 0;
            size_t len = strlen(path) + strlen(nm) + 3;
            char *disp = xcalloc(len, 1);
            snprintf(disp, len, "%s(%s)", path, nm);

            GROW(members, nmembers, capmem);
            Member *m = &members[nmembers++];
            memset(m, 0, sizeof *m);
            m->name = disp;
            m->size = sz;
            m->buf = xcalloc(sz + 8, 1);
            memcpy(m->buf, data, sz);
        }
        pos += 60 + sz;
        if (pos & 1) pos++;
    }
}

/*
 * Determine whether an archive member satisfies a strong undefined or common symbol.
 * Inputs: m - archive member pointer
 * Outputs: 1 if needed, 0 otherwise
 */
static int member_needed(Member *m) {
    if (m->size < sizeof(Elf64_Ehdr) || memcmp(m->buf, ELFMAG, SELFMAG)) return 0;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)m->buf;
    if (eh->e_shoff == 0 || eh->e_shoff > m->size ||
        (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > m->size - eh->e_shoff) return 0;
    for (int i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr sh, str;
        memcpy(&sh, m->buf + eh->e_shoff + (size_t)i * sizeof sh, sizeof sh);
        if (sh.sh_type != SHT_SYMTAB) continue;
        if (sh.sh_offset > m->size || sh.sh_size > m->size - sh.sh_offset ||
            sh.sh_link >= eh->e_shnum) return 0;
        memcpy(&str, m->buf + eh->e_shoff + (size_t)sh.sh_link * sizeof str, sizeof str);
        if (str.sh_offset > m->size || str.sh_size > m->size - str.sh_offset) return 0;
        Elf64_Sym *sy = (Elf64_Sym *)(m->buf + sh.sh_offset);
        const char *strs = (const char *)m->buf + str.sh_offset;
        int n = (int)(sh.sh_size / sizeof(Elf64_Sym));
        for (int k = (int)sh.sh_info; k < n; k++) {
            if (sy[k].st_shndx == SHN_UNDEF || sy[k].st_name >= str.sh_size) continue;
            GSym *g = lookup(symtab, strs + sy[k].st_name, 0);
            if (!g) continue;
            if (g->state == S_UNDEF && g->strong_ref && !g->dynamic_defined) return 1;
            if (g->state == S_COMMON &&
                ELF64_ST_BIND(sy[k].st_info) == STB_GLOBAL &&
                ELF64_ST_TYPE(sy[k].st_info) != STT_FUNC &&
                sy[k].st_shndx != SHN_COMMON)
                return 1;
        }
    }
    return 0;
}

/*
 * Iteratively extract and link needed members from one static archive.
 * Inputs: first - first member index, end - one past the last member index
 * Outputs: None
 */
static void resolve_archive(int first, int end) {
    int changed;
    do {
        changed = 0;
        for (int i = first; i < end; i++) {
            Member *m = &members[i];
            if (m->loaded || !member_needed(m)) continue;
            m->loaded = 1;
            add_object(m->name, m->buf, m->size);
            changed = 1;
        }
    } while (changed);
}

struct AbiRecord {
    Obj *obj;
    char *storage, *name;
    char *types[129];
    size_t ntypes;
    AbiRecord *next;
};

/*
 * Compare recorded IR-level function signatures from selected inputs.
 * Inputs: None; uses resolved symbols, selected objects, and direct shared inputs.
 * Outputs: Possible mismatch warnings on stderr.
 */
static void warn_abi_mismatches(void) {
    AbiRecord **records = NULL;
    size_t count = 0, capacity = 0;
    AbiRecord *references = NULL;
    for (int i = 0; i < nobjs + nabi_shared_inputs; i++) {
        int shared = i >= nobjs;
        int epoch = shared ? i - nobjs + 1 : 0;
        Obj *o = shared ? abi_shared_inputs[epoch - 1].obj : objs[i];
        if (shared) {
            SharedAbiInput *input = &abi_shared_inputs[epoch - 1];
            for (uint64_t k = 1; k < input->nsyms; k++) {
                Elf64_Sym *entry = &o->syms[k];
                unsigned bind = ELF64_ST_BIND(entry->st_info);
                unsigned visibility = ELF64_ST_VISIBILITY(entry->st_other);
                unsigned type = ELF64_ST_TYPE(entry->st_info);
                if ((bind != STB_GLOBAL && bind != STB_WEAK && bind != STB_GNU_UNIQUE) ||
                    (visibility != STV_DEFAULT && visibility != STV_PROTECTED) ||
                    (type != STT_FUNC && type != STT_NOTYPE && type != STT_GNU_IFUNC))
                    continue;
                if (input->versions) {
                    Elf64_Half version = input->versions[k];
                    if ((version & 0x8000) || !(version & 0x7fff)) continue;
                }
                GSym *symbol = lookup(symtab, o->strtab + entry->st_name, 0);
                if (!symbol) continue;
                if (symbol->abi_shared_epoch != epoch) {
                    symbol->abi_shared_epoch = epoch;
                    symbol->abi_shared_flags = 0;
                }
                symbol->abi_shared_flags |= 1;
                if (entry->st_shndx != SHN_UNDEF) symbol->abi_shared_flags |= 2;
            }
        }
        for (int j = 1; j < o->nsh; j++) {
            Elf64_Shdr *sh = &o->sh[j];
            if (!o->shstr || sh->sh_name >= o->shstrsz ||
                !memchr(o->shstr + sh->sh_name, 0, o->shstrsz - sh->sh_name) ||
                strcmp(o->shstr + sh->sh_name, "__crunch_abi") ||
                sh->sh_type != SHT_PROGBITS || !(sh->sh_flags & SHF_ALLOC))
                continue;
            const char *data = at(o, sh->sh_offset, sh->sh_size);
            for (size_t pos = 0; pos < sh->sh_size;) {
                const char *end = memchr(data + pos, '\n', sh->sh_size - pos);
                if (!end) break;
                size_t length = (size_t)(end - (data + pos));
                if (length > 8192 || memchr(data + pos, 0, length)) {
                    pos += length + 1;
                    continue;
                }
                char *line = xcalloc(length + 1, 1);
                memcpy(line, data + pos, length);
                pos += length + 1;
                char *save = NULL, *version = strtok_r(line, " ", &save);
                char *kind = strtok_r(NULL, " ", &save);
                char *name = strtok_r(NULL, " ", &save);
                char *variadic = strtok_r(NULL, " ", &save);
                if (!version || strcmp(version, "CABI1") || !kind ||
                    (strcmp(kind, "D") && strcmp(kind, "R")) || !name || !variadic ||
                    (strcmp(variadic, "unknown") && strcmp(variadic, "variadic"))) {
                    free(line);
                    continue;
                }
                GSym *symbol = lookup(symtab, name, 0);
                if (!symbol ||
                    (shared && (symbol->abi_shared_epoch != epoch ||
                                !(symbol->abi_shared_flags & (!strcmp(kind, "D") ? 2 : 1)))) ||
                    (!shared && !strcmp(kind, "D") &&
                     (symbol->state != S_DEF || symbol->obj != o))) {
                    free(line);
                    continue;
                }
                AbiRecord *record = xcalloc(1, sizeof *record);
                record->obj = o;
                record->storage = line;
                record->name = name;
                char *type;
                while ((type = strtok_r(NULL, " ", &save)) != NULL) {
                    if (record->ntypes == sizeof record->types / sizeof record->types[0])
                        break;
                    record->types[record->ntypes++] = type;
                }
                if (!record->ntypes || type) {
                    free(line);
                    free(record);
                    continue;
                }
                if (!strcmp(kind, "D")) {
                    record->next = symbol->abi_defs;
                    symbol->abi_defs = record;
                } else {
                    record->next = references;
                    references = record;
                }
                GROW(records, count, capacity);
                records[count++] = record;
            }
        }
    }
    for (AbiRecord *r = references; r; r = r->next) {
        GSym *symbol = lookup(symtab, r->name, 0);
        AbiRecord *definition = symbol->abi_defs;
        while (definition) {
            Obj *origin = definition->obj;
            int match = 0;
            do {
                AbiRecord *d = definition;
                definition = definition->next;
                if (r->ntypes != d->ntypes) continue;
                size_t i = 0;
                while (i < r->ntypes && !strcmp(r->types[i], d->types[i])) i++;
                if (i == r->ntypes) match = 1;
            } while (definition && definition->obj == origin);
            if (is_dynamic && symbol->state == S_DEF && symbol->obj &&
                (symbol->visibility == STV_DEFAULT || symbol->visibility == STV_PROTECTED) &&
                origin != symbol->obj)
                continue;
            if (!match)
                warn("possible ABI mismatch for `%s': declaration in %s differs from definition in %s",
                     r->name, r->obj->name, origin->name);
        }
    }
    for (int i = 0; i < nall; i++) allsyms[i]->abi_defs = NULL;
    for (size_t i = 0; i < count; i++) {
        free(records[i]->storage);
        free(records[i]);
    }
    free(records);
    for (int i = 0; i < nabi_shared_inputs; i++) {
        Obj *o = abi_shared_inputs[i].obj;
        free((char *)o->name);
        free(o->buf);
        free(o);
    }
    free(abi_shared_inputs);
}

#include "relocatable.inc"

/* ---------------------------------------------------------------- gc sections */

typedef struct EhInfo EhInfo;

/*
 * Recursively mark an input section and its relocation dependencies as live for garbage collection.
 * Inputs: s - input section pointer
 * Outputs: None
 */
static void mark_sec(InSec *s) {
    if (!s || !s->live || s->marked) return;
    s->marked = 1;
    Obj *o = s->obj;
    if (s->group) {
        Elf64_Shdr *group = &o->sh[s->group - 1];
        uint32_t *members = at(o, group->sh_offset, group->sh_size);
        for (size_t i = 1; i < group->sh_size / sizeof *members; i++)
            mark_sec(&o->secs[members[i]]);
    }
    if (!s->rela) return;
    Elf64_Shdr *r = &o->sh[s->rela - 1];
    size_t n = r->sh_size / sizeof(Elf64_Rela);
    Elf64_Rela *rel = at(o, r->sh_offset, n * sizeof(Elf64_Rela));
    for (size_t i = 0; i < n; i++) {
        uint32_t si = ELF64_R_SYM(rel[i].r_info);
        if (si >= (uint32_t)o->nsyms) die("%s: bad symbol index in relocation", o->name);
        if (!si) continue;
        if ((int)si < o->first_global) {
            unsigned index = o->syms[si].st_shndx;
            if (index && index < SHN_LORESERVE) {
                if (index >= (unsigned)o->nsh) die("%s: bad symbol section index", o->name);
                mark_sec(&o->secs[index]);
            }
            continue;
        }
        GSym *g = o->gs[si];
        if (g->state == S_DEF && g->obj && g->shndx < SHN_LORESERVE) {
            mark_sec(&g->obj->secs[g->shndx]);
        }
    }
}

/*
 * Perform garbage collection of unused input sections (--gc-sections).
 * Inputs: entry - entry point symbol name
 * Outputs: None
 */
static void gc_sections(const char *entry) {
    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = 0; k < o->nsh; k++) {
            InSec *s = &o->secs[k];
            if (!s->live) continue;
            const char *nm = s->sh->sh_name < o->shstrsz ? o->shstr + s->sh->sh_name : "";
            if ((s->sh->sh_flags & SHF_GNU_RETAIN) ||
                !strncmp(nm, ".init_array", 11) || !strncmp(nm, ".fini_array", 11) ||
                !strncmp(nm, ".ctors", 6) || !strncmp(nm, ".dtors", 6) || !strncmp(nm, ".note", 5)) {
                mark_sec(s);
            }
        }
    }

    GSym *eg = lookup(symtab, entry, 0);
    if (eg && eg->state == S_DEF && eg->obj && eg->shndx < SHN_LORESERVE) {
        mark_sec(&eg->obj->secs[eg->shndx]);
    }
    for (int i = 0; i < nall; i++) {
        GSym *g = allsyms[i];
        if (g->strong_ref && g->state == S_DEF && g->obj && g->shndx < SHN_LORESERVE) {
            mark_sec(&g->obj->secs[g->shndx]);
        }
    }

    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = 0; k < o->nsh; k++) {
            InSec *s = &o->secs[k];
            if (!s->live) continue;
            if (!s->marked) {
                s->live = 0;
                if (print_gc) {
                    const char *nm = s->sh->sh_name < o->shstrsz ? o->shstr + s->sh->sh_name : "";
                    fprintf(stderr, "removing unused section %s in %s\n", nm, o->name);
                }
            }
        }
    }
}

/*
 * Allocate one GOT slot per global symbol or per object-local symbol.
 * Inputs: None; processes live sections after archive extraction and GC.
 * Outputs: Populates GOT indices and entries for executable layout.
 */
static void collect_got(void) {
    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = 0; k < o->nsh; k++) {
            InSec *s = &o->secs[k];
            if (!s->live || s->sh->sh_type == SHT_NOBITS || !s->rela) continue;
            Elf64_Shdr *r = &o->sh[s->rela - 1];
            size_t n = r->sh_size / sizeof(Elf64_Rela);
            Elf64_Rela *rel = at(o, r->sh_offset, n * sizeof(Elf64_Rela));
            for (size_t j = 0; j < n; j++) {
                uint32_t type = ELF64_R_TYPE(rel[j].r_info);
                if (type != R_X86_64_GOTPCREL && type != R_X86_64_GOTPCRELX &&
                    type != R_X86_64_REX_GOTPCRELX) continue;
                if (is_pie)
                    die("GOT relocations in PIE output are not supported");
                uint32_t si = ELF64_R_SYM(rel[j].r_info);
                if (si >= (uint32_t)o->nsyms) die("%s: bad symbol index in relocation", o->name);
                int *slot = si && (int)si >= o->first_global ? &o->gs[si]->got : &o->got[si];
                if (*slot) continue;
                if (ngot >= INT_MAX / 2) die("too many GOT entries");
                GROW(got_entries, ngot, capgot);
                got_entries[ngot] = (GotEnt){o, (int)si};
                *slot = ++ngot;
            }
        }
    }
}

/* ----------------------------------------------------------------- layout */

static uint64_t image_base = 0x400000;
static uint64_t rx_end, rwaddr, rwoff, filesz_end, rw_end, content_end, relro_end;
static int nphdr, have_rw, have_tls;
static uint64_t tls_align = 1;

/*
 * Compute the System V ELF symbol hash used by the dynamic loader.
 * Inputs: name - NUL-terminated symbol name
 * Outputs: 32-bit hash value
 */
static uint32_t shared_symbol_hash(const char *name) {
    uint32_t h = 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h = (h << 4) + *p;
        uint32_t high = h & 0xf0000000U;
        if (high) h ^= high >> 24;
        h &= ~high;
    }
    return h;
}

/*
 * Allocate a shared-object GOT slot once for a global or object-local symbol.
 * Inputs: o - owning object; si - symbol index.
 * Outputs: Records the GOT entry and returns its one-based slot index.
 */
static int shared_got_slot(Obj *o, uint32_t si) {
    int *slot = (int)si >= o->first_global ? &o->gs[si]->got : &o->got[si];
    if (!*slot) {
        if (ngot >= INT_MAX / 2) die("too many GOT entries");
        GROW(got_entries, ngot, capgot);
        got_entries[ngot] = (GotEnt){o, (int)si};
        *slot = ++ngot;
    }
    return *slot;
}

/*
 * Record a shared initialization or finalization section and its priority.
 * Inputs: s - input section; name - validated section name.
 * Outputs: Adds the section in input order or rejects unsupported array layouts.
 */
static void shared_array_add(InSec *s, const char *name) {
    const char *base = s->cls == C_INITARR ? ".init_array" : ".fini_array";
    size_t len = strlen(base);
    if (strncmp(name, base, len) || (name[len] && name[len] != '.'))
        die("%s: unsupported shared array section name `%s'", s->obj->name, name);
    unsigned priority = 65535;
    int unnumbered = !name[len];
    if (!unnumbered) {
        const char *p = name + len + 1;
        if (!*p) die("%s: invalid shared array priority in `%s'", s->obj->name, name);
        priority = 0;
        for (; *p; p++) {
            if (*p < '0' || *p > '9' || priority > (65535u - (unsigned)(*p - '0')) / 10)
                die("%s: invalid shared array priority in `%s'", s->obj->name, name);
            priority = priority * 10 + (unsigned)(*p - '0');
        }
    }
    if (!(s->sh->sh_flags & SHF_WRITE) || (s->sh->sh_flags & (SHF_MERGE | SHF_STRINGS)) ||
        s->sh->sh_size % 8 ||
        s->sh->sh_addralign > 8 || (s->sh->sh_entsize && s->sh->sh_entsize != 8))
        die("%s: unsupported shared array layout in `%s'", s->obj->name, name);
    if (nshared_arrays >= INT_MAX / 2) die("too many shared array sections");
    GROW(shared_arrays, nshared_arrays, capshared_arrays);
    shared_arrays[nshared_arrays] = (SharedArray){s, priority, unnumbered, nshared_arrays};
    nshared_arrays++;
    if (s->sh->sh_size) {
        if (s->cls == C_INITARR) shared_init = 1;
        else shared_fini = 1;
    }
}

/*
 * Order shared array sections by type, numeric priority, and input order.
 * Inputs: a/b - shared array records.
 * Outputs: Negative, zero, or positive comparison result.
 */
static int shared_array_compare(const void *a, const void *b) {
    const SharedArray *x = a, *y = b;
    if (x->sec->cls != y->sec->cls) return x->sec->cls < y->sec->cls ? -1 : 1;
    if (x->priority != y->priority) return x->priority < y->priority ? -1 : 1;
    if (x->unnumbered != y->unnumbered) return x->unnumbered ? 1 : -1;
    return (x->order > y->order) - (x->order < y->order);
}

/*
 * Restore a max heap rooted at root within the shared array records.
 * Inputs: root - root index, count - heap size
 * Outputs: Reorders shared_arrays in place.
 */
static void sift_shared_arrays(int root, int count) {
    while (root < count / 2) {
        int child = root * 2 + 1;
        if (child + 1 < count &&
            shared_array_compare(&shared_arrays[child], &shared_arrays[child + 1]) < 0)
            child++;
        if (shared_array_compare(&shared_arrays[root], &shared_arrays[child]) >= 0) break;
        SharedArray tmp = shared_arrays[root];
        shared_arrays[root] = shared_arrays[child];
        shared_arrays[child] = tmp;
        root = child;
    }
}

/*
 * Sort shared array records in O(n log n) time.
 * Inputs: None
 * Outputs: Reorders shared_arrays according to shared_array_compare.
 */
static void sort_shared_arrays(void) {
    for (int i = nshared_arrays / 2; i > 0; i--)
        sift_shared_arrays(i - 1, nshared_arrays);
    for (int i = nshared_arrays - 1; i > 0; i--) {
        SharedArray tmp = shared_arrays[0];
        shared_arrays[0] = shared_arrays[i];
        shared_arrays[i] = tmp;
        sift_shared_arrays(0, i);
    }
}

/*
 * Validate shared relocations and prepare dynamic symbols and tables.
 * Inputs: None
 * Outputs: Initializes shared symbol, string and hash tables; rejects unsupported inputs.
 */
static void prepare_shared(void) {
    if (is_dynamic) {
        executable_fini_symbol = lookup(symtab, "__crunch_run_finalizers", 1);
        if (executable_fini_symbol->state != S_UNDEF || executable_fini_symbol->dynamic_defined ||
            executable_fini_symbol->visibility != STV_DEFAULT)
            die("reserved executable symbol `__crunch_run_finalizers' is already defined");
        executable_fini_symbol->state = S_DEF;
        executable_fini_symbol->linker = 1;
        executable_fini_symbol->shndx = SHN_ABS;
        executable_fini_symbol->type = STT_FUNC;
        executable_fini_symbol->weak = 0;
        for (int i = 0; i < nobjs; i++)
            for (int j = 0; j < objs[i]->nsh; j++) {
                InSec *s = &objs[i]->secs[j];
                if (!s->live || !s->sh->sh_size) continue;
                if (s->cls == C_CRUNCH_INIT) {
                    lookup(symtab, "__start___crunch_init_array", 1);
                    lookup(symtab, "__stop___crunch_init_array", 1);
                } else if (s->cls == C_CRUNCH_STATIC) {
                    lookup(symtab, "__start___crunch_static_arrays", 1);
                    lookup(symtab, "__stop___crunch_static_arrays", 1);
                }
            }
    }
    buf_add(&shared_strings, "", 1);
    for (int i = 0; i < nshared_needed; i++) {
        if (shared_strings.n > UINT32_MAX) die("shared dynamic strings are too large");
        shared_needed[i].string_offset = (uint32_t)buf_add(&shared_strings,
            shared_needed[i].name, strlen(shared_needed[i].name) + 1);
    }
    if (shared_soname) {
        if (shared_strings.n > UINT32_MAX) die("shared dynamic strings are too large");
        shared_soname_offset = (uint32_t)buf_add(&shared_strings, shared_soname,
                                                 strlen(shared_soname) + 1);
    }
    if (shared_runpath.n) {
        if (shared_strings.n > UINT32_MAX) die("shared dynamic strings are too large");
        shared_runpath_offset = (uint32_t)buf_add(&shared_strings, shared_runpath.p,
                                                  shared_runpath.n);
        buf_add(&shared_strings, "", 1);
    }
    shared_symbols = xcalloc((size_t)nall + 1, sizeof *shared_symbols);
    shared_names = xcalloc((size_t)nall + 1, sizeof *shared_names);
    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int j = 0; j < o->nsh; j++) {
            InSec *s = &o->secs[j];
            const char *name = s->sh->sh_name < o->shstrsz ? o->shstr + s->sh->sh_name : "";
            if (!memchr(name, 0, s->sh->sh_name < o->shstrsz ? o->shstrsz - s->sh->sh_name : 1))
                die("%s: invalid section name", o->name);
            if (!strcmp(name, ".note.GNU-stack") && (s->sh->sh_flags & SHF_EXECINSTR))
                die("%s: executable stack is unsupported in shared output", o->name);
            if (!s->live && !s->discarded &&
                (s->sh->sh_type == SHT_INIT_ARRAY || s->sh->sh_type == SHT_FINI_ARRAY) &&
                !(s->sh->sh_flags & SHF_ALLOC))
                die("%s: shared array section `%s' is not allocated", o->name, name);
            if (!s->live) continue;
            if (relro && !strncmp(name, ".data.rel.ro", 12) &&
                (!name[12] || name[12] == '.') &&
                (s->sh->sh_type != SHT_PROGBITS || !(s->sh->sh_flags & SHF_WRITE) ||
                 (s->sh->sh_flags & (SHF_EXECINSTR | SHF_TLS))))
                die("%s: unsupported RELRO section `%s'", o->name, name);
            int is_array = s->cls == C_INITARR || s->cls == C_FINIARR;
            if ((!strncmp(name, ".init_array", 11) && (!name[11] || name[11] == '.') &&
                 s->sh->sh_type != SHT_INIT_ARRAY) ||
                (!strncmp(name, ".fini_array", 11) && (!name[11] || name[11] == '.') &&
                 s->sh->sh_type != SHT_FINI_ARRAY) ||
                (!strncmp(name, ".preinit_array", 14) && (!name[14] || name[14] == '.')))
                die("%s: unsupported shared array section `%s'", o->name, name);
            if ((s->sh->sh_addralign && (s->sh->sh_addralign & (s->sh->sh_addralign - 1))) ||
                (s->sh->sh_flags & SHF_TLS) ||
                (s->sh->sh_flags & (SHF_WRITE | SHF_EXECINSTR)) == (SHF_WRITE | SHF_EXECINSTR) ||
                (s->sh->sh_type != SHT_PROGBITS && s->sh->sh_type != SHT_NOBITS &&
                 s->sh->sh_type != SHT_X86_64_UNWIND && !is_array) ||
                !strcmp(name, ".init") || !strcmp(name, ".fini") ||
                !strncmp(name, ".ctors", 6) || !strncmp(name, ".dtors", 6) ||
                !strncmp(name, ".eh_frame", 9) ||
                s->cls == C_EHFRAME)
                die("%s: unsupported allocated section in shared output", o->name);
            if (is_shared && (s->cls == C_CRUNCH_INIT || s->cls == C_CRUNCH_STATIC))
                die("%s: runtime initialization sections are not supported in shared output", o->name);
            if (is_array) shared_array_add(s, name);
            if (is_array && s->sh->sh_size && !s->rela)
                die("%s: shared array entries require relocations", o->name);
            if (!s->rela) continue;
            if (s->sh->sh_type == SHT_NOBITS)
                die("%s: relocations in NOBITS shared sections are unsupported", o->name);
            Elf64_Shdr *rh = &o->sh[s->rela - 1];
            if (rh->sh_size % sizeof(Elf64_Rela)) die("%s: invalid relocations", o->name);
            Elf64_Rela *rels = at(o, rh->sh_offset, rh->sh_size);
            size_t array_entries = is_array ? (size_t)(s->sh->sh_size / 8) : 0;
            uint8_t *array_slots = is_array ? xcalloc(array_entries, 1) : NULL;
            for (size_t k = 0; k < rh->sh_size / sizeof *rels; k++) {
                uint32_t type = ELF64_R_TYPE(rels[k].r_info), si = ELF64_R_SYM(rels[k].r_info);
                if (type == R_X86_64_NONE) continue;
                int is_got = type == R_X86_64_GOTPCREL || type == R_X86_64_GOTPCRELX ||
                             type == R_X86_64_REX_GOTPCRELX;
                int is_datarel = type == R_X86_64_64;
                if (is_array) {
                    if (!is_datarel || rels[k].r_offset % 8 ||
                        rels[k].r_offset / 8 >= array_entries ||
                        array_slots[rels[k].r_offset / 8])
                        die("%s: invalid shared array relocation in `%s'", o->name, name);
                    array_slots[rels[k].r_offset / 8] = 1;
                }
                if (!is_got && !is_datarel && type != R_X86_64_PC32 && type != R_X86_64_PLT32 &&
                    type != R_X86_64_PC64 && type != R_X86_64_PC16 && type != R_X86_64_PC8 &&
                    (is_shared || (type != R_X86_64_32 && type != R_X86_64_32S &&
                                   type != R_X86_64_16 && type != R_X86_64_8)))
                    die("%s: relocation type %u requires unsupported dynamic relocation", o->name, type);
                if (!si || si >= (uint32_t)o->nsyms)
                    die("%s: invalid shared relocation symbol", o->name);
                GSym *target = (int)si >= o->first_global ? o->gs[si] : NULL;
                if (is_dynamic && target && target->state == S_UNDEF &&
                    !target->dynamic_defined && crunch_registry_symbol(target->name) &&
                    type != R_X86_64_PC32 && type != R_X86_64_PC64)
                    die("%s: unsupported relocation for Crunch registry boundary `%s'",
                        o->name, target->name);
                int dynamic_data = is_datarel && (is_shared ||
                    (is_pie && image_relative_symbol(o, si)) || dynamic_preemptible(target));
                if (is_pie && !is_shared &&
                    (type == R_X86_64_32 || type == R_X86_64_32S ||
                     type == R_X86_64_16 || type == R_X86_64_8) &&
                    (image_relative_symbol(o, si) || dynamic_preemptible(target)))
                    die("%s: absolute relocation is unsupported in dynamic PIE", o->name);
                if (is_pie && is_got && !dynamic_preemptible(target) &&
                    !image_relative_symbol(o, si))
                    die("%s: absolute GOT symbol is unsupported in dynamic PIE", o->name);
                if (is_pie && !is_shared &&
                    (type == R_X86_64_PC32 || type == R_X86_64_PC64 ||
                     type == R_X86_64_PC16 || type == R_X86_64_PC8 ||
                     type == R_X86_64_PLT32) &&
                    !dynamic_preemptible(target) && !image_relative_symbol(o, si))
                    die("%s: PC-relative relocation against absolute symbol is unsupported in dynamic PIE",
                        o->name);
                if (dynamic_data) {
                    if (!(s->sh->sh_flags & SHF_WRITE))
                        die("%s: dynamic relocation in a read-only shared section is unsupported", o->name);
                    if (rels[k].r_offset > s->sh->sh_size ||
                        8 > s->sh->sh_size - rels[k].r_offset)
                        die("%s: relocation offset out of range", o->name);
                    if (shared_datarel_count >= INT_MAX / 2) die("too many dynamic data relocations");
                    shared_datarel_count++;
                }
                if ((int)si >= o->first_global) {
                    GSym *g = o->gs[si];
                    if (!g || (g->linker && g != executable_fini_symbol) ||
                        (g->state == S_UNDEF && g->visibility != STV_DEFAULT) ||
                        (g->state == S_DEF && g->shndx >= SHN_LORESERVE &&
                         (is_shared || g->shndx != SHN_ABS)))
                        die("%s: unsupported shared relocation against `%s'",
                            o->name, o->strtab + o->syms[si].st_name);
                    g->shared_ref = 1;
                    int preemptible = dynamic_preemptible(g);
                    if (is_got) shared_got_slot(o, si);
                    else if (is_datarel) g->datarel = 1;
                    else if (type == R_X86_64_PLT32 && preemptible) {
                        if (rels[k].r_addend != -4)
                            die("%s: unsupported PLT relocation addend for `%s'", o->name, g->name);
                        shared_got_slot(o, si);
                        if (!g->plt) {
                            if (shared_plt_count >= INT_MAX / 2) die("too many PLT entries");
                            g->plt = ++shared_plt_count;
                        }
                    } else if (preemptible && !(is_dynamic && !g->dynamic_defined &&
                                                crunch_registry_symbol(g->name)))
                        die("%s: shared relocation against undefined or preemptible symbol `%s' is unsupported",
                            o->name, o->strtab + o->syms[si].st_name);
                } else {
                    Elf64_Sym *sym = &o->syms[si];
                    if ((is_shared || sym->st_shndx != SHN_ABS) &&
                        (sym->st_shndx == SHN_UNDEF || sym->st_shndx >= (unsigned)o->nsh ||
                         !o->secs[sym->st_shndx].live))
                        die("%s: unsupported local shared relocation target", o->name);
                    if (is_got) shared_got_slot(o, si);
                }
            }
            for (size_t k = 0; k < array_entries; k++)
                if (!array_slots[k]) die("%s: shared array entries require relocations", o->name);
            free(array_slots);
        }
    }
    for (int i = 0; i < nall; i++) {
        GSym *g = allsyms[i];
        if (g->state == S_UNDEF && !g->got && !g->required && !g->datarel &&
            !(is_dynamic && crunch_registry_symbol(g->name))) continue;
        if (!*g->name) die("empty symbol name in shared output");
        if (strchr(g->name, '@'))
            die("symbol versioning is unsupported in shared output: `%s'", g->name);
        if (g->state == S_DEF && g->shndx >= SHN_LORESERVE && g->shndx != SHN_ABS)
            die("unsupported symbol section for shared output: `%s'", g->name);
        if (g->state == S_DEF && g->shndx < SHN_LORESERVE) {
            InSec *s = &g->obj->secs[g->shndx];
            uint64_t size = s->sh->sh_size;
            if (g->value > size || g->size > size - g->value)
                die("symbol outside its section in shared output: `%s'", g->name);
            if ((s->cls == C_INITARR && !shared_init) || (s->cls == C_FINIARR && !shared_fini))
                die("symbol in empty shared array is unsupported: `%s'", g->name);
        }
        if (g->state == S_COMMON && g->align && (g->align & (g->align - 1)))
            die("invalid common symbol alignment in shared output: `%s'", g->name);
        if (g->state != S_UNDEF && g->type != STT_NOTYPE && g->type != STT_OBJECT && g->type != STT_FUNC)
            die("unsupported symbol type for shared output: `%s'", g->name);
        if (g->visibility == STV_HIDDEN || g->visibility == STV_INTERNAL) continue;
        if (shared_strings.n > UINT32_MAX) die("shared symbol strings are too large");
        shared_symbols[++shared_count] = g;
        g->shared_index = (uint32_t)shared_count;
        shared_names[shared_count] = (uint32_t)buf_add(&shared_strings, g->name, strlen(g->name) + 1);
    }
    if (shared_strings.n > UINT32_MAX || shared_count >= UINT32_MAX)
        die("shared symbol table is too large");
    uint32_t nbucket = shared_count ? (uint32_t)shared_count : 1;
    uint32_t nchain = (uint32_t)shared_count + 1;
    uint32_t *buckets = xcalloc(nbucket, sizeof *buckets);
    uint32_t *chains = xcalloc(nchain, sizeof *chains);
    for (uint32_t i = 1; i < nchain; i++) {
        uint32_t bucket = shared_symbol_hash(shared_symbols[i]->name) % nbucket;
        chains[i] = buckets[bucket];
        buckets[bucket] = i;
    }
    buf_add(&shared_hash_data, &nbucket, sizeof nbucket);
    buf_add(&shared_hash_data, &nchain, sizeof nchain);
    buf_add(&shared_hash_data, buckets, (size_t)nbucket * sizeof *buckets);
    buf_add(&shared_hash_data, chains, (size_t)nchain * sizeof *chains);
    free(buckets);
    free(chains);
    shared_dynsym.size = (shared_count + 1) * sizeof(Elf64_Sym);
    shared_dynsym.align = 8;
    shared_dynstr.size = shared_strings.n;
    shared_dynstr.align = 1;
    shared_hash.size = shared_hash_data.n;
    shared_hash.align = 4;
    shared_plt.size = (uint64_t)shared_plt_count * 6;
    shared_plt.align = 1;
    shared_rela.size = ((uint64_t)ngot + (uint64_t)shared_datarel_count) * sizeof(Elf64_Rela);
    shared_rela.align = 8;
    shared_dynamic.size = ((uint64_t)(shared_rela.size ? 9 : 6) + (unsigned)nshared_needed +
                           (shared_init ? 2 : 0) + (shared_fini ? 2 : 0) +
                           (shared_soname ? 1 : 0) + (shared_runpath.n ? 1 : 0) +
                           (is_dynamic && is_pie ? 1 : 0)) * sizeof(Elf64_Dyn);
    shared_dynamic.align = 8;
}

/*
 * Define a synthetic linker-provided symbol (e.g., __executable_start, _end).
 * Inputs: name - symbol name string, v - symbol absolute virtual address value
 * Outputs: None
 */
static void def_linker_sym(const char *name, uint64_t v) {
    GSym *g = lookup(symtab, name, 0);
    if (g && g->state == S_UNDEF) { g->state = S_DEF; g->linker = 1; g->value = v; g->weak = 0; }
}


static char prov_comment_buf[256] = "Compiler: crunch-1.0 Linker: crunch-ld 1.0 Created by: Jason Metz <crunch.compiler@yahoo.com>";

/*
 * Compute virtual memory layout, section offsets, and symbol final addresses.
 * Inputs: None
 * Outputs: None
 */
static void layout(void) {

    out[C_COMMENT].size = strlen(prov_comment_buf) + 1;
    out[C_COMMENT].align = 1;
    if (has_script_base) image_base = script_base_addr;
    if ((is_pie || is_shared) && !has_script_base) image_base = 0;

    for (int i = 0; i < nobjs; i++)
        for (int k = 0; k < objs[i]->nsh; k++) {
            InSec *s = &objs[i]->secs[k];
            if (!s->live) continue;
            if (dynamic_output() && (s->cls == C_INITARR || s->cls == C_FINIARR)) continue;
            OutSec *os = &out[s->cls];
            uint64_t a = s->sh->sh_addralign ? s->sh->sh_addralign : 1;
            if (a > os->align) os->align = a;
            s->off = align_up(os->size, a);
            os->size = s->off + s->sh->sh_size;
        }

    if (dynamic_output() && nshared_arrays) {
        sort_shared_arrays();
        for (int i = 0; i < nshared_arrays; i++) {
            InSec *s = shared_arrays[i].sec;
            OutSec *os = &out[s->cls];
            os->align = 8;
            s->off = os->size;
            if (s->sh->sh_size > UINT64_MAX - os->size) die("shared array is too large");
            os->size += s->sh->sh_size;
        }
    }

    if (is_dynamic && shared_init) {
        if (out[C_TEXT].align < 16) out[C_TEXT].align = 16;
        if (out[C_TEXT].size > UINT64_MAX - 15)
            die("executable constructor trampoline is too large");
        executable_init_offset = align_up(out[C_TEXT].size, 16);
        if (executable_init_offset > UINT64_MAX - sizeof executable_init_code)
            die("executable constructor trampoline is too large");
        out[C_TEXT].size = executable_init_offset + sizeof executable_init_code;
    }
    if (is_dynamic) {
        if (out[C_TEXT].align < 16) out[C_TEXT].align = 16;
        if (out[C_TEXT].size > UINT64_MAX - 15)
            die("executable finalizer helper is too large");
        executable_fini_offset = align_up(out[C_TEXT].size, 16);
        size_t size = shared_fini ? sizeof executable_fini_code : 1;
        if (executable_fini_offset > UINT64_MAX - size)
            die("executable finalizer helper is too large");
        out[C_TEXT].size = executable_fini_offset + size;
    }

    for (int i = 0; i < nall; i++) {
        GSym *g = allsyms[i];
        if (g->state != S_COMMON) continue;
        uint64_t a = g->align ? g->align : 1;
        if (a > out[C_BSS].align) out[C_BSS].align = a;
        g->value = align_up(out[C_BSS].size, a);
        out[C_BSS].size = g->value + g->size;
    }
    if (is_dynamic && shared_fini) {
        if (out[C_BSS].size == UINT64_MAX) die("executable finalizer guard is too large");
        executable_fini_guard = out[C_BSS].size++;
        if (!out[C_BSS].align) out[C_BSS].align = 1;
    }

    out[C_GOT].size = 8ULL * ngot;
    out[C_GOT].align = 8;

    have_tls = out[C_TDATA].size || out[C_TBSS].size;
    if (have_tls) {
        tls_align = out[C_TDATA].align > out[C_TBSS].align ? out[C_TDATA].align : out[C_TBSS].align;
        if (tls_align < 1) tls_align = 1;
    }
    have_rw = 0;
    for (int c = C_TDATA; c < NCLS; c++) if (c != C_TBSS && out[c].size) have_rw = 1;
    if (dynamic_output()) have_rw = 1;
    nphdr = 1 + have_rw + have_tls + 1 + dynamic_output() + is_dynamic + relro +
            (is_dynamic && is_pie);
    uint64_t hdrsz = sizeof(Elf64_Ehdr) + (uint64_t)nphdr * sizeof(Elf64_Phdr) +
                     (is_dynamic ? strlen(dynamic_linker) + 1 : 0);

    uint64_t cur = image_base + hdrsz;
    for (int c = C_TEXT; c <= C_EHFRAME; c++) {
        OutSec *o = &out[c];
        if (!o->size) { o->addr = cur; o->off = cur - image_base; continue; }
        cur = align_up(cur, o->align);
        o->addr = cur; o->off = cur - image_base;
        cur += o->size;
    }
    if (dynamic_output()) {
        OutSec *tables[] = {&shared_plt, &shared_dynsym, &shared_dynstr, &shared_hash, &shared_rela};
        for (size_t i = 0; i < sizeof tables / sizeof tables[0]; i++) {
            OutSec *table = tables[i];
            cur = align_up(cur, table->align);
            table->addr = cur;
            table->off = cur - image_base;
            cur += table->size;
        }
    }
    rx_end = cur;
    rwoff = rx_end - image_base;
    rwaddr = align_up(cur, PAGE) + (rwoff % PAGE);
    cur = rwaddr; filesz_end = rwaddr;
    if (dynamic_output()) {
        cur = align_up(cur, shared_dynamic.align);
        shared_dynamic.addr = cur;
        shared_dynamic.off = rwoff + cur - rwaddr;
        cur += shared_dynamic.size;
        filesz_end = cur;
    }
    if (relro) {
        const int classes[] = {C_INITARR, C_FINIARR, C_GOT, C_DATA_REL_RO};
        for (size_t i = 0; i < sizeof classes / sizeof classes[0]; i++) {
            OutSec *o = &out[classes[i]];
            if (o->align > 1 && cur > UINT64_MAX - (o->align - 1))
                die("RELRO segment is too large");
            cur = align_up(cur, o->align);
            if (cur < rwaddr || cur - rwaddr > UINT64_MAX - rwoff ||
                o->size > UINT64_MAX - cur)
                die("RELRO segment is too large");
            o->addr = cur;
            o->off = rwoff + cur - rwaddr;
            cur += o->size;
        }
        if (cur > UINT64_MAX - (PAGE - 1)) die("RELRO segment is too large");
        relro_end = align_up(cur, PAGE);
        cur = filesz_end = relro_end;
    }
    for (int c = C_TDATA; c < NCLS; c++) {
        OutSec *o = &out[c];
        if (relro && (c == C_INITARR || c == C_FINIARR ||
                      c == C_GOT || c == C_DATA_REL_RO)) continue;
        if (c == C_TDATA && have_tls) cur = align_up(cur, tls_align);
        if (c == C_TBSS) {
            o->addr = o->size ? align_up(out[C_TDATA].addr + out[C_TDATA].size, o->align ? o->align : 1) : cur;
            o->off = rwoff + (o->addr - rwaddr);
            continue;
        }
        if (!o->size) { o->addr = cur; o->off = rwoff + (cur - rwaddr); continue; }
        o->addr = align_up(cur, o->align);
        o->off = rwoff + (o->addr - rwaddr);
        cur = o->addr + o->size;
        if (c != C_BSS) filesz_end = cur;
    }
    rw_end = cur;
    content_end = have_rw ? rwoff + (filesz_end - rwaddr) : rx_end - image_base;
    
    out[C_COMMENT].off = align_up(content_end, 1);
    out[C_COMMENT].addr = 0; // Not loaded in memory
    content_end = out[C_COMMENT].off + out[C_COMMENT].size;


    for (int i = 0; i < nobjs; i++)
        for (int k = 0; k < objs[i]->nsh; k++) {
            InSec *s = &objs[i]->secs[k];
            if (!s->live) continue;
            s->addr = out[s->cls].addr + s->off;
            s->foff = out[s->cls].off + s->off;
        }


    if (nmem_regions > 0) {
        // uint64_t total_size = (have_rw ? rw_end : rx_end) - image_base;
        // Check against first matching memory region or general bounds
        for (int ri = 0; ri < nmem_regions; ri++) {
            if (image_base >= mem_regions[ri].origin && 
                image_base < mem_regions[ri].origin + mem_regions[ri].length) {
                uint64_t region_end = mem_regions[ri].origin + mem_regions[ri].length;
                uint64_t img_end = (have_rw ? rw_end : rx_end);
                if (img_end > region_end) {
                    error("region `%s' overflowed by %llu bytes", 
                          mem_regions[ri].name, (unsigned long long)(img_end - region_end));
                }
            }
        }
    }

    uint64_t text_end = out[C_TEXT].addr + out[C_TEXT].size;
    uint64_t end = have_rw ? rw_end : rx_end;
    for (int i = 0; i < nscript_syms; i++) {
        uint64_t v = script_syms[i].value;
        if (script_syms[i].is_align) v = align_up(rx_end, v);
        def_linker_sym(script_syms[i].name, v ? v : end);
    }
    def_linker_sym("__executable_start", image_base);
    def_linker_sym("__data_start", have_rw ? rwaddr : rx_end);
    def_linker_sym("_end", end);
    def_linker_sym("end", end);
    def_linker_sym("_edata", have_rw ? filesz_end : rx_end);
    def_linker_sym("edata", have_rw ? filesz_end : rx_end);
    def_linker_sym("__bss_start", out[C_BSS].size ? out[C_BSS].addr : (have_rw ? filesz_end : rx_end));
    def_linker_sym("_etext", text_end);
    def_linker_sym("etext", text_end);
    def_linker_sym("__etext", text_end);
    if (out[C_CRUNCH_INIT].size) {
        def_linker_sym("__start___crunch_init_array", out[C_CRUNCH_INIT].addr);
        def_linker_sym("__stop___crunch_init_array",
                       out[C_CRUNCH_INIT].addr + out[C_CRUNCH_INIT].size);
    }
    if (out[C_CRUNCH_STATIC].size) {
        def_linker_sym("__start___crunch_static_arrays", out[C_CRUNCH_STATIC].addr);
        def_linker_sym("__stop___crunch_static_arrays",
                       out[C_CRUNCH_STATIC].addr + out[C_CRUNCH_STATIC].size);
    }
    if (is_dynamic)
        executable_fini_symbol->value = out[C_TEXT].addr + executable_fini_offset;

    for (int i = 0; i < nall; i++) {
        GSym *g = allsyms[i];
        if (is_shared && g->linker)
            die("linker-defined symbol `%s' is unsupported in shared output", g->name);
        if (is_dynamic && is_pie && g->linker &&
            g != executable_fini_symbol && !crunch_registry_symbol(g->name))
            die("linker-defined symbol `%s' is unsupported in dynamic PIE", g->name);
        if (g->state == S_DEF && g->linker) g->addr = g->value;
        else if (g->state == S_DEF)
            g->addr = g->shndx == SHN_ABS ? g->value : g->obj->secs[g->shndx].addr + g->value;
        else if (g->state == S_COMMON) g->addr = out[C_BSS].addr + g->value;
        else g->addr = 0;
    }
}

/* ------------------------------------------------------------ relocations */

static uint8_t *img;

/*
 * Retrieve the human-readable name of a symbol from an object file.
 * Inputs: o - object file pointer, si - symbol table index
 * Outputs: Symbol name string
 */
static const char *symname(Obj *o, uint32_t si) {
    const char *n = o->strtab + o->syms[si].st_name;
    return *n ? n : "<section>";
}

/*
 * Determine the byte width of a given x86-64 relocation type.
 * Inputs: t - ELF relocation type
 * Outputs: Relocation width in bytes (1, 2, 4, or 8)
 */
static size_t reloc_width(uint32_t t) {
    switch (t) {
    case R_X86_64_64: case R_X86_64_PC64: return 8;
    case R_X86_64_32: case R_X86_64_32S: case R_X86_64_PC32: case R_X86_64_PLT32:
    case R_X86_64_GOTPCREL: case R_X86_64_GOTPCRELX: case R_X86_64_REX_GOTPCRELX: return 4;
    case R_X86_64_16: case R_X86_64_PC16: return 2;
    case R_X86_64_8: case R_X86_64_PC8: return 1;
    }
    return 0;
}

/*
 * Check whether a 64-bit integer fits within a signed bit-width range.
 * Inputs: v - value to test, bits - target bit width (e.g., 32)
 * Outputs: 1 if fits, 0 otherwise
 */
static int fits_signed(int64_t v, int bits) {
    return v >= -((int64_t)1 << (bits - 1)) && v < ((int64_t)1 << (bits - 1));
}

/*
 * Resolve a symbol to its final static address after layout.
 * Inputs: o - owning object, si - symbol index.
 * Outputs: Final address, or zero for an undefined weak or null symbol.
 */
static uint64_t symbol_address(Obj *o, uint32_t si) {
    if (!si) return 0;
    if ((int)si >= o->first_global) return o->gs[si]->addr;
    Elf64_Sym *s = &o->syms[si];
    if (s->st_shndx == SHN_ABS) return s->st_value;
    if (s->st_shndx < SHN_LORESERVE) {
        if (s->st_shndx >= (unsigned)o->nsh) die("%s: bad symbol section index", o->name);
        InSec *sec = &o->secs[s->st_shndx];
        if (dynamic_output() && ((sec->cls == C_INITARR && !shared_init) ||
                          (sec->cls == C_FINIARR && !shared_fini)))
            die("%s: reference to empty shared array is unsupported", o->name);
        if (sec->live) return sec->addr + s->st_value;
    }
    return 0;
}

/*
 * Compute target + addend - place without overflowing or accepting wraparound.
 * Inputs: target - GOT entry address, addend - relocation addend, place - relocation address.
 * Outputs: One and a signed 32-bit result if representable; otherwise zero.
 */
static int got_disp32(uint64_t target, int64_t addend, uint64_t place, int32_t *result) {
    int negative = target < place;
    uint64_t magnitude = negative ? place - target : target - place;
    int add_negative = addend < 0;
    uint64_t add_magnitude = add_negative ? (uint64_t)(-(addend + 1)) + 1 : (uint64_t)addend;
    if (negative == add_negative) {
        uint64_t limit = negative ? 0x80000000ULL : 0x7fffffffULL;
        if (magnitude > limit || add_magnitude > limit - magnitude) return 0;
        magnitude += add_magnitude;
    } else if (magnitude >= add_magnitude) {
        magnitude -= add_magnitude;
    } else {
        magnitude = add_magnitude - magnitude;
        negative = add_negative;
    }

    if (magnitude > (negative ? 0x80000000ULL : 0x7fffffffULL)) return 0;
    *result = negative && magnitude == 0x80000000ULL ? INT32_MIN :
              negative ? -(int32_t)magnitude : (int32_t)magnitude;
    return 1;
}

/*
 * Patch a RIP-relative displacement in a linker-generated executable stub.
 * Inputs: code - stub bytes; address - stub virtual address; offset - field offset;
 * target - destination virtual address.
 * Outputs: Writes the displacement or rejects an out-of-range target.
 */
static void patch_stub_address(uint8_t *code, uint64_t address, size_t offset, uint64_t target) {
    int32_t displacement;
    if (!got_disp32(target, -4, address + offset, &displacement))
        die("executable startup or finalizer target is out of range");
    memcpy(code + offset, &displacement, sizeof displacement);
}

/*
 * Apply all section relocations and patch resolved symbol addresses into output image.
 * Inputs: o - object file pointer
 * Outputs: None
 */
static void apply_relocs(Obj *o) {
    for (int i = 0; i < o->nsh; i++) {
        InSec *t = &o->secs[i];
        if (!t->live || t->sh->sh_type == SHT_NOBITS) continue;
        if (!t->rela) continue;

        Elf64_Shdr *r = &o->sh[t->rela - 1];
        size_t n = r->sh_size / sizeof(Elf64_Rela);
        Elf64_Rela *rel = at(o, r->sh_offset, n * sizeof(Elf64_Rela));

        for (size_t k = 0; k < n; k++) {
            uint32_t type = ELF64_R_TYPE(rel[k].r_info), si = ELF64_R_SYM(rel[k].r_info);
            int64_t A = rel[k].r_addend;
            uint64_t off = rel[k].r_offset;
            if (type == R_X86_64_NONE) continue;
            if (si >= (uint32_t)o->nsyms) die("%s: bad symbol index in relocation", o->name);
            size_t w = reloc_width(type);
            if (!w) { error("%s: unsupported relocation type %u", o->name, type); continue; }
            if (off > t->sh->sh_size || w > t->sh->sh_size - off)
                die("%s: relocation offset out of range", o->name);

            uint64_t P = t->addr + off;
            uint8_t *loc = img + t->foff + off;
            if (si && (int)si >= o->first_global) {
                GSym *g = o->gs[si];
                if (!dynamic_output() && g->state == S_UNDEF && ELF64_ST_BIND(o->syms[si].st_info) != STB_WEAK) {
                    if (!g->reported) {
                        g->reported = 1;
                        error("%s: undefined reference to `%s'", o->name, g->name);
                    }
                    continue;
                }
            }
            uint64_t S = symbol_address(o, si);

            if (dynamic_output() && type == R_X86_64_64 &&
                (is_shared || (is_pie && image_relative_symbol(o, si)) ||
                 ((int)si >= o->first_global && dynamic_preemptible(o->gs[si])))) {
                GSym *g = (int)si >= o->first_global ? o->gs[si] : NULL;
                int preemptible = dynamic_preemptible(g);
                if (preemptible && !g->shared_index)
                    die("missing dynamic symbol for `%s'", g->name);
                Elf64_Rela dynamic = {
                    .r_offset = P,
                    .r_info = preemptible ? ELF64_R_INFO(g->shared_index, R_X86_64_64)
                                          : ELF64_R_INFO(0, R_X86_64_RELATIVE)
                };
                uint64_t addend = (preemptible ? 0 : S) + (uint64_t)A;
                memcpy(&dynamic.r_addend, &addend, sizeof addend);
                if (shared_datarel_written >= shared_datarel_count)
                    die("dynamic data relocation count changed during layout");
                memcpy(img + shared_rela.off +
                       ((size_t)ngot + (size_t)shared_datarel_written++) * sizeof dynamic,
                       &dynamic, sizeof dynamic);
                memset(loc, 0, 8);
                continue;
            }

            int64_t v = 0;
            int ok = 1;
            switch (type) {
            case R_X86_64_64:       
                { uint64_t x = S + A; memcpy(loc, &x, 8); break; }
            case R_X86_64_PC64:     
                { uint64_t x = S + A - P; memcpy(loc, &x, 8); break; }
            case R_X86_64_GOTPCREL:
            case R_X86_64_GOTPCRELX:
            case R_X86_64_REX_GOTPCRELX: {
                int slot = si && (int)si >= o->first_global ? o->gs[si]->got : o->got[si];
                if (!slot) die("%s: missing GOT entry", o->name);
                uint64_t address = out[C_GOT].addr + (uint64_t)(slot - 1) * 8;
                int32_t displacement;
                ok = got_disp32(address, A, P, &displacement);
                if (!ok) error("%s: GOTPCREL relocation out of range for symbol `%s`",
                               o->name, symname(o, si));
                else v = displacement;
                break;
            }
            case R_X86_64_PC32: 
            case R_X86_64_PLT32:
                if (dynamic_output() && type == R_X86_64_PLT32 && si >= (uint32_t)o->first_global &&
                    o->gs[si]->plt)
                    S = shared_plt.addr + (uint64_t)(o->gs[si]->plt - 1) * 6;
                v = (int64_t)(S + A - P);
                ok = fits_signed(v, 32);
                if (!ok) {
                    error("%s: relocation R_X86_64_PC32 out of range: %lld (symbol `%s` is too far from instruction at %#llx)",
                          o->name, (long long)v, symname(o, si), (unsigned long long)P);
                }
                break;
            case R_X86_64_32:  
                { 
                    uint64_t x = S + A; 
                    ok = x <= 0xffffffffULL; 
                    v = (int64_t)x; 
                    if (!ok) {
                        error("%s: relocation R_X86_64_32 zero-extension overflow: %#llx for symbol `%s`",
                              o->name, (unsigned long long)x, symname(o, si));
                    }
                } 
                break;
            case R_X86_64_32S: 
                v = (int64_t)(S + A); 
                ok = fits_signed(v, 32); 
                if (!ok) {
                    error("%s: relocation R_X86_64_32S sign-extension overflow: %lld for symbol `%s`",
                          o->name, (long long)v, symname(o, si));
                }
                break;
            case R_X86_64_16:  
                { 
                    uint64_t x = S + A; 
                    ok = x <= 0xffff; 
                    v = (int64_t)x; 
                    if (!ok) error("%s: relocation R_X86_64_16 overflow", o->name);
                } 
                break;
            case R_X86_64_PC16: 
                v = (int64_t)(S + A - P); 
                ok = fits_signed(v, 16); 
                if (!ok) error("%s: relocation R_X86_64_PC16 overflow", o->name);
                break;
            case R_X86_64_8:   
                { 
                    uint64_t x = S + A; 
                    ok = x <= 0xff; 
                    v = (int64_t)x; 
                    if (!ok) error("%s: relocation R_X86_64_8 overflow", o->name);
                } 
                break;
            case R_X86_64_PC8: 
                v = (int64_t)(S + A - P); 
                ok = fits_signed(v, 8); 
                if (!ok) error("%s: relocation R_X86_64_PC8 overflow", o->name);
                break;
            }
            if (!ok) continue;
            if (w < 8) memcpy(loc, &v, w);
        }
    }
}

/* -------------------------------------------------------------- output */


static const char *map_filename = NULL;

/*
 * Generate a detailed linker map file with memory region utilization and cross-references.
 * Inputs: None
 * Outputs: None
 */
static void write_map_file(void) {
    if (!map_filename) return;
    FILE *f = fopen(map_filename, "w");
    if (!f) {
        warn("cannot open map file %s for writing", map_filename);
        return;
    }

    fprintf(f, "MLD LINKER MAP FILE (crunch-ld " CRUNCH_VERSION ")\n\n");
    fprintf(f, "Memory Configuration & Utilization\n");
    fprintf(f, "-----------------------------------\n");
    fprintf(f, "Region Name\tOrigin\t\tLength\t\tUsed Bytes\tUtilization\n");
    
    if (nmem_regions > 0) {
        for (int i = 0; i < nmem_regions; i++) {
            uint64_t reg_start = mem_regions[i].origin;
            uint64_t reg_len = mem_regions[i].length;
            uint64_t reg_used = 0;
            for (int c = 0; c < NCLS; c++) {
                if (!out[c].size || out[c].addr == 0) continue;
                if (out[c].addr >= reg_start && out[c].addr < reg_start + reg_len) {
                    reg_used += out[c].size;
                }
            }
            double pct = reg_len > 0 ? ((double)reg_used / reg_len) * 100.0 : 0.0;
            fprintf(f, "%-12s	0x%016llx	0x%016llx	0x%08llx	%.2f%%\n",
                mem_regions[i].name,
                (unsigned long long)reg_start,
                (unsigned long long)reg_len,
                (unsigned long long)reg_used,
                pct);
        }
    } else {
        uint64_t total_used = 0;
        for (int c = 0; c < NCLS; c++) {
            if (out[c].size && out[c].addr != 0) total_used += out[c].size;
        }
        fprintf(f, "%-12s	0x%016llx	0xffffffffffffffff	0x%08llx	N/A\n",
            "DEFAULT",
            (unsigned long long)image_base,
            (unsigned long long)total_used);
    }

    fprintf(f, "\nSection Layout & Virtual Addresses\n");
    fprintf(f, "----------------------------------\n");
    fprintf(f, "Section\t\tAddress\t\tSize\t\tAlignment\n");
    for (int c = 0; c < NCLS; c++) {
        if (!out[c].size) continue;
        fprintf(f, "%-12s	0x%016llx	0x%08llx\t%llu\n",
            cls_name[c],
            (unsigned long long)out[c].addr,
            (unsigned long long)out[c].size,
            (unsigned long long)out[c].align);
    }

    fprintf(f, "\nSymbol Table Cross-Reference\n");
    fprintf(f, "----------------------------\n");
    fprintf(f, "Address\t\tSize\t\tName\n");
    for (int i = 0; i < nall; i++) {
        GSym *g = allsyms[i];
        if (g->state == S_UNDEF) continue;
        fprintf(f, "0x%016llx\t0x%08llx\t%s%s\n",
            (unsigned long long)g->addr,
            (unsigned long long)g->size,
            g->name,
            g->linker ? " (linker)" : "");
    }

    fclose(f);
}

/*
 * Construct and write the final linked ELF executable or shared object file.
 * Inputs: path - output file path, entry - entry symbol name, strip_level - symbol stripping level
 * Outputs: None
 */
static void write_output(const char *path, const char *entry, int strip_level) {
    Buf shstr = {0};
    buf_add(&shstr, "", 1);
    Elf64_Shdr shdrs[NCLS + 11];
    memset(shdrs, 0, sizeof shdrs);
    int nsec = 1;
    if (is_dynamic) {
        Elf64_Shdr *h = &shdrs[nsec++];
        h->sh_name = (uint32_t)buf_add(&shstr, ".interp", 8);
        h->sh_type = SHT_PROGBITS;
        h->sh_flags = SHF_ALLOC;
        h->sh_offset = sizeof(Elf64_Ehdr) + (uint64_t)nphdr * sizeof(Elf64_Phdr);
        h->sh_addr = image_base + h->sh_offset;
        h->sh_size = strlen(dynamic_linker) + 1;
        h->sh_addralign = 1;
    }
    for (int c = 0; c < NCLS; c++) {
        if (!out[c].size) continue;
        Elf64_Shdr *h = &shdrs[nsec];
        h->sh_name = (uint32_t)buf_add(&shstr, cls_name[c], strlen(cls_name[c]) + 1);
        h->sh_type = c == C_BSS || c == C_TBSS ? SHT_NOBITS : c == C_INITARR ? SHT_INIT_ARRAY
                   : c == C_FINIARR ? SHT_FINI_ARRAY
                   : c == C_EHFRAME ? SHT_X86_64_UNWIND : SHT_PROGBITS;
        h->sh_flags = (c == C_COMMENT ? 0 : SHF_ALLOC) | (c == C_TEXT ? SHF_EXECINSTR : 0) |
                      (c >= C_TDATA && c != C_COMMENT ? SHF_WRITE : 0) |
                      (c == C_TDATA || c == C_TBSS ? SHF_TLS : 0);
        h->sh_addr = out[c].addr;
        h->sh_offset = out[c].off;
        h->sh_size = out[c].size;
        h->sh_addralign = out[c].align ? out[c].align : 1;
        h->sh_entsize = (c == C_INITARR || c == C_FINIARR || c == C_GOT) ? 8 : 0;
        out[c].shndx = nsec++;
    }

    if (dynamic_output()) {
        int dynsym_index = nsec, dynstr_index = nsec + 1;
        OutSec *tables[] = {&shared_dynsym, &shared_dynstr, &shared_hash, &shared_dynamic};
        const char *names[] = {".dynsym", ".dynstr", ".hash", ".dynamic"};
        const uint32_t types[] = {SHT_DYNSYM, SHT_STRTAB, SHT_HASH, SHT_DYNAMIC};
        for (size_t i = 0; i < sizeof tables / sizeof tables[0]; i++) {
            OutSec *table = tables[i];
            Elf64_Shdr *h = &shdrs[nsec];
            h->sh_name = (uint32_t)buf_add(&shstr, names[i], strlen(names[i]) + 1);
            h->sh_type = types[i];
            h->sh_flags = SHF_ALLOC | (i == 3 ? SHF_WRITE : 0);
            h->sh_addr = table->addr;
            h->sh_offset = table->off;
            h->sh_size = table->size;
            h->sh_addralign = table->align;
            h->sh_link = (uint32_t)(i == 2 ? dynsym_index : dynstr_index);
            if (i == 1) h->sh_link = 0;
            if (i == 0) { h->sh_info = 1; h->sh_entsize = sizeof(Elf64_Sym); }
            if (i == 2) h->sh_entsize = sizeof(uint32_t);
            if (i == 3) h->sh_entsize = sizeof(Elf64_Dyn);
            table->shndx = nsec++;
        }
        if (shared_plt.size) {
            Elf64_Shdr *h = &shdrs[nsec];
            h->sh_name = (uint32_t)buf_add(&shstr, ".plt", 5);
            h->sh_type = SHT_PROGBITS;
            h->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            h->sh_addr = shared_plt.addr; h->sh_offset = shared_plt.off;
            h->sh_size = shared_plt.size; h->sh_addralign = shared_plt.align;
            shared_plt.shndx = nsec++;
        }
        if (shared_rela.size) {
            Elf64_Shdr *h = &shdrs[nsec];
            h->sh_name = (uint32_t)buf_add(&shstr, ".rela.dyn", 10);
            h->sh_type = SHT_RELA; h->sh_flags = SHF_ALLOC;
            h->sh_addr = shared_rela.addr; h->sh_offset = shared_rela.off;
            h->sh_size = shared_rela.size; h->sh_addralign = shared_rela.align;
            h->sh_entsize = sizeof(Elf64_Rela); h->sh_link = (uint32_t)dynsym_index;
            shared_rela.shndx = nsec++;
        }
    }

    Buf symb = {0}, strb = {0};
    int nlocal = 0;
    if (strip_level < 2) {
        Elf64_Sym nul; memset(&nul, 0, sizeof nul);
        buf_add(&symb, &nul, sizeof nul);
        buf_add(&strb, "", 1);
        if (strip_level == 0) {
            for (int i = 0; i < nobjs; i++) {
                Obj *o = objs[i];
                for (int k = 1; k < o->first_global; k++) {
                    Elf64_Sym n = o->syms[k];
                    int t = ELF64_ST_TYPE(n.st_info);
                    if (t == STT_SECTION || t == STT_FILE || !n.st_name) continue;
                    if (n.st_shndx == SHN_ABS) { }
                    else if (n.st_shndx < SHN_LORESERVE && n.st_shndx < (unsigned)o->nsh && o->secs[n.st_shndx].live) {
                        int cls = o->secs[n.st_shndx].cls;
                        if (out[cls].shndx) {
                            n.st_value = o->secs[n.st_shndx].addr + n.st_value;
                            n.st_shndx = (uint16_t)out[cls].shndx;
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    const char *nm = o->strtab + n.st_name;
                    n.st_name = (uint32_t)buf_add(&strb, nm, strlen(nm) + 1);
                    n.st_other = 0;
                    buf_add(&symb, &n, sizeof n);
                    nlocal++;
                }
            }
        }
        for (int i = 0; i < nall; i++) {
            GSym *g = allsyms[i];
            if (g->state == S_UNDEF) continue;
            if (g->state == S_DEF && !g->linker && g->shndx < SHN_LORESERVE &&
                !g->obj->secs[g->shndx].live)
                continue;
            Elf64_Sym n; memset(&n, 0, sizeof n);
            n.st_name = (uint32_t)buf_add(&strb, g->name, strlen(g->name) + 1);
            n.st_info = ELF64_ST_INFO(g->weak ? STB_WEAK : STB_GLOBAL, g->type);
            if (is_shared) n.st_other = g->visibility;
            n.st_value = g->addr;
            n.st_size = g->size;
            if (g->linker && is_dynamic && is_pie && g == executable_fini_symbol)
                n.st_shndx = (uint16_t)out[C_TEXT].shndx;
            else if (g->linker && is_dynamic && is_pie && crunch_registry_symbol(g->name))
                n.st_shndx = (uint16_t)out[strstr(g->name, "static_arrays")
                                              ? C_CRUNCH_STATIC : C_CRUNCH_INIT].shndx;
            else if (g->linker) n.st_shndx = SHN_ABS;
            else if (g->state == S_COMMON) n.st_shndx = (uint16_t)out[C_BSS].shndx;
            else if (g->shndx == SHN_ABS) n.st_shndx = SHN_ABS;
            else n.st_shndx = (uint16_t)out[g->obj->secs[g->shndx].cls].shndx;
            buf_add(&symb, &n, sizeof n);
        }
        Elf64_Shdr *h = &shdrs[nsec];
        h->sh_name = (uint32_t)buf_add(&shstr, ".symtab", 8);
        h->sh_type = SHT_SYMTAB; h->sh_link = (uint32_t)nsec + 1; h->sh_info = (uint32_t)nlocal + 1;
        h->sh_size = symb.n; h->sh_addralign = 8; h->sh_entsize = sizeof(Elf64_Sym);
        nsec++;
        h = &shdrs[nsec];
        h->sh_name = (uint32_t)buf_add(&shstr, ".strtab", 8);
        h->sh_type = SHT_STRTAB; h->sh_size = strb.n; h->sh_addralign = 1;
        nsec++;
    }
    int shstrndx = nsec;
    shdrs[nsec].sh_name = (uint32_t)buf_add(&shstr, ".shstrtab", 10);
    shdrs[nsec].sh_type = SHT_STRTAB;
    shdrs[nsec].sh_size = shstr.n;
    shdrs[nsec].sh_addralign = 1;
    nsec++;

    uint64_t pos = content_end;
    if (strip_level < 2) {
        pos = align_up(pos, 8); shdrs[shstrndx - 2].sh_offset = pos; pos += symb.n;
        shdrs[shstrndx - 1].sh_offset = pos; pos += strb.n;
    }
    shdrs[shstrndx].sh_offset = pos; pos += shstr.n;
    uint64_t shoff = align_up(pos, 8);
    uint64_t total = shoff + (uint64_t)nsec * sizeof(Elf64_Shdr);

    img = xcalloc(total, 1);

    for (int i = 0; i < nobjs; i++)
        for (int k = 0; k < objs[i]->nsh; k++) {
            InSec *s = &objs[i]->secs[k];
            if (!s->live || s->sh->sh_type == SHT_NOBITS || !s->sh->sh_size) continue;
            memcpy(img + s->foff, objs[i]->buf + s->sh->sh_offset, s->sh->sh_size);
        }

    for (int i = 0; i < ngot && !dynamic_output(); i++) {
        uint64_t value = symbol_address(got_entries[i].o, (uint32_t)got_entries[i].si);
        memcpy(img + out[C_GOT].off + (size_t)i * 8, &value, sizeof value);
    }
    for (int i = 0; i < nobjs; i++) apply_relocs(objs[i]);
    if (dynamic_output()) {
        if (shared_datarel_written != shared_datarel_count)
            die("dynamic data relocation count changed during layout");
        for (size_t i = 1; i <= shared_count; i++) {
            GSym *g = shared_symbols[i];
            Elf64_Sym symbol; memset(&symbol, 0, sizeof symbol);
            symbol.st_name = shared_names[i];
            int weak = g->state == S_UNDEF ? !g->strong_ref : g->weak;
            symbol.st_info = ELF64_ST_INFO(weak ? STB_WEAK : STB_GLOBAL, g->type);
            symbol.st_other = g->visibility;
            symbol.st_value = g->addr;
            symbol.st_size = g->size;
            if (g->state == S_UNDEF) symbol.st_shndx = SHN_UNDEF;
            else if (g->linker && is_pie && g == executable_fini_symbol)
                symbol.st_shndx = (uint16_t)out[C_TEXT].shndx;
            else if (g->linker && is_pie && crunch_registry_symbol(g->name))
                symbol.st_shndx = (uint16_t)out[strstr(g->name, "static_arrays")
                                                   ? C_CRUNCH_STATIC : C_CRUNCH_INIT].shndx;
            else if (g->linker) symbol.st_shndx = SHN_ABS;
            else if (g->state == S_COMMON) symbol.st_shndx = (uint16_t)out[C_BSS].shndx;
            else if (g->shndx == SHN_ABS) symbol.st_shndx = SHN_ABS;
            else symbol.st_shndx = (uint16_t)out[g->obj->secs[g->shndx].cls].shndx;
            memcpy(img + shared_dynsym.off + i * sizeof symbol, &symbol, sizeof symbol);
        }
        memcpy(img + shared_dynstr.off, shared_strings.p, shared_strings.n);
        memcpy(img + shared_hash.off, shared_hash_data.p, shared_hash_data.n);
        for (int i = 0; i < ngot; i++) {
            Obj *o = got_entries[i].o;
            uint32_t si = (uint32_t)got_entries[i].si;
            GSym *g = (int)si >= o->first_global ? o->gs[si] : NULL;
            int preemptible = dynamic_preemptible(g);
            Elf64_Rela rel = {
                .r_offset = out[C_GOT].addr + (uint64_t)i * 8,
                .r_info = preemptible ? ELF64_R_INFO(g->shared_index, R_X86_64_GLOB_DAT)
                                      : ELF64_R_INFO(0, R_X86_64_RELATIVE),
                .r_addend = preemptible ? 0 : (int64_t)symbol_address(o, si)
            };
            if (preemptible && !g->shared_index) die("missing dynamic symbol for `%s'", g->name);
            memcpy(img + shared_rela.off + (size_t)i * sizeof rel, &rel, sizeof rel);
        }
        for (size_t i = 1; i <= shared_count; i++) {
            GSym *g = shared_symbols[i];
            if (!g->plt) continue;
            uint64_t address = shared_plt.addr + (uint64_t)(g->plt - 1) * 6;
            uint64_t target = out[C_GOT].addr + (uint64_t)(g->got - 1) * 8;
            int32_t displacement;
            if (!got_disp32(target, -6, address, &displacement))
                die("shared PLT entry out of range for `%s'", g->name);
            uint8_t *code = img + shared_plt.off + (size_t)(g->plt - 1) * 6;
            code[0] = 0xff; code[1] = 0x25;
            memcpy(code + 2, &displacement, sizeof displacement);
        }
        Elf64_Dyn dynamic[] = {
            {.d_tag = DT_HASH, .d_un.d_ptr = shared_hash.addr},
            {.d_tag = DT_STRTAB, .d_un.d_ptr = shared_dynstr.addr},
            {.d_tag = DT_SYMTAB, .d_un.d_ptr = shared_dynsym.addr},
            {.d_tag = DT_STRSZ, .d_un.d_val = shared_dynstr.size},
            {.d_tag = DT_SYMENT, .d_un.d_val = sizeof(Elf64_Sym)},
            {.d_tag = DT_RELA, .d_un.d_ptr = shared_rela.addr},
            {.d_tag = DT_RELASZ, .d_un.d_val = shared_rela.size},
            {.d_tag = DT_RELAENT, .d_un.d_val = sizeof(Elf64_Rela)},
            {.d_tag = DT_NULL, .d_un.d_val = 0}
        };
        size_t n = 0;
        for (int i = 0; i < nshared_needed; i++) {
            Elf64_Dyn dependency = {.d_tag = DT_NEEDED, .d_un.d_val = shared_needed[i].string_offset};
            memcpy(img + shared_dynamic.off + n++ * sizeof dependency, &dependency, sizeof dependency);
        }
        if (shared_soname) {
            Elf64_Dyn soname = {.d_tag = DT_SONAME, .d_un.d_val = shared_soname_offset};
            memcpy(img + shared_dynamic.off + n++ * sizeof soname, &soname, sizeof soname);
        }
        if (shared_runpath.n) {
            Elf64_Dyn runpath = {.d_tag = DT_RUNPATH, .d_un.d_val = shared_runpath_offset};
            memcpy(img + shared_dynamic.off + n++ * sizeof runpath, &runpath, sizeof runpath);
        }
        if (is_dynamic && is_pie) {
            Elf64_Dyn flags = {.d_tag = DT_FLAGS_1, .d_un.d_val = DF_1_PIE};
            memcpy(img + shared_dynamic.off + n++ * sizeof flags, &flags, sizeof flags);
        }
        for (size_t i = 0; i < 5; i++)
            memcpy(img + shared_dynamic.off + n++ * sizeof(Elf64_Dyn), &dynamic[i], sizeof(Elf64_Dyn));
        if (shared_rela.size)
            for (size_t i = 5; i < 8; i++)
                memcpy(img + shared_dynamic.off + n++ * sizeof(Elf64_Dyn), &dynamic[i], sizeof(Elf64_Dyn));
        if (shared_init) {
            Elf64_Dyn array[] = {
                {.d_tag = DT_INIT_ARRAY, .d_un.d_ptr = out[C_INITARR].addr},
                {.d_tag = DT_INIT_ARRAYSZ, .d_un.d_val = out[C_INITARR].size}
            };
            memcpy(img + shared_dynamic.off + n * sizeof(Elf64_Dyn), array, sizeof array);
            n += 2;
        }
        if (shared_fini) {
            Elf64_Dyn array[] = {
                {.d_tag = DT_FINI_ARRAY, .d_un.d_ptr = out[C_FINIARR].addr},
                {.d_tag = DT_FINI_ARRAYSZ, .d_un.d_val = out[C_FINIARR].size}
            };
            memcpy(img + shared_dynamic.off + n * sizeof(Elf64_Dyn), array, sizeof array);
            n += 2;
        }
        memcpy(img + shared_dynamic.off + n * sizeof(Elf64_Dyn), &dynamic[8], sizeof(Elf64_Dyn));
    }
    
    if (out[C_COMMENT].size) {
        memcpy(img + out[C_COMMENT].off, prov_comment_buf, out[C_COMMENT].size);
    }

    if (nerrors) exit(1);

    const char *effective_entry = script_entry_sym ? script_entry_sym : entry;
    uint64_t entry_addr = 0;
    if (!is_shared) {
        entry_addr = out[C_TEXT].addr;
        GSym *eg = lookup(symtab, effective_entry, 0);
        if (eg && eg->state != S_UNDEF) entry_addr = eg->addr;
        else if (is_dynamic) die("cannot find dynamic executable entry symbol `%s'", effective_entry);
        else warn("cannot find entry symbol %s; defaulting to %#llx", effective_entry,
                  (unsigned long long)entry_addr);
    }
    if (is_dynamic && shared_init) {
        uint8_t *code = img + out[C_TEXT].off + executable_init_offset;
        uint64_t array_start = out[C_INITARR].addr;
        if (out[C_INITARR].size > UINT64_MAX - array_start)
            die("executable constructor array is too large");
        uint64_t array_end = array_start + out[C_INITARR].size;
        memcpy(code, executable_init_code, sizeof executable_init_code);
        uint64_t stub_addr = out[C_TEXT].addr + executable_init_offset;
        patch_stub_address(code, stub_addr, EXEC_INIT_START, array_start);
        patch_stub_address(code, stub_addr, EXEC_INIT_END, array_end);
        patch_stub_address(code, stub_addr, EXEC_INIT_ENTRY, entry_addr);
        entry_addr = out[C_TEXT].addr + executable_init_offset;
    }
    if (is_dynamic) {
        uint8_t *code = img + out[C_TEXT].off + executable_fini_offset;
        if (shared_fini) {
            uint64_t guard = out[C_BSS].addr + executable_fini_guard;
            uint64_t array_start = out[C_FINIARR].addr;
            if (out[C_FINIARR].size > UINT64_MAX - array_start)
                die("executable finalizer array is too large");
            uint64_t array_end = array_start + out[C_FINIARR].size;
            memcpy(code, executable_fini_code, sizeof executable_fini_code);
            uint64_t stub_addr = out[C_TEXT].addr + executable_fini_offset;
            patch_stub_address(code, stub_addr, EXEC_FINI_GUARD, guard);
            patch_stub_address(code, stub_addr, EXEC_FINI_START, array_start);
            patch_stub_address(code, stub_addr, EXEC_FINI_END, array_end);
        } else {
            *code = 0xc3;
        }
    }

    Elf64_Ehdr eh; memset(&eh, 0, sizeof eh);
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64; eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT; eh.e_ident[EI_OSABI] = ELFOSABI_NONE;
    eh.e_type = is_pie || is_shared ? ET_DYN : ET_EXEC;
    eh.e_machine = EM_X86_64; eh.e_version = EV_CURRENT;
    eh.e_entry = entry_addr;
    eh.e_phoff = sizeof eh; eh.e_shoff = shoff;
    eh.e_ehsize = sizeof eh; eh.e_phentsize = sizeof(Elf64_Phdr); eh.e_phnum = (uint16_t)nphdr;
    eh.e_shentsize = sizeof(Elf64_Shdr); eh.e_shnum = (uint16_t)nsec; eh.e_shstrndx = (uint16_t)shstrndx;
    memcpy(img, &eh, sizeof eh);

    Elf64_Phdr ph[8]; memset(ph, 0, sizeof ph);
    int np = 0;
    if (is_dynamic && is_pie) {
        ph[np].p_type = PT_PHDR;
        ph[np].p_flags = PF_R;
        ph[np].p_offset = sizeof(Elf64_Ehdr);
        ph[np].p_vaddr = ph[np].p_paddr = image_base + ph[np].p_offset;
        ph[np].p_filesz = ph[np].p_memsz = (uint64_t)nphdr * sizeof(Elf64_Phdr);
        ph[np].p_align = 8;
        np++;
    }
    if (is_dynamic) {
        ph[np].p_type = PT_INTERP;
        ph[np].p_flags = PF_R;
        ph[np].p_offset = sizeof(Elf64_Ehdr) + (uint64_t)nphdr * sizeof(Elf64_Phdr);
        ph[np].p_vaddr = ph[np].p_paddr = image_base + ph[np].p_offset;
        ph[np].p_filesz = ph[np].p_memsz = strlen(dynamic_linker) + 1;
        ph[np].p_align = 1;
        memcpy(img + ph[np].p_offset, dynamic_linker, ph[np].p_filesz);
        np++;
    }
    ph[np].p_type = PT_LOAD; ph[np].p_flags = PF_R | PF_X;
    ph[np].p_offset = 0; ph[np].p_vaddr = ph[np].p_paddr = image_base;
    ph[np].p_filesz = ph[np].p_memsz = rx_end - image_base; ph[np].p_align = PAGE;
    np++;
    if (have_rw) {
        ph[np].p_type = PT_LOAD; ph[np].p_flags = PF_R | PF_W;
        ph[np].p_offset = rwoff; ph[np].p_vaddr = ph[np].p_paddr = rwaddr;
        ph[np].p_filesz = filesz_end - rwaddr; ph[np].p_memsz = rw_end - rwaddr;
        ph[np].p_align = PAGE;
        np++;
    }
    if (dynamic_output()) {
        ph[np].p_type = PT_DYNAMIC; ph[np].p_flags = PF_R | PF_W;
        ph[np].p_offset = shared_dynamic.off;
        ph[np].p_vaddr = ph[np].p_paddr = shared_dynamic.addr;
        ph[np].p_filesz = ph[np].p_memsz = shared_dynamic.size;
        ph[np].p_align = shared_dynamic.align;
        np++;
    }
    if (relro) {
        ph[np].p_type = PT_GNU_RELRO; ph[np].p_flags = PF_R;
        ph[np].p_offset = rwoff;
        ph[np].p_vaddr = ph[np].p_paddr = rwaddr;
        ph[np].p_filesz = ph[np].p_memsz = relro_end - rwaddr;
        ph[np].p_align = 1;
        np++;
    }
    ph[np].p_type = PT_GNU_STACK; ph[np].p_flags = PF_R | PF_W; ph[np].p_align = 16;
    np++;
    memcpy(img + sizeof eh, ph, (size_t)np * sizeof(Elf64_Phdr));

    if (strip_level < 2) {
        memcpy(img + shdrs[shstrndx - 2].sh_offset, symb.p, symb.n);
        memcpy(img + shdrs[shstrndx - 1].sh_offset, strb.p, strb.n);
    }
    memcpy(img + shdrs[shstrndx].sh_offset, shstr.p, shstr.n);
    memcpy(img + shoff, shdrs, (size_t)nsec * sizeof(Elf64_Shdr));
    free(symb.p);
    free(strb.p);
    free(shstr.p);

    if (unlink(path) != 0 && (errno == EISDIR || errno == EPERM)) rmdir(path);
    FILE *f = fopen(path, "wb");
    if (!f) die("cannot open %s for writing", path);
    if (fwrite(img, 1, total, f) != total) die("write error on %s", path);
    fclose(f);
    mode_t m = umask(0); umask(m);
    chmod(path, 0777 & ~m);
}

/* ----------------------------------------------------------------- driver */

enum { INPUT_FILE, INPUT_GROUP_START, INPUT_GROUP_END };
typedef struct {
    char *path;
    int is_lib, kind, processed, first_member, end_member;
    int group_match, group_previous, group_objects;
} Input;
static Input *inputs;
static int ninputs, capin;
static const char **libdirs;
static int nlibdirs, caplib;

/*
 * Trim whitespace around a configuration field.
 * Inputs: text - mutable null-terminated string
 * Outputs: Pointer to the trimmed string
 */
static char *trim_config(char *text) {
    while (isspace((unsigned char)*text)) text++;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) end--;
    *end = 0;
    return text;
}

/*
 * Append configured library directories after command-line directories.
 * Inputs: environment - process environment vector
 * Outputs: Updates libdirs; reports configuration errors
 */
static void load_library_config(char **environment) {
    const char *path = NULL;
    for (char **entry = environment; entry && *entry; entry++) {
        if (!strncmp(*entry, "CRUNCH_CONF_FILE=", 17)) {
            path = *entry + 17;
            break;
        }
    }
    if (!path) path = CRUNCH_DEFAULT_CONF_FILE;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return;
        die("cannot read configuration file '%s': %s", path, strerror(errno));
    }
    char *line = NULL;
    size_t capacity = 0;
    unsigned long number = 0;
    while (getline(&line, &capacity, f) != -1) {
        number++;
        char *key = trim_config(line);
        if (!*key || *key == '#') continue;
        char *equals = strchr(key, '=');
        if (!equals) die("%s:%lu: expected 'key = value'", path, number);
        *equals = 0;
        key = trim_config(key);
        char *value = trim_config(equals + 1);
        if (strcmp(key, "library_path")) continue;
        size_t length = strlen(value);
        if (!length || *value == ':' || value[length - 1] == ':' || strstr(value, "::"))
            die("%s:%lu: empty directory in library_path", path, number);
        char *save = NULL;
        for (char *dir = strtok_r(value, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
            GROW(libdirs, nlibdirs, caplib);
            libdirs[nlibdirs++] = xstrdup(dir);
        }
    }
    if (ferror(f)) die("failed reading '%s'", path);
    free(line);
    if (fclose(f)) die("failed closing '%s'", path);
}

/*
 * Identify an explicitly named Crunch runtime input.
 * Inputs: input - command-line input descriptor
 * Outputs: Nonzero for runtime library names
 */
static int is_runtime_input(const Input *input) {
    if (input->kind != INPUT_FILE) return 0;
    const char *name = input->path;
    if (input->is_lib && !strcmp(name, "crunch")) return 1;
    if (input->is_lib && *name == ':') name++;
    const char *base = strrchr(name, '/');
    if (base) name = base + 1;
    return !strcmp(name, "libcrunch.a") || !strcmp(name, "libcrunch.so") ||
           !strncmp(name, "libcrunch.so.", 13);
}

/*
 * Locate an optional automatic runtime in configured paths or the default directory.
 * Inputs: name - runtime library filename
 * Outputs: Allocated path, or NULL if no readable file exists
 */
static char *find_runtime(const char *name) {
    char path[PATH_MAX];
    for (int i = 0; i <= nlibdirs; i++) {
        const char *dir = i == nlibdirs ? CRUNCH_DEFAULT_RUNTIME_DIR : libdirs[i];
        int n = snprintf(path, sizeof path, "%s/%s", dir, name);
        if (n < 0 || (size_t)n >= sizeof path) die("runtime library path too long");
        if (access(path, R_OK) == 0) return xstrdup(path);
        if (i < nlibdirs) {
            n = snprintf(path, sizeof path, "%s/crunch/%s", dir, name);
            if (n < 0 || (size_t)n >= sizeof path) die("runtime library path too long");
            if (access(path, R_OK) == 0) return xstrdup(path);
        }
    }
    return NULL;
}

#ifdef __CRUNCH__
/*
 * Resolve an existing runtime directory, following symbolic links.
 * Inputs: path - directory path
 * Outputs: Allocated absolute path, or NULL with errno set.
 */
static char *resolve_runtime_directory(const char *path) {
    char resolved[PATH_MAX], pending[PATH_MAX], target[PATH_MAX];
    size_t length = strlen(path), resolved_len;
    int links = 0;
    if (!length) { errno = ENOENT; return NULL; }
    if (length >= sizeof pending) { errno = ENAMETOOLONG; return NULL; }
    memcpy(pending, path, length + 1);
    if (*path == '/') {
        resolved[0] = '/'; resolved[1] = 0; resolved_len = 1;
    } else {
        if (!getcwd(resolved, sizeof resolved)) return NULL;
        resolved_len = strlen(resolved);
    }
    char *next = pending;
    while (*next) {
        while (*next == '/') next++;
        if (!*next) break;
        char *component = next;
        while (*next && *next != '/') next++;
        size_t component_len = (size_t)(next - component);
        if (component_len == 1 && component[0] == '.') continue;
        if (component_len == 2 && component[0] == '.' && component[1] == '.') {
            while (resolved_len > 1 && resolved[resolved_len - 1] != '/') resolved_len--;
            if (resolved_len > 1) resolved_len--;
            resolved[resolved_len] = 0;
            continue;
        }
        size_t parent_len = resolved_len;
        if (resolved_len + (resolved_len > 1) + component_len >= sizeof resolved) {
            errno = ENAMETOOLONG; return NULL;
        }
        if (resolved_len > 1) resolved[resolved_len++] = '/';
        memcpy(resolved + resolved_len, component, component_len);
        resolved_len += component_len;
        resolved[resolved_len] = 0;
        struct stat st;
        if (lstat(resolved, &st) != 0) return NULL;
        if ((st.st_mode & 0170000) == 0120000) {
            if (++links > 40) { errno = ELOOP; return NULL; }
            ssize_t n = readlink(resolved, target, sizeof target);
            if (n < 0) return NULL;
            if ((size_t)n == sizeof target) { errno = ENAMETOOLONG; return NULL; }
            target[n] = 0;
            size_t rest = strlen(next);
            if ((size_t)n + rest >= sizeof pending) { errno = ENAMETOOLONG; return NULL; }
            memmove(pending + n, next, rest + 1);
            memcpy(pending, target, (size_t)n);
            next = pending;
            if (target[0] == '/') {
                resolved_len = 1; resolved[1] = 0;
            } else {
                resolved_len = parent_len; resolved[resolved_len] = 0;
            }
        } else if ((st.st_mode & 0170000) != 0040000) {
            errno = ENOTDIR; return NULL;
        }
    }
    return xstrdup(resolved);
}
#else
/*
 * Resolve an existing runtime directory, following symbolic links.
 * Inputs: path - directory path
 * Outputs: Allocated absolute path, or NULL with errno set.
 */
static char *resolve_runtime_directory(const char *path) {
    return realpath(path, NULL);
}
#endif

/*
 * Add the automatic shared runtime's directory to the loader search path.
 * Inputs: runtime - selected library path
 * Outputs: Appends an absolute, literal directory to shared_runpath
 */
static void add_runtime_runpath(const char *runtime) {
    char *dir = xstrdup(runtime);
    char *slash = strrchr(dir, '/');
    if (slash == dir) slash[1] = 0;
    else *slash = 0;
    char *absolute = resolve_runtime_directory(dir);
    if (!absolute) die("cannot resolve runtime directory '%s': %s", dir, strerror(errno));
    if (strchr(absolute, ':') || strchr(absolute, '$'))
        die("runtime directory cannot be embedded in RUNPATH: '%s'", absolute);
    if (shared_runpath.n) buf_add(&shared_runpath, ":", 1);
    buf_add(&shared_runpath, absolute, strlen(absolute));
    free(absolute);
    free(dir);
}

/*
 * Register an input object file or library specification.
 * Inputs: p - file path or library name, is_lib - flag indicating library search (-l)
 * Outputs: None
 */
static void add_input(const char *p, int is_lib) {
    GROW(inputs, ninputs, capin);
    inputs[ninputs].path = xstrdup(p);
    inputs[ninputs].is_lib = is_lib;
    inputs[ninputs].kind = INPUT_FILE;
    inputs[ninputs].processed = 0;
    ninputs++;
}

/*
 * Register an archive group delimiter and match it with its partner.
 * Inputs: kind - group start or end, current - index of the open group
 * Outputs: None; updates current to the innermost open group
 */
static void add_group(int kind, int *current) {
    if (kind == INPUT_GROUP_END && *current < 0)
        die("group ended before it began");
    GROW(inputs, ninputs, capin);
    Input *input = &inputs[ninputs];
    memset(input, 0, sizeof *input);
    input->kind = kind;
    if (kind == INPUT_GROUP_START) {
        input->group_previous = *current;
        *current = ninputs;
    } else {
        input->group_match = *current;
        inputs[*current].group_match = ninputs;
        *current = inputs[*current].group_previous;
    }
    ninputs++;
}

/*
 * Search library paths, preferring shared libraries for shared output.
 * Inputs: name - library name string
 * Outputs: Allocated file path string to found library
 */
static char *find_lib(const char *name) {
    static const char *defdirs[] = {"/usr/local/lib", "/usr/lib", "/lib",
                                    "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", NULL};
    char path[4096];
    for (int pass = 0; pass < 2; pass++) {
        int n = pass == 0 ? nlibdirs : 5;
        for (int i = 0; i < n; i++) {
            const char *d = pass == 0 ? libdirs[i] : defdirs[i];
            if (name[0] == ':') {
                if (snprintf(path, sizeof path, "%s/%s", d, name + 1) >= (int)sizeof path)
                    die("library path too long");
                if (access(path, R_OK) == 0) return xstrdup(path);
                if (!strncmp(name + 1, "libcrunch.", 10)) {
                    if (snprintf(path, sizeof path, "%s/crunch/%s", d, name + 1) >= (int)sizeof path)
                        die("library path too long");
                    if (access(path, R_OK) == 0) return xstrdup(path);
                }
            } else {
                if (dynamic_output()) {
                    if (snprintf(path, sizeof path, "%s/lib%s.so", d, name) >= (int)sizeof path)
                        die("library path too long");
                    if (access(path, R_OK) == 0) return xstrdup(path);
                    if (!strcmp(name, "crunch")) {
                        if (snprintf(path, sizeof path, "%s/crunch/libcrunch.so", d) >= (int)sizeof path)
                            die("library path too long");
                        if (access(path, R_OK) == 0) return xstrdup(path);
                    }
                }
                if (snprintf(path, sizeof path, "%s/lib%s.a", d, name) >= (int)sizeof path)
                    die("library path too long");
                if (access(path, R_OK) == 0) return xstrdup(path);
                if (!strcmp(name, "crunch")) {
                    if (snprintf(path, sizeof path, "%s/crunch/libcrunch.a", d) >= (int)sizeof path)
                        die("library path too long");
                    if (access(path, R_OK) == 0) return xstrdup(path);
                }
            }
        }
    }
    if (!strcmp(name, "crunch") || !strcmp(name, ":libcrunch.a") ||
        !strcmp(name, ":libcrunch.so") || !strncmp(name, ":libcrunch.so.", 14)) {
        const char *filename = name[0] == ':' ? name + 1 :
                               dynamic_output() ? "libcrunch.so" : "libcrunch.a";
        char *runtime = find_runtime(filename);
        if (runtime) return runtime;
    }
    die("cannot find -l%s", name);
    return NULL;
}

/*
 * Parse command-line argument flags and optional parameters.
 * Inputs: argc - argument count, argv - argument vector, i - current index pointer, shortn - short flag, longn - long flag, val - output parameter value pointer
 * Outputs: 1 if matched, 0 otherwise
 */
static int match(int argc, char **argv, int *i, const char *shortn, const char *longn,
                 const char **val) {
    const char *a = argv[*i];
    if (shortn && a[0] == '-' && a[1] == shortn[0] && a[1] != '-') {
        if (a[2]) { *val = a + 2; return 1; }
        if (*i + 1 < argc) { *val = argv[++*i]; return 1; }
        die("missing argument to %s", a);
    }
    if (longn && !strncmp(a, "--", 2) && !strncmp(a + 2, longn, strlen(longn))) {
        size_t n = strlen(longn);
        if (a[2 + n] == '=') { *val = a + 3 + n; return 1; }
        if (!a[2 + n]) {
            if (*i + 1 < argc) { *val = argv[++*i]; return 1; }
            die("missing argument to %s", a);
        }
    }
    return 0;
}

/*
 * Read and parse a linker script file (-T).
 * Inputs: path - linker script file path
 * Outputs: None
 */
static void load_script_file(const char *path) {
    size_t sz = 0;
    uint8_t *buf = read_file(path, &sz);
    if (!buf) die("cannot open linker script %s", path);
    parse_linker_script(path, (const char *)buf);
    free(buf);
}

/*
 * Print the supported command-line options.
 * Inputs: None
 * Outputs: Help text on standard output
 */
static void print_help(void) {
    puts("Usage: crunch-ld [options] file...\n"
         "  -o FILE, --output=FILE          Set output file (default a.out)\n"
         "  -r, --relocatable               Produce a relocatable object\n"
         "  -shared, --shared               Produce a shared object\n"
         "  -dynamic, --dynamic             Produce a dynamic executable\n"
         "  -pie, --pie, -fPIE, -fpie      Produce a position-independent executable\n"
         "  -I PATH, --dynamic-linker=PATH Select dynamic interpreter\n"
         "  -e SYMBOL, --entry=SYMBOL      Set executable entry symbol\n"
         "  -L DIR, --library-path=DIR     Add library search directory\n"
         "  -l NAME, --library=NAME        Link library at this position\n"
         "  --start-group, -( / --end-group, -)  Rescan archive group\n"
         "  -T FILE, --script=FILE         Read a linker script\n"
         "  -M FILE, --Map=FILE            Write a link map\n"
         "  -u SYMBOL, --undefined=SYMBOL  Force an undefined symbol\n"
         "  --require-defined=SYMBOL       Require a definition\n"
         "  --forbid-defined=SYMBOL        Reject output-object definitions\n"
         "  --unique-shared-symbol=SYMBOL  Reject multiple shared definitions\n"
         "  --no-undefined                 Reject unresolved shared references\n"
         "  -soname NAME, --soname=NAME, -h NAME  Set shared SONAME\n"
         "  -rpath PATH, --rpath PATH      Add runtime search path\n"
         "  -z relro                       Protect dynamic relocation data\n"
         "  -nostdlib, -nodefaultlibs      Do not add the Crunch runtime\n"
         "  -crt0, --crt0                  Add the optional startup object\n"
         "  --gc-sections, --no-gc-sections  Control section garbage collection\n"
         "  --print-gc-sections            Report discarded sections\n"
         "  -s, --strip-all                Omit ordinary symbol tables\n"
         "  -S, -D, --strip-debug          Omit local symbols\n"
         "  -Wabi-mismatch, -Wall          Warn about possible ABI mismatches\n"
         "  -get                           Accepted and ignored\n"
         "  -v, --version                  Show version\n"
         "  --help                         Show this help");
}

/*
 * Main driver function: parses command-line arguments, loads inputs, resolves symbols, lays out memory, and outputs executable.
 * Inputs: argc - argument count, argv - argument vector, environment - environment vector
 * Outputs: Exit status code (0 on success, 1 on error)
 */
int main(int argc, char **argv, char **environment) {
    const char *output = "a.out", *entry = "_start";
    const char *reloc_incompatible = NULL;
    const char *shared_incompatible = NULL;
    int text_base_option = 0, script_option = 0;
    const char **required = NULL;
    int nrequired = 0, caprequired = 0;
    const char **forbidden = NULL;
    int nforbidden = 0, capforbidden = 0;
    const char **unique_shared = NULL;
    int nunique_shared = 0, capunique_shared = 0;
    int current_group = -1;
    int no_undefined = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v;
        if (a[0] != '-' || !a[1]) { add_input(a, 0); continue; }

        if (!strcmp(a, "--help")) { print_help(); return 0; }
        if (!strcmp(a, "-s") || !strcmp(a, "--strip-all")) { strip_level = 2; continue; }
        if (!strcmp(a, "-S") || !strcmp(a, "--strip-debug") || !strcmp(a, "-D")) { strip_level = 1; continue; }
        if (!strcmp(a, "-v") || !strcmp(a, "--version")) { puts("crunch-ld " CRUNCH_VERSION); return 0; }
        if (!strcmp(a, "-shared") || !strcmp(a, "--shared")) { is_shared = 1; continue; }
        if (!strcmp(a, "-dynamic") || !strcmp(a, "--dynamic")) { is_dynamic = 1; continue; }
        if (!strcmp(a, "-z") || !strncmp(a, "-z", 2)) {
            if (a[2]) v = a + 2;
            else if (++i < argc) v = argv[i];
            else die("missing argument to -z");
            if (strcmp(v, "relro")) die("unsupported -z option '%s'", v);
            relro = 1; continue;
        }
        if (!strcmp(a, "--no-undefined")) { no_undefined = 1; continue; }
        if (!strcmp(a, "-Wabi-mismatch") || !strcmp(a, "-Wall")) { warn_abi_mismatch = 1; continue; }
        if (!strcmp(a, "-soname")) {
            if (++i >= argc || !*argv[i]) die("missing argument to -soname");
            shared_soname = argv[i]; continue;
        }
        if (!strcmp(a, "-rpath") || !strcmp(a, "--rpath")) {
            if (++i >= argc) die("missing argument to %s", a);
            v = argv[i];
        } else if (!strncmp(a, "-rpath=", 7)) {
            v = a + 7;
        } else if (!strncmp(a, "--rpath=", 8)) {
            v = a + 8;
        } else {
            v = NULL;
        }
        if (v) {
            if (!*v) die("empty runtime search path");
            if (shared_runpath.n) buf_add(&shared_runpath, ":", 1);
            buf_add(&shared_runpath, v, strlen(v));
            continue;
        }
        if (!strcmp(a, "-pie") || !strcmp(a, "--pie") || !strcmp(a, "-fPIE") || !strcmp(a, "-fpie")) {
            is_pie = 1;
            continue;
        }
        if (!strcmp(a, "-nostdlib") || !strcmp(a, "-nodefaultlibs")) {
            nostdlib = 1;
            continue;
        }
        if (!strcmp(a, "-crt0") || !strcmp(a, "--crt0")) {
            use_crt0 = 1;
            continue;
        }
        if (!strcmp(a, "--gc-sections")) { gc_enabled = 1; continue; }
        if (!strcmp(a, "--no-gc-sections")) { gc_enabled = 0; continue; }
        if (!strcmp(a, "--print-gc-sections")) { print_gc = 1; continue; }
        if (!strcmp(a, "-r") || !strcmp(a, "--relocatable")) { relocatable = 1; continue; }
        if (!strcmp(a, "--start-group") || !strcmp(a, "-(")) {
            add_group(INPUT_GROUP_START, &current_group); continue;
        }
        if (!strcmp(a, "--end-group") || !strcmp(a, "-)")) {
            add_group(INPUT_GROUP_END, &current_group); continue;
        }
        if (!strcmp(a, "-get")) continue;
        if (match(argc, argv, &i, "T", "script", &v)) {
            script_option = 1; reloc_incompatible = "linker scripts"; load_script_file(v); continue;
        }
        if (match(argc, argv, &i, "u", "undefined", &v)) {
            shared_incompatible = "forced undefined symbols";
            GSym *g = lookup(symtab, v, 1);
            if (g->state == S_UNDEF || g->state == 0) {
                g->state = S_UNDEF;
                g->strong_ref = 1;
            }
            continue;
        }
        if (match(argc, argv, &i, NULL, "require-defined", &v)) {
            GSym *g = lookup(symtab, v, 1);
            g->strong_ref = 1;
            g->required = 1;
            GROW(required, nrequired, caprequired);
            required[nrequired++] = v;
            continue;
        }
        if (match(argc, argv, &i, NULL, "forbid-defined", &v)) {
            if (!*v || *v == '-') die("missing argument to --forbid-defined");
            GROW(forbidden, nforbidden, capforbidden);
            forbidden[nforbidden++] = v;
            continue;
        }
        if (match(argc, argv, &i, NULL, "unique-shared-symbol", &v)) {
            if (!*v || *v == '-') die("missing argument to --unique-shared-symbol");
            GROW(unique_shared, nunique_shared, capunique_shared);
            unique_shared[nunique_shared++] = v;
            continue;
        }
        if (!strncmp(a, "-Ttext-segment=", 15)) {
            text_base_option = 1; image_base = strtoull(a + 15, NULL, 0); continue;
        }
        
        if (match(argc, argv, &i, "I", "dynamic-linker", &v)) { dynamic_linker = v; is_dynamic = 1; continue; }
        if (match(argc, argv, &i, "M", "Map", &v)) { map_filename = v; continue; }
        if (match(argc, argv, &i, "o", "output", &v)) { output = v; continue; }
        if (match(argc, argv, &i, "h", "soname", &v)) {
            if (!*v) die("empty shared SONAME");
            shared_soname = v; continue;
        }
        if (match(argc, argv, &i, "e", "entry", &v)) {
            reloc_incompatible = "entry selection"; entry = v; continue;
        }
        if (match(argc, argv, &i, "L", "library-path", &v)) {
            GROW(libdirs, nlibdirs, caplib); libdirs[nlibdirs++] = v; continue; }
        if (match(argc, argv, &i, "l", "library", &v)) { add_input(v, 1); continue; }
        die("unsupported option '%s'", a);
    }

    if (current_group >= 0) die("missing --end-group");
    if (is_dynamic && !dynamic_linker) dynamic_linker = CRUNCH_DYNAMIC_LINKER;
    if (is_dynamic && (!*dynamic_linker || dynamic_linker[0] != '/'))
        die("dynamic interpreter must be an absolute path");
    if (is_dynamic && (is_shared || relocatable || gc_enabled || print_gc ||
                       use_crt0 || text_base_option || script_option || shared_incompatible))
        die("selected options are not supported with dynamic executable output");
    if (no_undefined && !is_shared) die("--no-undefined is only supported with shared output");
    if (shared_soname && !is_shared) die("SONAME is only supported with shared output");
    if (shared_runpath.n && (!dynamic_output() || relocatable))
        die("runtime search path is only supported with shared or dynamic executable output");
    if (relro && (!dynamic_output() || relocatable))
        die("-z relro is only supported with shared or dynamic executable output");
    if (relocatable && (reloc_incompatible || strip_level || is_pie || dynamic_linker ||
                        gc_enabled || print_gc || use_crt0 || map_filename || is_shared))
        die("%s is not supported with relocatable linking",
            reloc_incompatible ? reloc_incompatible : "the selected option");
    if (is_shared && (shared_incompatible || reloc_incompatible || is_pie || dynamic_linker ||
                      gc_enabled || print_gc || use_crt0 || map_filename))
        die("%s is not supported with shared output",
            shared_incompatible ? shared_incompatible :
            reloc_incompatible ? reloc_incompatible : "the selected option");

    load_library_config(environment);
    if (!nostdlib && !relocatable) {
        int explicit_runtime = 0;
        for (int i = 0; i < ninputs; i++)
            if (is_runtime_input(&inputs[i])) explicit_runtime = 1;
        char *runtime = explicit_runtime ? NULL :
            find_runtime(dynamic_output() ? "libcrunch.so" : "libcrunch.a");
        if (runtime) {
            struct stat runtime_stat, other_stat;
            if (stat(runtime, &runtime_stat) == 0) {
                for (int i = 0; i < ninputs; i++) {
                    if (inputs[i].kind != INPUT_FILE) continue;
                    char *resolved = inputs[i].is_lib ? find_lib(inputs[i].path) : NULL;
                    const char *path = resolved ? resolved : inputs[i].path;
                    if (stat(path, &other_stat) == 0 && other_stat.st_dev == runtime_stat.st_dev &&
                        other_stat.st_ino == runtime_stat.st_ino) explicit_runtime = 1;
                    free(resolved);
                }
                if (!explicit_runtime && stat(output, &other_stat) == 0 &&
                    other_stat.st_dev == runtime_stat.st_dev && other_stat.st_ino == runtime_stat.st_ino)
                    die("output '%s' is also the runtime input", output);
            }
            if (!explicit_runtime) {
                if (dynamic_output()) add_runtime_runpath(runtime);
                if (is_dynamic) {
                    char *slash = strrchr(runtime, '/');
                    char fallback[PATH_MAX];
                    int n = snprintf(fallback, sizeof fallback, "%.*s/libcrunch-fallback.a",
                                     (int)(slash - runtime), runtime);
                    if (n < 0 || (size_t)n >= sizeof fallback) die("runtime library path too long");
                    if (access(fallback, R_OK) == 0) add_input(fallback, 0);
                }
                add_input(runtime, 0);
            }
            free(runtime);
        }
    }

    if (use_crt0) {
        const char *crt0_path = "/usr/local/lib/crunch/crt0.o";
        if (access(crt0_path, R_OK) != 0) crt0_path = "crt0.o";
        if (access(crt0_path, R_OK) == 0) {
            Input *new_inputs = xcalloc(ninputs + 2, sizeof(Input));
            new_inputs[0].path = xstrdup(crt0_path);
            new_inputs[0].is_lib = 0;
            for (int j = 0; j < ninputs; j++) {
                new_inputs[j + 1] = inputs[j];
                if (inputs[j].kind != INPUT_FILE) new_inputs[j + 1].group_match++;
            }
            inputs = new_inputs;
            ninputs++;
        } else {
            die("cannot find crt0.o");
        }
    }

    int has_input = 0;
    for (int i = 0; i < ninputs; i++)
        if (inputs[i].kind == INPUT_FILE) has_input = 1;
    if (!has_input) die("no input files");

    for (int i = 0; i < ninputs; i++) {
        Input *input = &inputs[i];
        if (input->kind == INPUT_GROUP_START) {
            input->group_objects = nobjs;
            continue;
        }
        if (input->kind == INPUT_GROUP_END) {
            Input *start = &inputs[input->group_match];
            if (start->group_objects != nobjs) {
                start->group_objects = nobjs;
                i = input->group_match;
            }
            continue;
        }
        if (!input->processed) {
            char *path = input->is_lib ? find_lib(input->path) : input->path;
            size_t size;
            uint8_t *buf = read_file(path, &size);
            if (!buf) die("cannot open %s", path);
            input->first_member = nmembers;
            if (size >= 8 && !memcmp(buf, "!<arch>\n", 8)) {
                add_archive(path, buf, size);
                free(buf);
            } else if (size >= SELFMAG && !memcmp(buf, ELFMAG, SELFMAG)) {
                if (dynamic_output() && size >= sizeof(Elf64_Ehdr)) {
                    Elf64_Ehdr eh;
                    memcpy(&eh, buf, sizeof eh);
                    if (eh.e_type == ET_DYN) {
                        if (!add_shared_input(path, buf, size, input->is_lib)) free(buf);
                    } else add_object(path, buf, size);
                } else add_object(path, buf, size);
            } else if (relocatable || dynamic_output()) {
                die("%s: input is not an ELF object or archive", path);
            } else {
                if (memchr(buf, 0, size) || !parse_linker_script(path, (const char *)buf))
                    die("%s: input is not an ELF object, archive, or recognized linker script", path);
                free(buf);
            }
            input->end_member = nmembers;
            input->processed = 1;
        }
        resolve_archive(input->first_member, input->end_member);
    }
    if (nerrors) return 1;

    if (warn_abi_mismatch) warn_abi_mismatches();

    if (is_dynamic) {
        for (int i = 0; i < nall; i++) {
            GSym *g = allsyms[i];
            if (!g->runtime_guard_shared || g->state != S_DEF)
                continue;
            size_t length = strlen(g->name) + sizeof "__crunch_fallback_";
            char *name = xcalloc(length, 1);
            snprintf(name, length, "__crunch_fallback_%s", g->name);
            GSym *fallback = lookup(symtab, name, 0);
            free(name);
            if (fallback && fallback->state == S_DEF &&
                fallback->obj == g->obj && fallback->shndx == g->shndx &&
                fallback->value == g->value)
                error("shared library requires a user definition of `%s'; "
                      "the executable selects an incompatible runtime fallback", g->name);
        }
    }
    if (nerrors) return 1;

    for (int i = 0; i < nforbidden; i++) {
        GSym *g = lookup(symtab, forbidden[i], 0);
        if (g && g->state != S_UNDEF)
            error("symbol `%s' must not be defined in the output", forbidden[i]);
    }
    free(forbidden);
    for (int i = 0; i < nunique_shared; i++) {
        GSym *g = lookup(symtab, unique_shared[i], 0);
        if (g && g->dynamic_definitions > 1)
            error("symbol `%s' is defined by multiple shared inputs", unique_shared[i]);
    }
    free(unique_shared);
    if (nerrors) return 1;

    if (relocatable) {
        for (int i = 0; i < nrequired; i++) {
            GSym *g = lookup(symtab, required[i], 0);
            if (!g || g->state == S_UNDEF)
                error("required symbol `%s' is not defined", required[i]);
        }
        free(required);
        if (nerrors) return 1;
        write_relocatable(output);
        return 0;
    }

    if (gc_enabled) gc_sections(entry);

    if (dynamic_output()) prepare_shared();
    else collect_got();
    layout();
    if (no_undefined || is_dynamic) {
        for (int i = 0; i < nall; i++) {
            GSym *g = allsyms[i];
            if (g->state == S_UNDEF && g->shared_ref && g->strong_ref && !g->dynamic_defined)
                error("undefined reference to `%s'", g->name);
        }
    }
    for (int i = 0; i < nrequired; i++) {
        GSym *g = lookup(symtab, required[i], 0);
        if (!g || (g->state == S_UNDEF && !(dynamic_output() && g->dynamic_defined)))
            error("required symbol `%s' is not defined", required[i]);
    }
    free(required);
    if (nerrors) return 1;
    write_output(output, entry, strip_level);
    write_map_file();
    return nerrors ? 1 : 0;
}

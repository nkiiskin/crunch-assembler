typedef struct {
    Elf64_Shdr header;
    const uint8_t *data;
    Obj *object;
    int input_index;
    Buf contents;
} RelSection;

static void rel_pad(Buf *buffer, uint64_t alignment) {
    if (!alignment) alignment = 1;
    if ((alignment & (alignment - 1)) || alignment > SIZE_MAX ||
        buffer->n > SIZE_MAX - (size_t)(alignment - 1))
        die("invalid or excessive output section alignment");
    size_t end = (size_t)align_up(buffer->n, alignment);
    if (end > buffer->n) {
        size_t padding = end - buffer->n;
        uint8_t *zeros = xcalloc(padding, 1);
        buf_add(buffer, zeros, padding);
        free(zeros);
    }
}

static uint32_t rel_add_section(RelSection **sections, int *count, int *capacity,
                                Elf64_Shdr header, const uint8_t *data,
                                Obj *object, int input_index) {
    if (*count >= SHN_LORESERVE) die("too many output sections");
    GROW(*sections, *count, *capacity);
    RelSection *s = &(*sections)[*count];
    memset(s, 0, sizeof *s);
    s->header = header;
    s->data = data;
    s->object = object;
    s->input_index = input_index;
    return (uint32_t)(*count)++;
}

static uint32_t rel_string(Buf *strings, const char *text) {
    if (strings->n > UINT32_MAX || strlen(text) >= UINT32_MAX - strings->n)
        die("output string table too large");
    return (uint32_t)buf_add(strings, text, strlen(text) + 1);
}

static const char *rel_section_name(Obj *o, Elf64_Shdr *sh) {
    if (!o->shstr || sh->sh_name >= o->shstrsz ||
        !memchr(o->shstr + sh->sh_name, 0, o->shstrsz - sh->sh_name))
        die("%s: invalid section name", o->name);
    return o->shstr + sh->sh_name;
}

static uint16_t rel_symbol_section(Obj *o, uint16_t index) {
    if (index == SHN_UNDEF || index == SHN_ABS || index == SHN_COMMON) return index;
    if (index >= SHN_LORESERVE || index >= o->nsh || !o->section_map[index])
        die("%s: unsupported symbol section index %u", o->name, index);
    return (uint16_t)o->section_map[index];
}

static uint32_t rel_symbol(Buf *symbols, Buf *strings, Elf64_Sym symbol,
                           const char *name) {
    if (symbols->n / sizeof(Elf64_Sym) >= UINT32_MAX) die("too many output symbols");
    symbol.st_name = *name ? rel_string(strings, name) : 0;
    uint32_t index = (uint32_t)(symbols->n / sizeof(Elf64_Sym));
    buf_add(symbols, &symbol, sizeof symbol);
    return index;
}

static void write_relocatable(const char *path) {
    RelSection *sections = NULL;
    int nsections = 0, capacity = 0;
    Buf names = {0}, strings = {0}, symbols = {0}, file = {0};
    Elf64_Shdr empty_section = {0};
    Elf64_Sym empty_symbol = {0};
    buf_add(&names, "", 1);
    buf_add(&strings, "", 1);
    buf_add(&symbols, &empty_symbol, sizeof empty_symbol);
    rel_add_section(&sections, &nsections, &capacity, empty_section, NULL, NULL, 0);

    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        o->section_map = xcalloc((size_t)o->nsh, sizeof *o->section_map);
        o->symbol_map = xcalloc((size_t)o->nsyms + 1, sizeof *o->symbol_map);
        for (int k = 1; k < o->nsh; k++) {
            Elf64_Shdr h = o->sh[k];
            if (h.sh_type != SHT_GROUP || o->secs[k].discarded) continue;
            h.sh_name = rel_string(&names, rel_section_name(o, &h));
            h.sh_addr = 0;
            o->section_map[k] = rel_add_section(&sections, &nsections, &capacity, h, NULL, o, k);
        }
    }

    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        int symstr = -1;
        for (int k = 1; k < o->nsh; k++)
            if (o->sh[k].sh_type == SHT_SYMTAB) symstr = (int)o->sh[k].sh_link;
        for (int k = 1; k < o->nsh; k++) {
            Elf64_Shdr h = o->sh[k];
            if (k == o->eh->e_shstrndx || k == symstr || o->secs[k].discarded ||
                h.sh_type == SHT_SYMTAB || h.sh_type == SHT_RELA || h.sh_type == SHT_GROUP) continue;
            switch (h.sh_type) {
            case SHT_PROGBITS: case SHT_NOBITS: case SHT_NOTE: case SHT_STRTAB:
            case SHT_INIT_ARRAY: case SHT_FINI_ARRAY: case SHT_PREINIT_ARRAY:
            case SHT_X86_64_UNWIND:
                break;
            default:
                die("%s: unsupported section type %u in relocatable link", o->name, h.sh_type);
            }
            const char *name = rel_section_name(o, &h);
            h.sh_name = rel_string(&names, name);
            h.sh_addr = 0;
            const uint8_t *data = h.sh_type == SHT_NOBITS ? NULL : at(o, h.sh_offset, h.sh_size);
            o->section_map[k] = rel_add_section(&sections, &nsections, &capacity, h, data, o, k);
        }
    }

    for (int i = 1; i < nsections; i++) {
        RelSection *s = &sections[i];
        Obj *o = s->object;
        if (s->header.sh_type == SHT_GROUP) continue;
        if (s->header.sh_link) {
            if (s->header.sh_link >= (unsigned)o->nsh || !o->section_map[s->header.sh_link])
                die("%s: unsupported linked section in relocatable link", o->name);
            s->header.sh_link = o->section_map[s->header.sh_link];
        }
        if (s->header.sh_flags & SHF_INFO_LINK) {
            if (s->header.sh_info >= (unsigned)o->nsh || !o->section_map[s->header.sh_info])
                die("%s: unsupported section info in relocatable link", o->name);
            s->header.sh_info = o->section_map[s->header.sh_info];
        }
    }

    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = 1; k < o->first_global; k++) {
            Elf64_Sym s = o->syms[k];
            if (s.st_shndx < SHN_LORESERVE && s.st_shndx &&
                o->secs[s.st_shndx].discarded) continue;
            s.st_shndx = rel_symbol_section(o, s.st_shndx);
            o->symbol_map[k] = rel_symbol(&symbols, &strings, s, o->strtab + s.st_name);
        }
    }
    uint32_t first_global = (uint32_t)(symbols.n / sizeof(Elf64_Sym));
    for (int i = 0; i < nall; i++) {
        GSym *g = allsyms[i];
        if (g->state == S_UNDEF && !g->strong_ref && !g->keep_undefined) continue;
        Elf64_Sym s = g->original ? *g->original : empty_symbol;
        unsigned binding = g->state == S_UNDEF ? (g->strong_ref ? STB_GLOBAL : STB_WEAK)
                                              : (g->weak ? STB_WEAK : STB_GLOBAL);
        s.st_info = ELF64_ST_INFO(binding, ELF64_ST_TYPE(s.st_info));
        s.st_other = (s.st_other & ~3u) | g->visibility;
        if (g->state == S_UNDEF) {
            s.st_shndx = SHN_UNDEF;
            s.st_value = s.st_size = 0;
        } else if (g->state == S_COMMON) {
            s.st_shndx = SHN_COMMON;
            s.st_value = g->align;
            s.st_size = g->size;
        } else {
            s.st_shndx = rel_symbol_section(g->obj, (uint16_t)g->shndx);
            s.st_value = g->value;
            s.st_size = g->size;
        }
        g->output_index = rel_symbol(&symbols, &strings, s, g->name);
    }
    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = o->first_global; k < o->nsyms; k++)
            o->symbol_map[k] = o->gs[k]->output_index;
    }

    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = 1; k < o->nsh; k++) {
            Elf64_Shdr h = o->sh[k];
            if (h.sh_type != SHT_RELA || o->secs[k].discarded) continue;
            if (h.sh_info < (unsigned)o->nsh && o->secs[h.sh_info].discarded) continue;
            if (h.sh_info >= (unsigned)o->nsh || !o->section_map[h.sh_info] ||
                h.sh_link >= (unsigned)o->nsh || o->sh[h.sh_link].sh_type != SHT_SYMTAB ||
                h.sh_entsize != sizeof(Elf64_Rela) || h.sh_size % sizeof(Elf64_Rela))
                die("%s: invalid relocation section", o->name);
            for (int j = 1; j < k; j++)
                if (o->sh[j].sh_type == SHT_RELA && o->sh[j].sh_info == h.sh_info)
                    die("%s: multiple relocation sections for one target are unsupported", o->name);
            const char *name = rel_section_name(o, &h);
            h.sh_name = rel_string(&names, name);
            h.sh_addr = 0;
            h.sh_info = o->section_map[h.sh_info];
            h.sh_link = 0;
            uint32_t index = rel_add_section(&sections, &nsections, &capacity, h, NULL, o, k);
            o->section_map[k] = index;
            RelSection *outsec = &sections[index];
            Elf64_Rela *input = at(o, o->sh[k].sh_offset, o->sh[k].sh_size);
            for (size_t j = 0; j < h.sh_size / sizeof *input; j++) {
                Elf64_Rela r = input[j];
                uint32_t si = ELF64_R_SYM(r.r_info);
                if (si >= (uint32_t)o->nsyms || r.r_offset > o->sh[o->sh[k].sh_info].sh_size)
                    die("%s: invalid relocation", o->name);
                if (si && !o->symbol_map[si]) {
                    Elf64_Shdr *target_header = &o->sh[o->sh[k].sh_info];
                    const char *target_name = rel_section_name(o, target_header);
                    unsigned section_index = o->syms[si].st_shndx;
                    if (ELF64_R_TYPE(r.r_info) == R_X86_64_NONE) {
                        r.r_info = ELF64_R_INFO(0, R_X86_64_NONE);
                    } else if ((int)si < o->first_global && section_index < (unsigned)o->nsh &&
                               o->secs[section_index].discarded &&
                               !strncmp(target_name, ".debug", 6)) {
                        size_t width = reloc_width(ELF64_R_TYPE(r.r_info));
                        if (!width || r.r_offset > target_header->sh_size ||
                            width > target_header->sh_size - r.r_offset ||
                            target_header->sh_type == SHT_NOBITS ||
                            (target_header->sh_flags & SHF_COMPRESSED))
                            die("%s: unsupported debug relocation to discarded section", o->name);
                        RelSection *target = &sections[o->section_map[o->sh[k].sh_info]];
                        if (!target->contents.p) {
                            buf_add(&target->contents, target->data, (size_t)target_header->sh_size);
                            target->data = target->contents.p;
                        }
                        memset(target->contents.p + r.r_offset, 0, width);
                        r.r_info = ELF64_R_INFO(0, R_X86_64_NONE);
                        r.r_addend = 0;
                    } else {
                        die("%s: relocation references a discarded or unsupported symbol", o->name);
                    }
                    si = 0;
                }
                r.r_info = ELF64_R_INFO(o->symbol_map[si], ELF64_R_TYPE(r.r_info));
                buf_add(&outsec->contents, &r, sizeof r);
            }
            outsec->data = outsec->contents.p;
        }
    }

    for (int i = 0; i < nobjs; i++) {
        Obj *o = objs[i];
        for (int k = 1; k < o->nsh; k++) {
            Elf64_Shdr *input = &o->sh[k];
            if (input->sh_type != SHT_GROUP || o->secs[k].discarded) continue;
            RelSection *group = &sections[o->section_map[k]];
            uint32_t *members = at(o, input->sh_offset, input->sh_size);
            buf_add(&group->contents, members, sizeof *members);
            for (size_t j = 1; j < input->sh_size / sizeof *members; j++) {
                uint32_t mapped = o->section_map[members[j]];
                if (!mapped) die("%s: unsupported section group member", o->name);
                buf_add(&group->contents, &mapped, sizeof mapped);
            }
            if (!o->symbol_map[input->sh_info])
                die("%s: discarded section group signature", o->name);
            group->header.sh_info = o->symbol_map[input->sh_info];
            group->data = group->contents.p;
        }
    }

    Elf64_Shdr h = {0};
    h.sh_name = rel_string(&names, ".symtab");
    h.sh_type = SHT_SYMTAB; h.sh_size = symbols.n; h.sh_addralign = 8;
    h.sh_entsize = sizeof(Elf64_Sym); h.sh_info = first_global;
    uint32_t symtab = rel_add_section(&sections, &nsections, &capacity, h, symbols.p, NULL, 0);
    memset(&h, 0, sizeof h);
    h.sh_name = rel_string(&names, ".strtab"); h.sh_type = SHT_STRTAB;
    h.sh_size = strings.n; h.sh_addralign = 1;
    uint32_t strtab = rel_add_section(&sections, &nsections, &capacity, h, strings.p, NULL, 0);
    sections[symtab].header.sh_link = strtab;
    for (int i = 1; i < nsections; i++)
        if (sections[i].header.sh_type == SHT_RELA || sections[i].header.sh_type == SHT_GROUP)
            sections[i].header.sh_link = symtab;
    memset(&h, 0, sizeof h);
    h.sh_name = rel_string(&names, ".shstrtab"); h.sh_type = SHT_STRTAB;
    h.sh_size = names.n; h.sh_addralign = 1;
    uint32_t shstrtab = rel_add_section(&sections, &nsections, &capacity, h, names.p, NULL, 0);

    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64; eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT; eh.e_type = ET_REL; eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT; eh.e_ehsize = sizeof eh; eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = (uint16_t)nsections; eh.e_shstrndx = (uint16_t)shstrtab;
    buf_add(&file, &eh, sizeof eh);
    for (int i = 1; i < nsections; i++) {
        RelSection *s = &sections[i];
        rel_pad(&file, s->header.sh_addralign);
        s->header.sh_offset = file.n;
        if (s->header.sh_type != SHT_NOBITS)
            buf_add(&file, s->data, (size_t)s->header.sh_size);
    }
    rel_pad(&file, 8);
    eh.e_shoff = file.n;
    for (int i = 0; i < nsections; i++)
        buf_add(&file, &sections[i].header, sizeof(Elf64_Shdr));
    memcpy(file.p, &eh, sizeof eh);
    FILE *f = fopen(path, "wb");
    if (!f) die("cannot open %s for writing", path);
    if (fwrite(file.p, 1, file.n, f) != file.n || fclose(f) != 0)
        die("write error on %s", path);
    for (int i = 1; i < nsections; i++) free(sections[i].contents.p);
    free(sections); free(names.p); free(strings.p); free(symbols.p); free(file.p);
}

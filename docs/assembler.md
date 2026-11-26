# Crunch object assembler

`crunch-as` is an x86-64 assembler that produces ELF64 relocatable objects and
by default links them into an executable using the adjacent `crunch-ld`.
Use `-c` to assemble without linking.

```sh
build/crunch-as -nostdlib -o program input.s
build/crunch-as -c -o output.o input.s
```

The assembler accepts `-` or no input file to read standard input. Without
`-o`, linking produces `a.out`; `-c` produces one object per input in the
current directory, or `stdin.o` for standard input. Multiple inputs with
`-c -o` are assembled together into one object. The linker accepts `-nostdlib`
through the assembler; invoke `crunch-ld` separately for other linker options.
The compiler suite must use `-c` when invoking this version of `crunch-as`.

The experimental assembler builds the installed `libcrunch.a` and
`libcrunch.so.1` by default.
Configure with `--with-runtime-assembler=gnu` before running `make` and
`make install` to use GNU `as` for the runtime instead. The configured archiver
is still used. This does not change the driver's assembler or linker selection;
set those in `crunch.conf` separately.

Alternatively, `make crunch-native-runtime` builds the separate
`build/out/libcrunch-native.a` for comparison. That separate archive is not
installed or selected by the driver.

Source diagnostics identify the filename and line, using `<stdin>` for standard
input. Errors in macro or repetition bodies also show the expansion sites,
including nested expansions. The assembler recognizes preprocessor line markers
of the form `# line "filename"` (including GNU numeric flags), so diagnostics
from preprocessed `.S` files can identify included sources. Columns are not
tracked.

Assembler `.include "file"` supports nested includes, including within active
conditional blocks, macros and repetitions. Relative names are searched first
in the working directory, then in `-I` directories in order, as with GNU `as`;
they are not implicitly relative to the including file. Absolute names are
opened directly. The driver passes its `-I` directories to the assembler for
both `.s` and `.S` inputs. For `.S` files, these directories are also passed
to the preprocessor for `#include`. Included-file diagnostics retain their
file and line; nesting is limited to 64 levels.

Alternate macro mode (`.altmacro`) is rejected. `.exitm` is supported inside macros
and repetition blocks, but is rejected outside them. `.irpc` supports
unquoted, whitespace-free character lists of at most 256 characters;
quoted lists, embedded whitespace and comma-separated lists are rejected.
Macro parameters may be marked `:req`; missing or empty required arguments
are rejected. Double-quoted arguments and defaults are supported, including
commas and escaped characters; `.irp` values use the same quoting rules.
Unquoted whitespace and single-quoted macro arguments or `.irp` values,
defaults on required parameters, and other parameter qualifiers such as
`:vararg` are not supported. Substitution of a value containing `#` outside
a quoted string is also rejected.
`.if` and `.rept` can use previously defined absolute `.equ` and `.set`
constants, including active macro and repetition expansions. Unresolved
forward aliases are not available during preprocessing. Absolute `.equ` and
`.set` definitions may be reassigned; expressions using already-known
constants capture their values at the definition. Forward absolute `.equ` and
`.set` references can be resolved later for assembly, but not for earlier
`.if` or `.rept` directives. Forward section-relative aliases remain unsupported.
`.ifdef` and `.ifndef` test symbols defined earlier in the active source,
including labels, common symbols, section names and `.equ`/`.set` symbols.
Macro names and declarations such as `.globl` do not define symbols.
Conditional blocks can use multiple `.elseif` branches; expressions in
unselected later branches are not evaluated.

Immediate-to-memory `movb`, `movw`, `movl` and `movq` support numeric and
symbolic immediates. Numeric values must fit the destination width; `movq`
uses the instruction's sign-extended 32-bit immediate. Unsuffixed `mov`
defaults to 32 bits when its destination is memory.
Shift and rotate instructions accept an omitted count as an implicit count
of one; `cqto` is accepted as an alias for `cqo`.
`endbr64` is accepted for assembly generated with x86 control-flow protection.
An untyped `.note.gnu.property` section is emitted as `SHT_NOTE`, as with GNU
`as`.

Memory operands support 64-bit and 32-bit base/index/scale addressing,
including index-only and RIP- or EIP-relative forms. The 32-bit forms emit
an address-size prefix and use 32-bit effective addresses; base and index
registers must have matching widths. Malformed fields and unsupported
symbolic displacement expressions are rejected.

The assembler supports `movups` between XMM registers and memory, plus the
x87 and scalar SSE instructions used by the
Crunch power and real-formatting runtime helpers and generated scalar
conversions and arithmetic, as well as character
immediates, memory-source arithmetic, two-operand immediate `imul`, and
unsuffixed conditional moves. This is not a complete x87, SSE or GNU
assembler implementation.
For binary80 work it also accepts memory forms of `fldt`, `fstpt`, `flds`,
`fstps`, `fildl`, `fildll`, `fistpl`, `fistpll`, `fnstcw`, and `fldcw`;
implicit `fmulp`, `fsubrp`, `fdivrp`, and `fucomip`; and operand-free
`fchs`, `fabs`, `ftst`, and `fldz`. This does not yet enable source-level
`long double` code generation.

Direct branches to external or weak symbols and calls to global symbols use
PLT relocations for zero-addend expressions. Nonzero addends use PC-relative
relocations unless `@PLT` is explicit. Local same-section targets can be
resolved during assembly. Relaxation starts with short jumps and widens them
until all displacements fit the resulting layout, including alignment padding.
It can conservatively retain a near jump even when another layout could use a
short one. The `loop`, `loope`/`loopz`, and `loopne`/`loopnz` instructions
have only an 8-bit displacement: same-section local targets are resolved
and range-checked after relaxation, while other targets retain PC8
relocations for the linker.

## Shared-library interoperability

With `-c`, `crunch-as` produces relocatable objects, not shared libraries. Hand-written
position-independent assembly can be linked into a `.so` with GNU `ld`. For
example:

```asm
.data
.globl shared_value
.type shared_value,@object
shared_value:
    .long 35
.size shared_value,.-shared_value

.globl hidden_value
.hidden hidden_value
.type hidden_value,@object
hidden_value:
    .long 7
.size hidden_value,.-hidden_value

.text
.globl answer
.type answer,@function
answer:
    movq shared_value@GOTPCREL(%rip), %rax
    movl (%rax), %eax
    addl hidden_value(%rip), %eax
    ret
.size answer,.-answer
.section .note.GNU-stack,"",@progbits
```

Save this as `answer.s`, then build and load it with:

```sh
crunch-as -c -o answer.o answer.s
ld -shared -z text -o libanswer.so answer.o
python3 -c 'import ctypes; print(ctypes.CDLL("./libanswer.so").answer())'
```

The program prints `42`. The `-z text` option makes GNU `ld` reject dynamic
relocations in read-only sections; it does not make non-PIC assembly
position-independent.

The shared-library tests cover GOT-relative loads and stores of default-visible
global data, `@PLT` calls to default-visible functions, and RIP-relative data
access and calls to hidden definitions. They also exercise symbols resolved
from the loading executable, `dlopen`/`dlsym`, and function and data
interposition with `LD_PRELOAD`. Default-visible data and functions can be
preempted; hidden definitions are not exported or preempted. The assembly
author must choose appropriate PIC relocations and follow the platform ABI.

This is a tested subset, not a claim of complete PIC, TLS, or GNU assembler
compatibility. `crunch-ld -shared` supports GOT and PLT references for this
PIC subset, initialized 64-bit pointers in writable data, and local and hidden
PC-relative references. It does not
currently accept GNU `ld`'s `-z text` option. It can also record shared-library
inputs as dependencies of a shared output. The Crunch driver does not build
shared libraries or perform dynamic links, and Crunch-generated assembly is
not guaranteed to be PIC. See
[`crunch-ld` shared-object limitations](../src/linker/README.md#shared-objects).

Custom `.section` directives support mergeable constants (`M`) and strings
(`MS`) with a positive entry size up to 1 MiB. The entry size is preserved in
ELF, and mergeable section tails are padded according to that size. An
existing ungrouped custom section can be selected again by name. The `R` flag
marks a section with `SHF_GNU_RETAIN`, protecting it from section garbage
collection. The `G` flag
supports section groups using `.section name,"flagsG",@type,signature` and
an optional `,comdat`; for mergeable sections the entry size comes before the
signature. Group members and their relocation sections are emitted with ELF
group metadata. Grouped sections must be reselected with their full
attributes; conflicting COMDAT declarations for one signature and unsupported
extra attributes are rejected.
The `.text`, `.data`, `.bss`, `.rodata`, `.tdata` and `.tbss` directives
accept an omitted subsection or an absolute expression equal to zero;
nonzero subsections are rejected instead of being emitted in source order.

`.ascii`, `.asciz` and `.string` support comma-separated strings and adjacent quoted
fragments, including GNU-style hexadecimal, numeric and control escapes.
Each `.asciz` or `.string` string group receives a NUL terminator. Unterminated strings
and trailing non-string text are rejected. In macro and repetition bodies,
named parameter substitutions still apply inside quoted strings; other
string escapes are preserved for decoding.

`.file "filename"` records a local absolute ELF `STT_FILE` symbol, including
for repeated filenames. GNU-style escapes are decoded. Numbered `.file`
directives for DWARF line tables are not supported and are rejected; the
assembler does not generate DWARF line information.

Symbolic operands support a symbol with an optional signed integer addend;
unsupported combinations are rejected rather than emitted as symbol names.
This is not a complete GNU symbolic expression grammar.

Binding and visibility directives accept comma-separated symbol lists.
As with GNU `as`, `.extern` does not change binding; undefined references
are resolved by the linker. Quoted symbol names and the `.symver` `@@@`
shorthand are not supported.

`.align`, `.balign`, and `.p2align` track the required ELF alignment for
every section, including when a maximum-skip limit suppresses padding.
Alignments must be powers of two and at most 1 MiB. Omitted fill in an
executable section uses single-byte NOPs; other sections use zero fill. An
empty second operand followed by no third operand explicitly selects zero
fill.

`.comm` emits ELF common symbols, or allocates `.bss` storage after a
`.local` declaration. Repeated global commons retain the first nonzero size
and use the latest alignment; differing sizes produce a warning. `.lcomm`
allocates `.bss` storage and also accepts an explicit alignment as a Crunch
extension. Common alignments must be powers of two and at most 1 MiB, and
local allocations are subject to the 1 MiB section limit. Converting an
already declared global common to local storage, redefining a local common
with `.set`, and using a local common as a `.set` alias target or in a
`.-symbol` size expression are not supported.

Section-relative `.set` aliases support already-defined section symbols with a
constant offset; forward aliases and negative or overflowing section offsets
are rejected. Zero-valued data is supported in NOBITS sections; relocations
and deferred symbol differences there are not supported. Explicit
`@init_array` and `@fini_array` sections are emitted as ELF initialization and
finalization arrays. When the type is omitted, `.init_array`, `.fini_array`,
and their priority-suffixed names select the corresponding array type.

`make check` assembles the runtime sources and compares GNU and experimental
assembler/runtime combinations on a compiler-generated execution corpus. It
also compares common instruction encodings and relocations against GNU `as`
across register widths, addressing modes, and immediate boundaries. The
experimental assembler remains incomplete; these checks are not a claim of full
compatibility.
See [assembler-todo.md](assembler-todo.md) for remaining work.

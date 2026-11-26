# crunch-ld: An Experimental Linker for x86-64 Linux ELF

This linker is experimental and is not a complete replacement for GNU ld.
Static executable links support `R_X86_64_GOTPCREL`,
`R_X86_64_GOTPCRELX`, and `R_X86_64_REX_GOTPCRELX` without instruction
relaxation. Other GOT relocations and TLS relocations remain unsupported.
GOT relocations in experimental PIE output without a dynamic loader are rejected.
Relocatable linking (`-r`) preserves relocations for a later linker to resolve.
Standalone executable links automatically append `libcrunch.a`, or
`libcrunch.so` for dynamic executables, and shared links append
`libcrunch.so`. The linker searches `-L` directories followed by
`library_path` entries from `crunch.conf`, checking each directory and its
`crunch` subdirectory, then the configured installation runtime directory.
Repeated configuration entries are searched in order, and `CRUNCH_CONF_FILE`
overrides the configuration filename. If the runtime is not found, linking
continues without it. An explicit runtime input (including `-lcrunch` and
`-l:libcrunch.so`) suppresses automatic selection; `-nostdlib` and
`-nodefaultlibs` disable it, and relocatable links never add a runtime.
Dynamic executables also add `libcrunch-fallback.a` from the runtime directory
when available. When automatically adding a shared runtime, the linker appends
its absolute directory to `DT_RUNPATH` after any explicit `-rpath` entries.
This binds the output to that directory. Relative library paths are resolved at
link time; directories containing `:` or `$` cannot be safely embedded and
are rejected. Explicit runtime inputs do not add a RUNPATH automatically.
The Crunch driver passes `-nostdlib` and
its own runtime explicitly for executable links.

For static executable links, non-ELF inputs may also be treated as restricted
linker scripts when they contain a recognized script construct and no NUL
bytes. This detection does not validate the full script syntax. Explicit
scripts can be supplied with `-T`.

`-Wabi-mismatch` compares available Crunch ABI records for declarations
and their selected definitions in relocatable objects, including extracted
archive members, and visible candidate definitions in direct shared inputs.
It reports possible differences without failing the link.
Records may describe unused declarations or different IR types with the same
calling convention. Missing or incomplete metadata, assembly, indirect
dependencies, and later-loaded libraries are not verified; runtime symbol
interposition is not fully modeled. No warning is not evidence of compatibility.
Warnings are based on selected inputs before section garbage collection.

`crunch-ld` is an independent ELF linker designed for x86-64 Linux. It is
available as an opt-in alternative to GNU ld for Crunch links.

For dynamic executables and shared objects, a canonical GNU x86 CET property
note containing only IBT and SHSTK feature bits is accepted but not retained.
The linker warns when those bits are present: the output does not advertise
these protections and must not be assumed to have CET enforcement. Other GNU
property notes are rejected. Relocatable linking preserves the input notes.

## Shared objects

`crunch-ld -shared -o library.so input.o ...` produces a loadable ELF64 shared
object for a restricted position-independent subset. Defined global and weak
symbols with default or protected visibility are exported; hidden and internal
symbols are not. PC-relative relocations to local, hidden or protected
definitions are resolved statically. Static archives can supply definitions
using the usual archive order rules. The result can be loaded by the system
dynamic loader, including through `dlopen`.

PIC may access undefined or default-visible data using `@GOTPCREL` and call
undefined or default-visible functions using `@PLT`. Dynamic GOT entries use
`R_X86_64_GLOB_DAT` for preemptible and undefined symbols and
`R_X86_64_RELATIVE` for local, hidden, and protected definitions. PLT entries
are eagerly resolved through the GOT, including when a library is opened with
lazy binding. Undefined weak GOT references can resolve to zero; undefined
strong references must be supplied by the dynamic loader's symbol scope.
Default-visible definitions can be interposed.

Initialized 64-bit pointers in writable sections support `R_X86_64_64`
relocations, including symbol addends. Local, hidden, and protected targets
use `R_X86_64_RELATIVE`; undefined or default-visible targets use dynamic
`R_X86_64_64` relocations and can be interposed. Undefined weak targets
resolve to zero before the addend is applied. These relocations may point to
functions or data. By default, input `.data.rel.ro` sections are merged into
writable data and the output does not provide GNU RELRO protection.

Use `-z relro` (or `-zrelro`) with `-shared` or `-dynamic` to emit a
`PT_GNU_RELRO` segment. It contains `.dynamic`, the GOT, initialization and
finalization arrays, and writable input `.data.rel.ro` and `.data.rel.ro.*`
sections. The latter must be allocated, writable, non-executable `SHT_PROGBITS`
sections. Ordinary data, BSS, and the Crunch-specific runtime registries remain
outside the protected pages. A compatible loader makes RELRO pages read-only
after applying relocations and before constructors run; attempts to modify
them afterwards can fault. The linker resolves GOT and PLT entries eagerly
regardless of this option. Other `-z` options are unsupported, and `-z relro`
is rejected for static and relocatable output.

Shared outputs support `.init_array` and `.fini_array` constructors and
destructors. Numbered sections such as `.init_array.00101` are ordered by
decimal priority from 0 to 65535; unnumbered sections follow numbered
priority-65535 sections, and equal priorities retain input order. The loader
runs initializers in array order and finalizers in reverse order when the
library is unloaded or the process exits. Array sections must be allocated,
writable, aligned no more than eight bytes, and contain one `R_X86_64_64`
relocation for each eight-byte entry. Entries must resolve to callable
functions; an unresolved weak or null target is not a safe callback. Symbols
in an empty array are supported when an array of the same kind has entries;
symbols or references to an entirely empty output array are rejected.

ELF64 x86-64 shared objects may be supplied as inputs. Each distinct
dependency name is recorded in input order as a `DT_NEEDED` entry, whether or
not its symbols are used. The input's `DT_SONAME` is preferred; without one,
a direct input uses the path supplied on the command line, while a library
found with `-l` uses its basename. Set the output's SONAME with
`-soname NAME`, `--soname=NAME`, or `-h NAME`. For `-shared`, `-lfoo` searches
each library directory for `libfoo.so` before `libfoo.a`; `-l:FILE` searches
for exactly `FILE`.

An earlier shared input's visible definitions prevent later archives from
being extracted for those symbols, and can satisfy `--require-defined`.
With `--no-undefined`, a shared link rejects strong undefined symbols
referenced by input relocations unless provided by a direct input; unresolved
weak symbols remain permitted.
This link-time check does not follow the shared input's own dependencies; the
runtime loader handles those dependencies. Shared inputs must include section
headers and a dynamic symbol table consistent with their dynamic metadata.
Hidden or non-default symbol versions are not used for archive selection;
full symbol-version handling is not supported.

`--forbid-defined=SYMBOL` rejects a definition in output objects, including
weak and common definitions. `--unique-shared-symbol=SYMBOL` rejects a symbol
defined by multiple distinct direct shared inputs; transitive dependencies
are not checked. Both options are repeatable.

For shared objects and dynamic executables, `-rpath PATH` or `--rpath PATH`
embeds a `DT_RUNPATH` search path; the `-rpath=PATH` and `--rpath=PATH` forms
are also accepted. Repeated options are joined with colons in command-line
order. The path is passed unchanged to the loader, so quote expressions such
as `'$ORIGIN/../lib'` to prevent shell expansion. On glibc, `$ORIGIN` refers
to the directory of the object containing the RUNPATH, and RUNPATH is used
only for that object's direct dependencies, not their children. A shared
dependency can have its own RUNPATH. Empty arguments are rejected, but empty
colon-separated components may search the current working directory and
should be avoided. Runtime search paths do not change `-L` or `-l` link-time
search. Without this option, RUNPATH is emitted only for an automatically
selected shared Crunch runtime. Other dependencies may need `-rpath` or
separate loader configuration such as `LD_LIBRARY_PATH`. Legacy `DT_RPATH`
is not emitted.

Direct PC-relative references to undefined or preemptible symbols,
absolute relocations other than 64-bit pointers in writable sections,
nonstandard PLT addends, TLS, unwind sections, legacy `.init`, `.fini`,
`.ctors`, `.dtors`, and preinitialization sections are rejected. Linker scripts, PIE, garbage
collection, interpreter options, and entry selection cannot be combined with
`-shared`. Synthetic linker-defined symbols such as `_end` are not supported
in shared output. The driver does not create shared libraries, and
Crunch-generated assembly is not guaranteed to be PIC.

## Dynamic executables

`crunch-ld -dynamic -o program start.o library.so` produces a fixed-address
ELF64 `ET_EXEC` executable using the interpreter selected by configure.
`-I PATH` or `--dynamic-linker PATH` also selects dynamic executable mode and
overrides the interpreter; PATH must be absolute. An entry symbol (normally
`_start`, or one selected with `-e`) must be defined by an input object.
Add `-pie` or `--pie` to `-dynamic` to produce a position-independent
`ET_DYN` executable with `DF_1_PIE`; the default dynamic executable remains
fixed-address. Dynamic mode adds the shared runtime as described above.

Dynamic executables accept the shared inputs, dependency naming and library
search rules described above. Their default-visible definitions are exported
to dependencies, and references to definitions in the executable are bound
locally. Calls to external functions use `R_X86_64_PLT32`; external data can
be accessed through GOTPCREL relocations or 64-bit pointers in writable
sections. GOT and PLT references are resolved eagerly, undefined weak GOT or
pointer references may resolve to zero, and unresolved strong references must
be supplied by a direct input shared object. Direct PC-relative or narrower
absolute references to shared definitions and read-only dynamic relocations
are rejected. There are no copy relocations or dynamic text relocations.
Local relocations supported by the static linker remain available within this
subset. Use the `-rpath` option described above or configure the loader
search path separately, e.g. with `LD_LIBRARY_PATH`.

Dynamic PIE requires position-independent inputs. Image-relative 64-bit
pointers in writable sections are relocated by the loader, but narrow
absolute image references, PC-relative references to absolute symbols, and
dynamic relocations in read-only sections are rejected. GOT references to
absolute symbols and most synthetic linker-defined symbols are unsupported.
No copy relocations or text relocations are generated.

The loader runs shared-library constructors before entering the executable.
For a nonempty executable `.init_array`, `crunch-ld` emits a startup trampoline
that calls its entries before transferring control to the selected entry point.
It preserves the original process-entry registers and stack, and passes
`argc`, `argv`, and `envp` to each constructor with the x86-64 ABI's stack
alignment. Numbered entries are ordered by priority as for shared objects;
equal priorities retain input order. The executable's entry point must not run
the same array again. This startup assumes an interpreter that leaves the main
executable's `.init_array` to its entry point, as the default glibc loader does.
Array entries have the same relocation, alignment, and callable-target
restrictions as shared initialization arrays. The executable also contains
`DT_INIT_ARRAY` and `DT_INIT_ARRAYSZ` metadata.

Crunch-generated module wrappers are guarded against repeated execution, so
the generated entry point's registry traversal does not initialize them again.
Executable `.fini_array` sections follow the same layout and priority rules;
managed shutdown runs their entries in reverse order. The output includes
`DT_FINI_ARRAY` and `DT_FINI_ARRAYSZ` and exports the reserved function
`void __crunch_run_finalizers(void)` for a custom entry point to call before
exiting. The helper is present even with no finalizers. A guard prevents
reentrant or repeated calls from executing entries again; concurrent callers
do not wait for an in-progress traversal. The callbacks must return normally.

Newly compiled Crunch `_start` code calls this hook when `main` returns, and
the current static and shared runtime implementations of `exit()` call it
before the exit syscall. Old object files or runtimes must be rebuilt to use
the hook. Custom entry points must call the hook themselves. A direct exit
syscall bypasses executable finalizers, and all these exit paths bypass
shared-library finalizers.
Normal loader shutdown and standard libc startup are not supported; directly
calling the loader's finalization function is not guaranteed to work in a
program without libc.
Legacy constructor sections, TLS, unwind sections, and preinitialization
sections are rejected. The executable's Crunch-specific registry bounds are
exported when present so the shared runtime's initializer helper can resolve
them. Linker scripts, garbage collection, custom image bases, `-crt0`,
and forced undefined symbols are not supported in this mode.

For example, after building, an otherwise supported Crunch source can be
linked explicitly against the shared runtime:

```sh
build/out/crunch -c program.bc -o program.o
build/out/crunch-ld -dynamic -o program program.o build/out/libcrunch.so
LD_LIBRARY_PATH="$PWD/build/out" ./program
```

Alternatively, `build/out/crunch program.bc -o program` defaults to
dynamic mode and the shared runtime, with the runtime directory embedded as
RUNPATH. The driver also accepts repeatable `--rpath` / `-rpath` paths before
that built-in runtime directory, for example `--rpath '$ORIGIN/../lib'`;
see `docs/configure.md` for packaging details. `--static` selects static
linking. `crunch -pie` opts into dynamic PIE. `crunch -z relro` opts
into the same RELRO protection described above, and is only valid for dynamic
executable links. Crunch's generated `_start` uses a
raw exit syscall and therefore does not run shared-library finalizers.

For example, save this as `answer.s`:

```asm
.text
.globl answer
.type answer,@function
answer:
    movl $42, %eax
    ret
.section .note.GNU-stack,"",@progbits
```

```sh
crunch-as -o answer.o answer.s
crunch-ld -shared -o libanswer.so answer.o
python3 -c 'import ctypes; print(ctypes.CDLL("./libanswer.so").answer())'
```

The program prints `42`.

Relocatable links preserve input sections (including debug sections), local and
global symbols, common symbols, and unresolved references. They extract needed
archive members but do not add the runtime automatically. Section groups are
preserved, and duplicate COMDAT groups are selected by signature, retaining
the first. References from live sections to discarded local symbols are
rejected, except that debug relocations are neutralized. When duplicate
COMDAT code has `.eh_frame` entries, the linker removes its FDEs; filtering
requires 32-bit-length frame records and rejects references it cannot safely
associate with a discarded FDE. `SHT_REL`, unsupported section
types or symbol bindings, and multiple relocation sections for one target are
rejected. Linker scripts,
entry selection, stripping, garbage collection, map output, PIE, interpreter,
and `crt0` options are not supported with `-r`. There is no GNU ld fallback.

Objects and archives are processed in command-line order. An archive extracts
members for strong references already encountered or strong non-function
definitions that replace existing common symbols. Weak definitions and other
common definitions alone do not trigger extraction. Each archive rescans its
own members until no more are needed; it is not revisited for later inputs
unless listed again. Use `--start-group` and `--end-group` (or `-(` and `-)`) to rescan
archives across a group for circular dependencies. These rules also apply to
relocatable links, which retain unresolved references for a later link.

## Features

- **ELF64 x86-64 Support**: Selected relocations including `R_X86_64_PC32`,
  `R_X86_64_32S`, `R_X86_64_64`, and the three GOTPCREL variants, with range checks.
- **Garbage Collection**: `--gc-sections` to strip unreferenced code and data sections.
- **Static Library Archives**: Full parsing and member extraction for standard Unix `.a` archives.
- **Linker Scripts**: Custom script support for `ENTRY`, `MEMORY` block definitions, symbol assignments, and `ALIGN()` expressions.
- **Dynamic Executables**: Restricted dynamic links with `-dynamic` or
  `-I` / `--dynamic-linker`; the Crunch driver defaults to dynamic executables.
  Add `-pie` for a position-independent dynamic executable; the default is
  fixed-address. PIE without dynamic linking remains experimental.
- **Detailed Map Files**: `-M` / `-Map` output with memory configuration utilization percentages and section/symbol cross-references.
- **Defensive Hardening**: Robust boundary checks against truncated ELF files, section header table overflows, and safe memory allocations.

## Building & Testing

From the Crunch project root, run `./configure`, `make`, and `make check`.
The linker is built as `build/out/crunch-ld` and installed alongside `crunch`.
See `docs/configure.md` for driver selection and limitations.

## Usage

```bash
build/out/crunch-ld -r -o combined.o file1.o file2.o
build/out/crunch-ld -nostdlib -o output_prog start.o combined.o
build/out/crunch-ld -shared -o libexample.so example.o
```

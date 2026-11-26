The most valuable next improvements to crunch-as would be in correctness, GNU assembler compatibility, and diagnostics rather than simply adding more instructions.

Status: the missing `.shstrtab` terminator has been fixed, and `make check`
now runs ELF, linker, execution, and initial GNU `as` comparison
checks. Further ELF and instruction coverage is still needed. GNU `as`
resolves numeric local-label references across input files in a single
invocation, so confirm intended compatibility with tests before changing that
behavior.

Source diagnostics now retain filenames and lines through macro and repetition
expansion and deferred fixups, including preprocessor line markers. Assembler
`.include` is supported; columns remain unsupported. The priorities below are
historical suggestions, not a list of completed work.

Here is the order I'd recommend.
Recommended priorities
Priority	Improvement	Why it matters
1	Per-file source tracking	Preserve filename, line and column through preprocessing, macros and multi-file assembly.
2	Numeric local-label scoping	Ensure 1f and 1b references cannot accidentally cross input-file boundaries.
3	ELF correctness	Fix the string-table warning from ld -r and validate generated objects with readelf and linkers.
4	Expression engine	Support a more complete GNU-style expression grammar, precedence, symbol differences and relocatable expressions.
5	Instruction encoding validation	Improve operand checking, immediate ranges, REX handling, prefixes and invalid instruction diagnostics.
6	GNU assembler compatibility tests	Compare output behavior against GNU as for supported syntax and instructions.
7	More directives	Add useful directives such as .type, .size, .hidden, .weak, .comm, .org, .fill, .incbin and .include.
8	Macro compatibility	Implement .altmacro substitution and improve macro expansion diagnostics.

What I would tackle first
1. Reliable source locations
The recent line/column improvement is a good start, but source locations should survive every transformation:
- Multiple input files.
- Macro expansion and nested macros.
- Repeated blocks (.rept, .irp).
- Conditional assembly.
- Included files.
An error should identify the actual source location and, when applicable, the macro expansion site.
2. ELF object-file correctness
This is particularly important because producing valid ELF files is one of the assembler's central responsibilities.

I would investigate the existing ld -r warning:
string table [8] is corrupt


Then validate:
- Section and symbol string tables.
- Symbol indices and binding.
- Relocation offsets and types.
- Section alignment and flags.
- .symtab, .strtab and .shstrtab.
- Undefined and weak symbols.
- Linking multiple generated objects.
3. Automated instruction compatibility tests
Build a test suite that assembles the same supported instruction snippets with crunch-as and GNU as, then compares:
- Machine-code bytes.
- Relocation types.
- Relocation offsets.
- Symbol information.
This will catch encoding bugs much more effectively than adding instructions without systematic validation.
Suggested development sequence
1. Source tracking and diagnostics
   
   Make filename, line and column metadata survive all preprocessing stages.
2. Numeric labels and multi-file correctness
   
   Give each input file an independent numeric-label scope.
3. ELF validation and linker compatibility
   
   Fix the string-table issue and add object-file validation tests.
4. Expression and relocation improvements
   
   Expand expression support and test complex relocatable expressions.
5. GNU compatibility and regression suite
   
   Systematically compare supported features against GNU as.
My recommendation: Start with ELF correctness, while also fixing per-file source tracking and numeric-label scoping. These address foundational correctness issues before expanding the instruction set.

I would keep the project as a standalone C assembler that writes ELF64 objects directly—not turn it into a wrapper around GNU as.

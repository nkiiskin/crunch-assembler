# Crunch assembler and linker

![Crunchie, the Crunch mascot](Crunchie.jpg)

Standalone extraction of the `crunch-as` x86-64 ELF assembler
and `crunch-ld` linker from the Crunch 0.9.0 C-compiler suite. Linux x86-64 and a C11 compiler are
required. GNU make and Python 3 are needed for the build and tests. Crunch-as comes with it's
own crunch-as(1) man page.

```sh
make
make check
sudo make install PREFIX=/opt

# Assemble and link:
crunch-as -nostdlib -o program main.s tools.s
# Assemble only:
crunch-as -c -o program.o *.s
# Assemble from stdin:
cat source.s | crunch-as -o program
```

`make check` also needs GNU binutils and a system C compiler. Four tests
requiring the full Crunch compiler and runtime are skipped in this extraction.
The GitHub Actions workflow builds and tests the standalone tools and their
staged installation on Ubuntu 24.04 when this project is hosted on GitHub.
The installed tools default to `/usr/local/bin`; use `PREFIX=/path` and
`DESTDIR=/staging` to change the installation location. Installing over a
Crunch suite installation replaces its copies of the same tools.
The standalone assembler's default linking behavior differs from older suite
versions, so install it separately unless the suite supports `-c`.

The linker embeds an automatically detected Linux ELF interpreter for dynamic
links. Override it at build time with
`make DYNAMIC_LINKER=/absolute/path/to/ld-linux-x86-64.so.2`.
The linker retains Crunch's optional runtime auto-discovery; use `-nostdlib`
to disable it when linking a standalone assembly program.

Example:

```sh
build/crunch-as -nostdlib -o program program.s
./program
```

By default, `crunch-as` assembles and invokes the `crunch-ld` installed
beside it, writing `a.out` unless `-o` is given. Use `-c` to produce
relocatable objects without linking:

```sh
build/crunch-as -c -o program.o program.s
build/crunch-ld -nostdlib -o program program.o
```

Without `-o`, `-c` writes one `.o` file per input in the current directory.
With `-o`, multiple source inputs are assembled into one object. Input defaults
to standard input; `-c` names that object `stdin.o` unless `-o` is supplied.
The old `crunch-as input.s output.o` shorthand is no longer supported; use
`-c -o output.o input.s`. For linker options other than `-nostdlib`, assemble
with `-c` and invoke `crunch-ld` separately.

See [assembler documentation](docs/assembler.md) and
[linker documentation](src/linker/README.md) for supported features and
limitations. Some passages describe integration with the full compiler suite,
which is not included in this standalone extraction.

Distributed under GNU GPL version 2; see [Copying](Copying).

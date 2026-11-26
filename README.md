# Crunch assembler and linker

Standalone extraction of the experimental `crunch-as` x86-64 ELF assembler
and `crunch-ld` linker from Crunch 0.9.0. Linux x86-64 and a C11 compiler are
required. GNU make and Python 3 are needed for the build and tests.

```sh
make
make check
sudo make install
```

`make check` also needs GNU binutils and a system C compiler. Four tests
requiring the full Crunch compiler and runtime are skipped in this extraction.
The GitHub Actions workflow builds and tests the standalone tools and their
staged installation on Ubuntu 24.04 when this project is hosted on GitHub.
The installed tools default to `/usr/local/bin`; use `PREFIX=/path` and
`DESTDIR=/staging` to change the installation location. Installing over a
Crunch suite installation replaces its copies of the same tools.

The linker embeds an automatically detected Linux ELF interpreter for dynamic
links. Override it at build time with
`make DYNAMIC_LINKER=/absolute/path/to/ld-linux-x86-64.so.2`.
The linker retains Crunch's optional runtime auto-discovery; use `-nostdlib`
to disable it when linking a standalone assembly program.

Example:

```sh
build/crunch-as -o program.o program.s
build/crunch-ld -nostdlib -o program program.o
./program
```

See [assembler documentation](docs/assembler.md) and
[linker documentation](src/linker/README.md) for supported features and
limitations. Some passages describe integration with the full compiler suite,
which is not included in this standalone extraction.

Distributed under GNU GPL version 2; see [Copying](Copying).

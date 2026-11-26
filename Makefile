CC ?= cc
PYTHON ?= python3
CFLAGS ?= -O2
CPPFLAGS ?=
PREFIX ?= /usr/local
DESTDIR ?=
DYNAMIC_LINKER ?= $(firstword $(wildcard /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2))

TOOLS = build/crunch-as build/crunch-ld

.PHONY: all check install uninstall clean FORCE
all: $(TOOLS)

build:
	mkdir -p $@

build/crunch-linker-config.h: FORCE | build
	@case '$(DYNAMIC_LINKER)' in ''|*[!a-zA-Z0-9_./+-]*|[!/]* ) \
	  echo "Set DYNAMIC_LINKER to an absolute ELF interpreter path" >&2; exit 1;; esac
	@printf '%s\n' '#ifndef CRUNCH_LINKER_CONFIG_H' '#define CRUNCH_LINKER_CONFIG_H' \
	  '#define CRUNCH_DYNAMIC_LINKER "$(DYNAMIC_LINKER)"' '#endif' > $@.tmp
	@cmp -s $@.tmp $@ && rm -f $@.tmp || mv -f $@.tmp $@

build/crunch-as: src/driver/crunch_as_main.c src/assembler/assembler.c include/assembler/assembler.h include/common/compiler.h | build
	$(CC) $(CPPFLAGS) -iquote include $(CFLAGS) -std=c11 -Wall -Wextra -Wpedantic $(filter %.c,$^) -o $@

build/crunch-ld: src/linker/crunch-ld.c src/linker/relocatable.inc include/version.h build/crunch-linker-config.h | build
	$(CC) $(CPPFLAGS) -iquote include -iquote build $(CFLAGS) -std=c11 -Wall -Wextra -Wpedantic $< -o $@

check: all
	$(PYTHON) tests/fixtures/assembler/tests.py build/crunch-as
	$(PYTHON) tests/test_linker.py

install: all
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(PREFIX)/share/man/man1" "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/docs" "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/src/linker"
	install -m 755 $(TOOLS) "$(DESTDIR)$(PREFIX)/bin/"
	install -m 644 src/assembler/crunch-as.1 src/linker/crunch-ld.1 "$(DESTDIR)$(PREFIX)/share/man/man1/"
	install -m 644 README.md Copying "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/"
	install -m 644 docs/assembler.md "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/docs/"
	install -m 644 src/linker/README.md "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/src/linker/"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/crunch-as" "$(DESTDIR)$(PREFIX)/bin/crunch-ld"
	rm -f "$(DESTDIR)$(PREFIX)/share/man/man1/crunch-as.1" "$(DESTDIR)$(PREFIX)/share/man/man1/crunch-ld.1"
	rm -f "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/README.md" "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/Copying"
	rm -f "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/docs/assembler.md" "$(DESTDIR)$(PREFIX)/share/doc/crunch-assembler/src/linker/README.md"

clean:
	rm -f $(TOOLS) build/crunch-linker-config.h build/crunch-linker-config.h.tmp

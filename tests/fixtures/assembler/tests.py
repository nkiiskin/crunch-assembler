#!/usr/bin/env python3
"""ELF and GNU assembler compatibility checks for crunch-as."""

import os
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest


ASSEMBLER = pathlib.Path(sys.argv.pop(1)).resolve()
ROOT = pathlib.Path(__file__).resolve().parents[3]


def command(*args):
    """Run a tool and report its output if it fails."""
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stderr}")
    return result


def section(data, index):
    """Return one ELF64 section header."""
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size = struct.unpack_from("<H", data, 58)[0]
    return struct.unpack_from("<IIQQQQIIQQ", data, section_offset + index * entry_size)


def named_section(obj, name):
    """Return a named ELF section header."""
    data = obj.read_bytes()
    names = string_table(data, section(data, struct.unpack_from("<H", data, 62)[0]))
    count = struct.unpack_from("<H", data, 60)[0]
    for index in range(count):
        header = section(data, index)
        start = header[0]
        if names[start:names.index(b"\0", start)].decode() == name:
            return header
    raise AssertionError(f"{obj}: missing {name}")


def string_table(data, header):
    """Return an ELF section's bytes and check its required NUL boundaries."""
    offset, size = header[4:6]
    table = data[offset:offset + size]
    if len(table) != size or not table or table[0] != 0 or table[-1] != 0:
        raise AssertionError("invalid ELF string table")
    return table


def symbol_section(obj, index):
    """Resolve a readelf symbol section index to its name."""
    if not index.isdecimal():
        return index
    data = obj.read_bytes()
    shstr_index = struct.unpack_from("<H", data, 62)[0]
    names = string_table(data, section(data, shstr_index))
    name_offset = section(data, int(index))[0]
    return names[name_offset:names.index(b"\0", name_offset)].decode()


def symbol_records(obj):
    """Return ELF symbol metadata indexed by symbol name."""
    records = {}
    pattern = re.compile(
        r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s+(\S+)\s*$"
    )
    for line in command("readelf", "-sW", obj).stdout.splitlines():
        match = pattern.match(line)
        if match:
            value, size, kind, bind, visibility, index, name = match.groups()
            records[name] = (int(value, 16), int(size), kind, bind, visibility,
                             symbol_section(obj, index))
    return records


def relocations(obj):
    """Extract relocation offset, type, symbol and addend from GNU readelf."""
    result = command("readelf", "-rW", obj)
    pattern = re.compile(
        r"^\s*([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\S+)\s+"
        r"[0-9a-f]+\s+(\S+)(?:\s+([+-])\s+([0-9a-f]+))?\s*$"
    )
    entries = []
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if match:
            offset, kind, symbol, sign, addend = match.groups()
            value = int(addend, 16) if addend else 0
            entries.append((int(offset, 16), kind, symbol, -value if sign == "-" else value))
    return entries


def instruction_records(obj, count):
    """Extract individually labelled instruction bytes and relative relocations."""
    data = obj.read_bytes()
    shstr_index = struct.unpack_from("<H", data, 62)[0]
    names = string_table(data, section(data, shstr_index))
    count_sections = struct.unpack_from("<H", data, 60)[0]
    text = None
    for index in range(count_sections):
        header = section(data, index)
        start = header[0]
        if names[start:names.index(b"\0", start)] == b".text":
            text = data[header[4]:header[4] + header[5]]
            break
    if text is None:
        raise AssertionError(f"{obj}: missing .text")
    symbols = command("readelf", "-sW", obj).stdout
    offsets = {}
    for value, name in re.findall(r"^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(case\d+)$",
                                  symbols, re.MULTILINE):
        offsets[name] = int(value, 16)
    if len(offsets) != count + 1:
        raise AssertionError(f"{obj}: expected {count + 1} case labels, found {len(offsets)}")
    entries = relocations(obj)
    records = []
    for index in range(count):
        start, end = offsets[f"case{index:04d}"], offsets[f"case{index + 1:04d}"]
        refs = [(offset - start, kind, symbol, addend)
                for offset, kind, symbol, addend in entries if start <= offset < end]
        records.append((text[start:end], refs))
    return records


class AssemblerTests(unittest.TestCase):
    """Exercise independently assembled and linked ELF objects."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="crunch-as-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name)

    def assemble(self, source, name, assembler=ASSEMBLER):
        """Assemble source text using either crunch-as or GNU as."""
        src, obj = self.path / f"{name}.s", self.path / f"{name}.o"
        src.write_text(source)
        command(assembler, "-o", obj, src)
        return obj

    def diagnostic(self, source):
        """Return the diagnostic for a rejected standard-input source."""
        result = subprocess.run(
            [str(ASSEMBLER), "-o", str(self.path / "failed.o")],
            input=source, capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)
        return result.stderr

    def test_endbr64_encoding(self):
        source = ".text\nendbr64\nret\n"
        ours = self.assemble(source, "endbr64-ours")
        gnu = self.assemble(source, "endbr64-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.diagnostic(".text\nendbr64 %rax\n")

    def test_gnu_property_note_type(self):
        source = '.section .note.gnu.property,"a"\n.p2align 3\n.long 4,16,5\n'
        ours = self.assemble(source, "property-ours")
        gnu = self.assemble(source, "property-gnu", "as")
        self.assertEqual(named_section(ours, ".note.gnu.property")[1],
                         named_section(gnu, ".note.gnu.property")[1])

    def test_movups_register_and_memory_encodings(self):
        source = (".text\nmovups %xmm0, %xmm15\nmovups %xmm14, %xmm1\n"
                  "movups -32(%r12,%r9,4), %xmm14\n"
                  "movups %xmm15, 128(%r13,%r8,2)\n")
        ours = self.assemble(source, "movups-ours")
        gnu = self.assemble(source, "movups-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        for instruction in ("movups %rax, %xmm0", "movups %xmm0, %rax",
                            "movups $1, %xmm0", "movups (%rax), (%rbx)"):
            self.diagnostic(".text\n" + instruction + "\n")

    def test_binary80_x87_encodings(self):
        source = (".text\nfldt (%rax)\nfstpt -32(%r12,%r9,4)\n"
                  "flds (%r13)\nfstps external(%rip)\nfildl (%rax)\n"
                  "fildll (%r8)\nfistpl (%rax)\nfistpll (%r12)\n"
                  "fnstcw 8(%r13)\nfldcw external(%rip)\n"
                  "faddp\nfmulp\nfsubrp\nfdivrp\nfucomip\n"
                  "fchs\nfabs\nftst\nfldz\n")
        ours = self.assemble(source, "binary80-ours")
        gnu = self.assemble(source, "binary80-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(relocations(ours), relocations(gnu))
        for instruction in ("fldt %rax", "fstpt %xmm0", "fildll $1",
                            "fistpll %rax", "fnstcw %ax", "fldcw %rax",
                            "fmulp %st(1)", "fucomip %st(1)", "fchs %st"):
            self.diagnostic(".text\n" + instruction + "\n")

    def test_binary80_x87_c_interoperability(self):
        source = (".text\n.globl extended_add\nextended_add:\n"
                  "fldt 8(%rsp)\nfldt 24(%rsp)\nfaddp\n"
                  "fstpt -24(%rsp)\nfldt -24(%rsp)\nret\n"
                  '.section .note.GNU-stack,"",@progbits\n')
        obj = self.assemble(source, "binary80-call")
        harness = self.path / "binary80-call.c"
        harness.write_text(
            "extern long double extended_add(long double, long double);\n"
            "int main(void) { long double x = extended_add(1.0L, 0x1p-63L);"
            " return x != 1.0L + 0x1p-63L || x == 1.0L; }\n")
        executable = self.path / "binary80-call"
        command("cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                harness, obj, "-o", executable)
        self.assertEqual(subprocess.run([str(executable)]).returncode, 0)

    def test_include_search_and_expansion_match_gnu(self):
        first, second, source_dir = (self.path / name for name in ("first", "second", "source"))
        for directory in (first, second, source_dir):
            directory.mkdir()
        (self.path / "choice.inc").write_text(".byte 1\n")
        (first / "choice.inc").write_text(".byte 2\n")
        (second / "choice.inc").write_text(".byte 3\n")
        (source_dir / "choice.inc").write_text(".byte 99\n")
        (first / "nested.inc").write_text('.byte 4\n.include "inner.inc"\n')
        (second / "inner.inc").write_text(".byte 5\n")
        (first / "macro file.inc").write_text(".byte 6\n")
        (first / "close.inc").write_text(".byte 7\n.endif\n")
        (first / "open.inc").write_text(".if 1\n.byte 8\n")
        (first / "empty.inc").write_text("")
        source = source_dir / "main.s"
        source.write_text(
            '.data\n.include "choice.inc"\n.include "nested.inc"\n'
            '.macro use_file file:req\n.include "\\file"\n.endm\n'
            'use_file "macro file.inc"\n.if 1\n.include "close.inc"\n'
            '.include "open.inc"\n.byte 9\n.endif\n'
            '.if 0\n.include "not-present.inc"\n.endif\n'
            '.rept 2\n.include "macro file.inc"\n.endr\n'
            'before_include: .include "empty.inc"\n'
            '.ifdef before_include\n.byte 10\n.endif\n'
        )
        for assembler in ("as", ASSEMBLER):
            with self.subTest(assembler=assembler):
                obj = self.path / f"{pathlib.Path(assembler).name}.o"
                result = subprocess.run([str(assembler), "-I", str(first), f"-I{second}",
                                         "-o", str(obj), str(source)],
                                        cwd=self.path, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                header = named_section(obj, ".data")
                self.assertEqual(obj.read_bytes()[header[4]:header[4] + header[5]],
                                 bytes((1, 4, 5, 6, 7, 8, 9, 6, 6, 10)))
        (self.path / "choice.inc").unlink()
        for assembler in ("as", ASSEMBLER):
            obj = self.path / f"search-{pathlib.Path(assembler).name}.o"
            result = subprocess.run([str(assembler), "-I", str(first), "-I", str(second),
                                     "-o", str(obj), str(source)],
                                    cwd=self.path, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            header = named_section(obj, ".data")
            self.assertEqual(obj.read_bytes()[header[4]], 2)

    def test_include_errors_locations_and_output(self):
        includes = self.path / "includes"
        includes.mkdir()
        bad = includes / "bad.inc"
        bad.write_text("# comment\ninvalid_instruction\n")
        nested = includes / "nested.inc"
        nested.write_text('.include "bad.inc"\n')
        source = self.path / "main.s"
        output = self.path / "preserved.o"
        cases = (
            ('.include "nested.inc"\n', f"{bad}:2:"),
            ('.include "missing.inc"\n', f"{source}:1:"),
            ('.include missing\n', f"{source}:1:"),
            ('.include "bad.inc" garbage\n', f"{source}:1:"),
            ('.include "unterminated\n', f"{source}:1:"),
        )
        for text, location in cases:
            with self.subTest(text=text):
                source.write_text(text)
                output.write_bytes(b"unchanged")
                reference = subprocess.run(["as", "-I", str(includes),
                                            "-o", str(self.path / "failed-gnu.o"), str(source)],
                                           cwd=self.path, capture_output=True, text=True)
                self.assertNotEqual(reference.returncode, 0)
                result = subprocess.run([str(ASSEMBLER), "-I", str(includes),
                                         "-o", str(output), str(source)],
                                        cwd=self.path, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(location, result.stderr)
                self.assertEqual(output.read_bytes(), b"unchanged")
        source.write_text('.macro bad\n.include "bad.inc"\n.endm\nbad\n')
        result = subprocess.run([str(ASSEMBLER), "-I", str(includes),
                                 "-o", str(output), str(source)],
                                cwd=self.path, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{bad}:2: error:", result.stderr)
        self.assertIn(f"{source}:4: note: expanded from here", result.stderr)
        cycle = includes / "cycle.inc"
        cycle.write_text('.include "cycle.inc"\n')
        source.write_text('.include "cycle.inc"\n')
        result = subprocess.run([str(ASSEMBLER), "-I", str(includes),
                                 "-o", str(output), str(source)],
                                cwd=self.path, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("include nesting limit", result.stderr)
        self.assertEqual(output.read_bytes(), b"unchanged")

    def test_include_absolute_escaping_and_source_locations(self):
        include = self.path / 'escaped "name".inc'
        include.write_text(".byte 42\n")
        filename = str(include).replace("\\", "\\\\").replace('"', '\\"')
        source = self.path / "source.s"
        source.write_text(f'.data\n.include "{filename}"\n.byte 5\n')
        for assembler in ("as", ASSEMBLER):
            output = self.path / f"absolute-{pathlib.Path(assembler).name}.o"
            command(assembler, "-o", output, source)
            header = named_section(output, ".data")
            self.assertEqual(output.read_bytes()[header[4]:header[4] + header[5]], b"\x2a\x05")
        source.write_text(f'.include "{filename}"\ninvalid_instruction\n')
        result = subprocess.run([str(ASSEMBLER), "-o", str(self.path / "failed.o"), str(source)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{source}:2: error:", result.stderr)

        source_dir = self.path / "source-dir"
        source_dir.mkdir()
        (source_dir / "only-here.inc").write_text(".byte 1\n")
        source = source_dir / "source.s"
        source.write_text('.include "only-here.inc"\n')
        for assembler in ("as", ASSEMBLER):
            result = subprocess.run([str(assembler), "-o", str(self.path / "failed.o"), str(source)],
                                    cwd=self.path, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("only-here.inc", result.stderr)
        for args in (["-I"], ["-I", ""], ["-I", str(source_dir), "-I"]):
            result = subprocess.run([str(ASSEMBLER), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("-I requires", result.stderr)

    def test_directive_names_require_boundaries(self):
        names = (".byte", ".word", ".short", ".long", ".int", ".quad",
                 ".zero", ".space", ".align", ".balign", ".p2align",
                 ".ascii", ".asciz", ".string", ".file")
        for name in names:
            for suffix in ("_bogus", ".bogus", "9bogus"):
                with self.subTest(name=name, suffix=suffix):
                    source = f".data\n{name}{suffix} 1\n"
                    gnu = subprocess.run(
                        ["as", "-o", str(self.path / "invalid-gnu.o")],
                        input=source, capture_output=True, text=True
                    )
                    self.assertNotEqual(gnu.returncode, 0)
                    self.assertIn("<stdin>:2: error: unsupported directive",
                                  self.diagnostic(source))
        output = self.path / "preserved.o"
        output.write_bytes(b"unchanged")
        result = subprocess.run([str(ASSEMBLER), "-o", str(output)],
                                input=".data\n.bytegarbage 42\n",
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"unchanged")

    def test_data_directive_names_match_gnu(self):
        source = (
            ".data\n.byte 0x12\n.word\t0x3456\n.short 0x789a\n"
            ".long 0x12345678\n.int\t0x23456789\n.quad 0x123456789abcdef0\n"
            ".zero 2\n.space\t3,42\n.align 8,0\n.balign\t16,0\n"
            '.p2align 5,0\n.ascii "a"\n.asciz\t"b"\n'
        )
        ours = self.assemble(source, "directive-names-ours")
        gnu = self.assemble(source, "directive-names-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        self.assertEqual(native[8], reference[8])
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])

    def test_zero_subsection_selection_matches_gnu(self):
        source = (
            ".equ zero,0\n.text 0\n.globl first\nfirst: nop\n"
            ".data (3-3)\n.globl value\nvalue: .quad first\n"
            ".bss zero\n.globl storage\nstorage: .zero 4\n"
            ".text\nret\n.data 0\n.byte 42\n"
        )
        ours = self.assemble(source, "zero-subsection-ours")
        gnu = self.assemble(source, "zero-subsection-gnu", "as")
        for name in (".text", ".data", ".bss"):
            with self.subTest(section=name):
                native, reference = named_section(ours, name), named_section(gnu, name)
                self.assertEqual(native[5], reference[5])
                if name != ".bss":
                    self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                                     gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        for name in ("first", "value", "storage"):
            self.assertEqual(symbol_records(ours)[name], symbol_records(gnu)[name])
        self.assertEqual(relocations(ours), relocations(gnu))

        extensions = self.assemble(
            ".rodata 0\n.byte 1\n.tdata 0\n.byte 2\n.tbss 0\n.zero 3\n",
            "zero-subsection-extensions"
        )
        for name, size in ((".rodata", 1), (".tdata", 1), (".tbss", 3)):
            self.assertEqual(named_section(extensions, name)[5], size)

    def test_section_subsections_reject_unsupported_operands(self):
        for section in (".text", ".data", ".bss", ".rodata", ".tdata", ".tbss"):
            for operand in ("1", "-1", "1+1"):
                with self.subTest(section=section, operand=operand):
                    self.assertIn("nonzero section subsections are unsupported",
                                  self.diagnostic(f"{section} {operand}\n"))
            for operand in ("unknown", "0,1", "(0", "0 trailing"):
                with self.subTest(section=section, operand=operand):
                    source = f"{section} {operand}\n"
                    if section in (".text", ".data", ".bss"):
                        gnu = subprocess.run(
                            ["as", "-o", str(self.path / "invalid-subsection.o")],
                            input=source, capture_output=True, text=True
                        )
                        self.assertNotEqual(gnu.returncode, 0)
                    self.assertIn("section subsection must be an absolute expression",
                                  self.diagnostic(source))
        output = self.path / "preserved-subsection.o"
        output.write_bytes(b"unchanged")
        source = ".text 1\n.byte 0x11\n.text 0\n.byte 0x22\n.text 1\n.byte 0x33\n"
        result = subprocess.run([str(ASSEMBLER), "-o", str(output)],
                                input=source, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nonzero section subsections are unsupported", result.stderr)
        self.assertEqual(output.read_bytes(), b"unchanged")

    def test_file_and_stdin_locations(self):
        first, second = self.path / "first.s", self.path / "second.s"
        first.write_text(".text\nret\n")
        second.write_text("# comment\n\ninvalid_instruction\n")
        result = subprocess.run(
            [str(ASSEMBLER), "-o", str(self.path / "failed.o"), str(first), str(second)],
            capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{second}:3: error:", result.stderr)
        self.assertNotIn(f"{first}:", result.stderr)
        self.assertIn("<stdin>:2: error:", self.diagnostic(".text\ninvalid_instruction\n"))

    def test_macro_expansion_locations(self):
        source = (".macro inner arg\ninvalid_instruction\n.endm\n"
                  ".macro outer\ninner 1\n.endm\n.text\nouter\n")
        diagnostic = self.diagnostic(source)
        self.assertIn("<stdin>:2: error:", diagnostic)
        self.assertIn("<stdin>:5: note: expanded from here", diagnostic)
        self.assertIn("<stdin>:8: note: expanded from here", diagnostic)
        self.assertLess(diagnostic.index("<stdin>:2:"), diagnostic.index("<stdin>:5:"))
        self.assertLess(diagnostic.index("<stdin>:5:"), diagnostic.index("<stdin>:8:"))
        argument_error = self.diagnostic(".macro m arg\nret\n.endm\nm unknown=1\n")
        self.assertIn("<stdin>:4: error: unknown named macro argument", argument_error)
        nested_argument = self.diagnostic(
            ".macro inner arg\nret\n.endm\n.macro outer\ninner unknown=1\n.endm\nouter\n"
        )
        self.assertIn("<stdin>:5: error: unknown named macro argument", nested_argument)
        self.assertIn("<stdin>:7: note: expanded from here", nested_argument)

    def test_macro_exit_and_nested_character_repetition_match_gnu(self):
        source = (
            ".macro inner\n.byte 1\n.if 1\n.exitm\n.endif\n.byte 99\n.endm\n"
            ".macro outer\ninner\n.byte 2\n.endm\n"
            ".data\nouter\n.rept 3\n.byte 3\n.if 1\n.exitm\n.endif\n"
            ".byte 99\n.endr\n.byte 4\n"
            ".irpc outer,ab\n.ascii \"\\outer\"\n.irpc inner,xy\n"
            ".ascii \"\\inner\"\n.endr\n.endr\n"
        )
        ours = self.assemble(source, "macro-flow-ours")
        gnu = self.assemble(source, "macro-flow-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, b"\x01\x02\x03\x04axybxy")

    def test_macro_counter_matches_gnu(self):
        source = (
            ".macro inner\n.byte \\@\n.endm\n"
            ".macro outer\n.byte \\@\ninner\n.byte \\@\n"
            ".rept 2\n.byte \\@\n.endr\n.endm\n"
            ".data\nouter\nouter\n"
            ".irp value,a,b,c\n.byte \\@\ninner\n.byte \\@\n.endr\n"
            ".irpc value,xy\n.byte \\@\n.byte \\@\n.endr\ninner\n"
        )
        ours = self.assemble(source, "macro-counter-ours")
        gnu = self.assemble(source, "macro-counter-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, bytes((0, 1, 0, 0, 0, 2, 3, 2, 2, 2,
                                      4, 4, 4, 4, 5, 4, 4, 6, 4, 7, 7, 7, 7, 7)))

    def test_macro_required_parameters_match_gnu(self):
        source = (
            ".macro emit value:req,extra=7\n.byte \\value,\\extra\n.endm\n"
            ".macro defaults first=3,second=5\n.byte \\first,\\second\n.endm\n"
            ".data\nemit 42\nemit value=1,extra=2\nemit 9,\n"
            "defaults ,7\ndefaults first=,second=8\n"
        )
        ours = self.assemble(source, "macro-required-ours")
        gnu = self.assemble(source, "macro-required-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, bytes((42, 7, 1, 2, 9, 7, 3, 7, 3, 8)))

        for call in ("emit", "emit ,1", "emit value=", 'emit value=""'):
            with self.subTest(call=call):
                source = f".macro emit value:req,extra=7\n.byte 42\n.endm\n.data\n{call}\n"
                gnu_result = subprocess.run(
                    ["as", "-o", str(self.path / "missing-required.o")],
                    input=source, capture_output=True, text=True
                )
                self.assertNotEqual(gnu_result.returncode, 0)
                self.assertIn("missing required macro argument", self.diagnostic(source))
        for declaration, message in (
            ("value:vararg", "unsupported macro parameter qualifier"),
            ("value:unknown", "unsupported macro parameter qualifier"),
            ("value:req=1", "default value for required macro parameter is unsupported"),
            ("value:req,value", "duplicate macro parameter"),
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(message, self.diagnostic(f".macro emit {declaration}\n.endm\n"))

    def test_macro_quoted_arguments_match_gnu(self):
        source = "\n".join((
            ".macro match value",
            r".ifc \value,hello",
            ".byte 1",
            ".else",
            ".byte 2",
            ".endif",
            ".endm",
            r'.macro emit value:req',
            r'.asciz "\value"',
            ".endm",
            r'.macro defaulted value="a b"',
            r'.asciz "\value"',
            ".endm",
            ".macro number value=7",
            r".byte \value",
            ".endm",
            ".data",
            'match "hello"',
            'emit "a=b,c"',
            'emit value="a b"',
            r'emit "a\"b"',
            r'emit "a\\b"',
            r'emit "a\nb"',
            'defaulted',
            'number ""',
            "",
        ))
        ours = self.assemble(source, "macro-quoted-ours")
        gnu = self.assemble(source, "macro-quoted-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, b'\x01a=b,c\0a b\0a"b\0a\\b\0a\nb\0a b\0\x07')
        for argument in ('"unterminated', '"a"tail', "'a'", "a b"):
            with self.subTest(argument=argument):
                source = f".macro emit value\n.byte 42\n.endm\nemit {argument}\n"
                self.diagnostic(source)

    def test_macro_unknown_substitutions_preserved(self):
        for token in (r"\missing", r"\1"):
            with self.subTest(token=token):
                source = f".macro m value\n.byte 1{token}\n.endm\n.data\nm 2\n"
                gnu = subprocess.run(
                    ["as", "-o", str(self.path / "unknown-substitution.o")],
                    input=source, capture_output=True, text=True
                )
                self.assertNotEqual(gnu.returncode, 0)
                self.assertIn("<stdin>:2: error:", self.diagnostic(source))
        source = (
            ".macro m\n.ifc \\missing,\\missing\n.byte 9\n.endif\n.endm\n.data\nm\n"
            ".irp a,1,2\n.irp b,3,4\n.byte \\a,\\b\n.endr\n.endr\n"
        )
        ours = self.assemble(source, "macro-unknown-ours")
        gnu = self.assemble(source, "macro-unknown-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])

    def test_macro_unsupported_constructs_fail_safely(self):
        duplicate = ".macro m\n.byte 1\n.endm\n.macro m\n.byte 2\n.endm\n"
        parameters = ",".join(f"p{i}" for i in range(33))
        arguments = ",".join("1" for _ in range(33))
        cases = (
            (".altmacro\n", ".altmacro is unsupported"),
            (".altmacro # comment\n", ".altmacro is unsupported"),
            (".macro m\n.altmacro\n.endm\nm\n", ".altmacro is unsupported"),
            (".exitm\n.byte 42\n", ".exitm outside a macro or repetition"),
            (".macro m\n.exitm garbage\n.endm\nm\n", ".exitm does not accept operands"),
            (duplicate, "macro already defined"),
            (f".macro m {parameters}\n.endm\n", "too many macro parameters"),
            (f".macro m a=0\n.byte \\a\n.endm\nm {arguments}\n", "too many macro arguments"),
            ('.irpc ch,"ab"\n.byte 1\n.endr\n', "unsupported .irpc character list"),
            (".irpc ch,a b\n.byte 1\n.endr\n", "unsupported .irpc character list"),
            (".irpc ch,a,b\n.byte 1\n.endr\n", "unsupported or excessive .irpc character list"),
            (f".irpc ch,{'a' * 257}\n.byte 1\n.endr\n", "unsupported or excessive .irpc character list"),
        )
        for source, message in cases:
            with self.subTest(message=message, source=source[:40]):
                self.assertIn(message, self.diagnostic(source))
        safe = self.assemble(".if 0\n.altmacro\n.endif\n.noaltmacro\n.data\n.byte 42\n",
                             "inactive-altmacro")
        header = named_section(safe, ".data")
        self.assertEqual(safe.read_bytes()[header[4]:header[4] + header[5]], b"\x2a")
        output = self.path / "altmacro-preserved.o"
        output.write_bytes(b"unchanged")
        result = subprocess.run([str(ASSEMBLER), "-o", str(output)],
                                input=".altmacro\n.data\n.byte 42\n",
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"unchanged")

    def test_preprocessing_locations(self):
        for directive in (".rept 1", ".irp x,one", ".irpc x,a"):
            with self.subTest(directive=directive):
                diagnostic = self.diagnostic(f"{directive}\ninvalid_instruction\n.endr\n")
                self.assertIn("<stdin>:2: error:", diagnostic)
                self.assertIn("<stdin>:1: note: expanded from here", diagnostic)
        self.assertIn("<stdin>:2: error: unterminated conditional",
                      self.diagnostic(".text\n.if 1\nret\n"))
        self.assertIn("<stdin>:3: error:", self.diagnostic(".if 1\n.text\ninvalid_instruction\n.endif\n"))
        nested = self.diagnostic(".macro m\n.rept 1\ninvalid_instruction\n.endr\n.endm\nm\n")
        self.assertIn("<stdin>:3: error:", nested)
        self.assertIn("<stdin>:2: note: expanded from here", nested)
        self.assertIn("<stdin>:6: note: expanded from here", nested)

    def test_conditional_directives_fail_safely(self):
        cases = (
            (".if 0\n.byte 1\n.else\n.byte 2\n.else\n.byte 3\n.endif\n",
             "<stdin>:5: error: duplicate .else"),
            (".if 0\n.else\n.elseif 1\n.endif\n",
             "<stdin>:3: error: .elseif after .else"),
            (".if 0\n.if 1\n.else\n.elseif 1\n.endif\n.endif\n",
             "<stdin>:4: error: .elseif after .else"),
            (".ifdef\n.endif\n", "<stdin>:1: error: .ifdef/.ifndef expects"),
            (".ifndef symbol+1\n.endif\n", "<stdin>:1: error: .ifdef/.ifndef expects"),
            (".if 0\n.ifdef invalid,extra\n.endif\n.endif\n",
             "<stdin>:2: error: .ifdef/.ifndef expects"),
            (".if 0\n.elseif missing\n.endif\n",
             "<stdin>:2: error: .elseif requires an absolute expression"),
            (".elseif 1\n", "<stdin>:1: error: unexpected conditional/repetition terminator"),
            (".if 0\nskipped: .endif\n", "<stdin>:1: error: unterminated conditional"),
        )
        for source, message in cases:
            with self.subTest(message=message):
                result = subprocess.run(["as", "-o", str(self.path / "invalid-conditional.o")],
                                        input=source, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, self.diagnostic(source))
        valid = (
            ".data\n.if 1\n.byte 1\n.ifc a,a\n.byte 2\n.else\n.byte 99\n"
            ".endif\n.else\n.byte 99\n.endif\n"
        )
        ours = self.assemble(valid, "conditional-ours")
        gnu = self.assemble(valid, "conditional-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        diagnostic = self.diagnostic(".macro m\n.if 0\n.elseif missing\n.endif\n.endm\nm\n")
        self.assertIn("<stdin>:3: error: .elseif requires an absolute expression", diagnostic)
        self.assertIn("<stdin>:6: note: expanded from here", diagnostic)

    def test_defined_symbol_and_elseif_conditionals_match_gnu(self):
        source = (
            ".data\n.globl declared\n.weak weak_name\n.extern external\n"
            ".ifdef declared\n.byte 99\n.elseif 0\n.byte 99\n.elseif 1\n.byte 1\n"
            ".elseif missing\n.byte 99\n.else\n.byte 99\n.endif\n"
            ".ifndef weak_name\n.byte 2\n.endif\n"
            ".ifndef external\n.byte 3\n.endif\n"
            ".ifdef future\n.byte 99\n.else\n.byte 4\n.endif\n"
            "future: .byte 0\n"
            ".ifdef future\n.byte 5\n.endif\n"
            ".comm shared,4,4\n.lcomm local_shared,4\n"
            ".ifdef shared\n.byte 6\n.endif\n"
            ".ifdef local_shared\n.byte 7\n.endif\n"
            ".equ constant,2\n.set zero,0\n.set alias,future\n"
            ".ifdef constant\n.byte 8\n.endif\n"
            ".ifdef zero\n.byte 9\n.endif\n"
            ".ifdef alias\n.byte 10\n.endif\n"
            ".section conditional_section,\"a\",@progbits\n.data\n"
            ".ifdef conditional_section\n.byte 11\n.endif\n"
            ".ifdef .text\n.byte 12\n.endif\n"
            ".ifndef .\n.byte 13\n.endif\n"
            ".macro defined_macro symbol:req\n"
            ".ifdef \\symbol\n.byte 14\n.else\n.byte 99\n.endif\n.endm\n"
            ".ifndef defined_macro\n.byte 15\n.endif\n"
            "defined_macro future\n"
            ".macro make_symbol\n.set macro_symbol,1\n.endm\n"
            "make_symbol\n.ifdef macro_symbol\n.byte 27\n.endif\n"
            ".if 0\n.set inactive,1\n.endif\n"
            ".ifndef inactive\n.byte 16\n.endif\n"
            ".rept 2\n.ifdef zero\n.byte 17\n.endif\n.endr\n"
            ".rept 2\n.ifdef repeated\n.byte 29\n.else\n.byte 28\n"
            ".set repeated,1\n.endif\n.endr\n"
            ".if 0\n.ifndef future\n.byte 99\n.elseif 1\n.byte 99\n.endif\n"
            ".elseif constant-2\n.byte 99\n.elseif constant-1\n.byte 18\n"
            ".else\n.byte 99\n.endif\n"
            ".if 1\n.byte 19\n.elseif\n.byte 99\n.endif\n"
            "opening: .ifdef opening\n.byte 20\n.endif\n"
            ".if 1\n.byte 21\nclosing: .else\n.byte 99\n.endif\n"
            ".ifdef closing\n.byte 22\n.endif\n"
            ".if 0\ninactive_label: .else\n.byte 23\n.endif\n"
            ".ifndef inactive_label\n.byte 24\n.endif\n"
            ".if 1\n"
            ".macro inner_conditional\n.if 0\n.byte 99\n.else\n.byte 25\n.endif\n.endm\n"
            "inner_conditional\n.endif\n"
            "1: .if 1\n.byte 26\n.endif\n"
            ".rept 0\n.if 1\n.else garbage\n.endif\n.endr\n"
            ".rept 1\n.macro unused_conditional\n.if 1\n"
            ".else garbage\n.endif\n.endm\n.endr\n.byte 30\n"
        )
        ours = self.assemble(source, "defined-ours")
        gnu = self.assemble(source, "defined-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, bytes((1, 2, 3, 4, 0, 5, 6, 7, 8, 9, 10, 11, 12,
                                      13, 15, 14, 27, 16, 17, 17, 28, 29, 18, 19,
                                      20, 21, 22, 24, 25, 26, 30)))

    def test_many_preprocessing_symbols(self):
        source = (".section .text\n" +
                  "".join(f"label_{i}:\n" for i in range(4094)) +
                  ".section .bss\n.section .rodata\n.section .data\n"
                  ".set flag,1\n.ifdef label_0\n.if flag\n.byte 42\n.endif\n.endif\n"
                  ".set flag,0\n.ifndef absent\n.if flag\n.byte 99\n.endif\n.endif\n")
        obj = self.assemble(source, "many-preprocessing-symbols")
        data = named_section(obj, ".data")
        self.assertEqual(obj.read_bytes()[data[4]:data[4] + data[5]], b"\x2a")

    def test_many_output_symbols(self):
        labels = [f"label_{i:05d}_abcdefghijklmnopqrstuvwxyz" for i in range(9000)]
        source = (".lcomm scratch,8\n.weak unused\n.text\n"
                  ".globl _start\n.type _start,@function\n_start:\n"
                  "lea pointers(%rip),%rsi\n"
                  f"lea {labels[-1]}(%rip),%rax\ncmp %rax,8(%rsi)\njne fail\n"
                  "lea scratch(%rip),%rax\ncmp %rax,16(%rsi)\njne fail\n"
                  "mov $42,%edi\nmov $60,%eax\nsyscall\n"
                  "fail: mov $1,%edi\nmov $60,%eax\nsyscall\n.size _start,.-_start\n" +
                  "".join(f"{name}:\n" for name in labels) +
                  ".globl answer\n.type answer,@function\nanswer: ret\n"
                  ".symver answer,answer@VERSION\n"
                  f".data\npointers: .quad {labels[0]},{labels[-1]},scratch,answer\n")
        ours = self.assemble(source, "many-symbols")
        gnu = self.assemble(source, "many-symbols-gnu", "as")
        native, reference = symbol_records(ours), symbol_records(gnu)
        for name in ("_start", "scratch", "answer", "answer@VERSION", labels[0], labels[-1]):
            self.assertEqual(native[name], reference[name], name)
        self.assertNotIn("unused", native)
        self.assertEqual([entry[2] for entry in relocations(ours)[-4:]],
                         [labels[0], labels[-1], "scratch", "answer"])
        self.assertGreater(named_section(ours, ".strtab")[5], 1 << 18)
        exe = self.path / "many-symbols-program"
        command(ASSEMBLER.parent / "crunch-ld", "-nostdlib", "-o", exe, ours)
        self.assertEqual(subprocess.run([str(exe)], check=False).returncode, 42)

    def test_many_relocations(self):
        source = (
            ".weak missing_weak\n.text\n.globl _start,target\n"
            "_start:\ncall target\n"
            "lea first(%rip),%rsi\nlea target+1(%rip),%rax\n"
            "cmp %rax,32792(%rsi)\njne fail\n"
            "lea second(%rip),%rsi\nlea target+2(%rip),%rax\n"
            "cmp %rax,23992(%rsi)\njne fail\n"
            "cmpq $0,24000(%rsi)\njne fail\n"
            "mov $42,%edi\nmov $60,%eax\nsyscall\n"
            "fail: mov $1,%edi\nmov $60,%eax\nsyscall\n"
            ".type target,@function\ntarget: ret\n.data\nfirst:\n" +
            "".join(f".quad target+{i % 3}\n" for i in range(4100)) +
            '.section .other,"aw",@progbits\nsecond:\n' +
            "".join(f".quad target+{i % 3}\n" for i in range(3000)) +
            ".quad missing_weak\n"
        )
        ours = self.assemble(source, "many-relocations")
        gnu = self.assemble(source, "many-relocations-gnu", "as")
        native = [r for r in relocations(ours) if r[1] == "R_X86_64_64"]
        reference = [r for r in relocations(gnu) if r[1] == "R_X86_64_64"]
        self.assertEqual(len(native), 7101)
        self.assertEqual(native, reference)
        exe = self.path / "many-relocations-program"
        command(ASSEMBLER.parent / "crunch-ld", "-nostdlib", "-o", exe, ours)
        self.assertEqual(subprocess.run([str(exe)], check=False).returncode, 42)

    def test_defined_symbol_conditionals_across_input_files(self):
        first = self.path / "first.s"
        second = self.path / "second.s"
        first.write_text(".data\n.ifndef later\n.byte 1\n.endif\n"
                         "prior: .byte 2\n.set flag,1\n")
        second.write_text(".ifdef prior\n.byte 3\n.endif\n"
                          ".ifdef flag\n.byte 4\n.endif\nlater: .byte 5\n")
        ours = self.path / "multiple-ours.o"
        gnu = self.path / "multiple-gnu.o"
        command(ASSEMBLER, "-o", ours, first, second)
        command("as", "-o", gnu, first, second)
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, bytes((1, 2, 3, 4, 5)))

    def test_string_conditionals_and_irp_match_gnu(self):
        source = "\n".join((
            ".macro emit value # comment",
            r'.asciz "\value"',
            ".endm # comment",
            ".data",
            'emit "a#b"',
            '.irp value,"hello","a b","a=b","a,b",plain # comment',
            r'.asciz "\value"',
            r".ifc \value,hello",
            ".byte 1",
            ".else",
            ".byte 2",
            ".endif",
            ".endr",
            '.irp value,"a#b"',
            r'.asciz "\value"',
            ".endr",
            '.ifc "a,b","a,b"',
            ".byte 9",
            ".else # comment",
            ".byte 3",
            ".endif # comment",
            ".ifnc (a,b),(a,b)",
            ".byte 4",
            ".endif",
            ".ifc a,a # comment",
            ".byte 5",
            ".endif",
            ".ifc a,a,extra",
            ".byte 9",
            ".else",
            ".byte 6",
            ".endif",
            "",
        ))
        ours = self.assemble(source, "conditional-irp-ours")
        gnu = self.assemble(source, "conditional-irp-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, b"a#b\0hello\0\x01a b\0\x02a=b\0\x02a,b\0\x02"
                               b"plain\0\x02a#b\0\x03\x04\x05\x06")
        self.assertIn("unsupported macro argument syntax",
                      self.diagnostic(".irp value,a b\n.byte 1\n.endr\n"))
        self.assertIn("unquoted macro substitution containing # is unsupported",
                      self.diagnostic('.irp v,"a#b"\n.ifc \\v,a\n.byte 1\n.endif\n.endr\n'))

    def test_preprocessing_source_order_constants_match_gnu(self):
        source = (
            ".equ base,2\n.set count,base+1\n.data\n"
            ".if count-3\n.byte 99\n.else\n.byte 1\n.endif\n"
            ".rept count\n.byte 7\n.endr\n"
            ".set count,0\n.if count\n.byte 99\n.else\n.byte 2\n.endif\n"
            ".if 0\n.set count,99\n.equ inactive,9\n.endif\n"
            ".if count\n.byte 99\n.else\n.byte 3\n.endif\n"
            ".macro define value\n.set count,\\value\n.endm\n"
            "define 2\n.rept count\n.byte 4\n.endr\n"
            ".set count,0\n.rept 3\n.byte count\n.set count,count+1\n.endr\n"
            ".if count-3\n.byte 99\n.else\n.byte 5\n.endif\n"
            "marker: .set count,1\n.if count\n.byte 6\n.endif\n"
        )
        ours = self.assemble(source, "ordered-constants-ours")
        gnu = self.assemble(source, "ordered-constants-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, bytes((1, 7, 7, 7, 2, 3, 4, 4, 0, 1, 2, 5, 6)))

    def test_preprocessing_rejects_unavailable_constants(self):
        sources = (
            ".if later\n.byte 1\n.endif\n.equ later,1\n",
            ".rept later\n.byte 1\n.endr\n.equ later,1\n",
            ".if 0\n.set hidden,1\n.endif\n.if hidden\n.byte 1\n.endif\n",
            ".set x,1\n.set x,unknown\n.if x\n.byte 1\n.endif\n",
            ".macro unused\n.equ hidden,1\n.endm\n.if hidden\n.byte 1\n.endif\n",
            ".equ alias,later\n.if alias\n.byte 1\n.endif\n.equ later,1\n",
        )
        for source in sources:
            with self.subTest(source=source):
                gnu = subprocess.run(
                    ["as", "-o", str(self.path / "invalid-order.o")],
                    input=source, capture_output=True, text=True
                )
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        diagnostic = self.diagnostic(".macro m\n.if missing\n.endif\n.endm\nm\n")
        self.assertIn("<stdin>:2: error: .if requires an absolute expression", diagnostic)
        self.assertIn("<stdin>:5: note: expanded from here", diagnostic)

    def test_equ_set_source_order_matches_gnu(self):
        source = (
            ".data\n.byte future,forward_set\n"
            ".set forward_set,forward_base+1\n.set forward_base,3\n"
            ".set future,1\n.equ future,2\n.byte future\n"
            ".set base,3\n.equ snapshot,base+1\n.set base,9\n.byte snapshot,base\n"
            ".equ repeated,5\n.byte repeated\n.equ repeated,6\n.byte repeated\n"
            ".equ forward,later+1\n.set later,7\n.byte forward\n"
            ".set later,11\n.byte forward,later\n"
            ".equ before_repeat,base\n"
            ".macro define n\n.equ base,\\n\n.equ snap,base+1\n.endm\n"
            "define 12\n.byte before_repeat,base,snap\n"
            ".rept 2\n.equ base,base+1\n.byte base\n.endr\n"
            ".if base-14\n.byte 99\n.elseif snap-13\n.byte 99\n.else\n.byte 15\n.endif\n"
            ".if 0\n.equ base,99\n.endif\n.byte base\n"
        )
        ours = self.assemble(source, "equ-order-ours")
        gnu = self.assemble(source, "equ-order-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(data, bytes((1, 4, 2, 4, 9, 5, 6, 8, 8, 11, 9, 12, 13,
                                      13, 14, 15, 14)))
        for symbol in ("future", "base", "snapshot", "repeated", "forward", "later", "snap"):
            self.assertEqual(symbol_records(ours)[symbol], symbol_records(gnu)[symbol])

    def test_equ_set_invalid_expressions(self):
        for source in (".equ invalid,(2\n.byte invalid\n",
                       ".equ a,b+1\n.equ b,a+1\n.byte a\n",
                       ".set x,1\n.equ x,1+*2\n.byte x\n"):
            with self.subTest(source=source):
                result = subprocess.run(["as", "-o", str(self.path / "invalid-equ.o")],
                                        input=source, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.diagnostic(source)

    def test_conditional_terminators_reject_operands(self):
        sources = (
            ".if 0\n.byte 1\n.else garbage\n.byte 2\n.endif\n",
            ".if 1\n.byte 1\n.else garbage\n.byte 2\n.endif\n",
            ".if 1\n.byte 1\n.endif garbage\n",
            ".if 0\n.if 1\n.else garbage\n.endif\n.endif\n",
            ".if 0\n.if 1\n.endif garbage\n.endif\n",
        )
        for source in sources:
            with self.subTest(source=source):
                gnu = subprocess.run(
                    ["as", "-o", str(self.path / "invalid-conditional.o")],
                    input=source, capture_output=True, text=True
                )
                self.assertNotEqual(gnu.returncode, 0)
                self.assertIn("unexpected operands after conditional terminator",
                              self.diagnostic(source))
        diagnostic = self.diagnostic(".macro m\n.if 1\n.endif garbage\n.endm\nm\n")
        self.assertIn("<stdin>:3: error:", diagnostic)
        self.assertIn("<stdin>:5: note: expanded from here", diagnostic)

    def test_deferred_and_numeric_label_locations(self):
        cases = (
            (".text\njmp 2f\n", 2, "unresolved forward numeric label"),
            (".equ bad, unknown\n.text\nret\n", 1, "unresolved or cyclic .equ"),
            (".data\n.quad missing-other\n.text\nret\n", 2, "unresolved symbol"),
            (".symver missing, alias@VER\n.text\nret\n", 1, ".symver source symbol is undefined"),
            (".pushsection .data\nret\n", 1, "unclosed .pushsection"),
        )
        for source, line, message in cases:
            with self.subTest(message=message):
                self.assertIn(f"<stdin>:{line}: error: {message}", self.diagnostic(source))
        diagnostic = self.diagnostic(".macro m\n.quad missing-other\n.endm\nm\n")
        self.assertIn("<stdin>:2: error: unresolved symbol", diagnostic)
        self.assertIn("<stdin>:4: note: expanded from here", diagnostic)

    def test_preprocessor_line_markers(self):
        diagnostic = self.diagnostic('# 23 "some\\\\path\\"quoted.S"\ninvalid_instruction\n')
        self.assertIn('some\\path"quoted.S:23: error:', diagnostic)
        diagnostic = self.diagnostic('# ordinary comment\ninvalid_instruction\n')
        self.assertIn("<stdin>:2: error:", diagnostic)

    def test_numeric_label_across_files(self):
        first, second = self.path / "first.s", self.path / "second.s"
        first.write_text(".text\njmp 1f\n")
        second.write_text("1:\nret\n")
        obj = self.path / "combined.o"
        command(ASSEMBLER, "-o", obj, first, second)
        binary = self.path / "combined.bin"
        command("objcopy", "--dump-section", f".text={binary}", obj)
        self.assertEqual(binary.read_bytes(), b"\xeb\x00\xc3")

    def test_numeric_label_names_and_long_expansion(self):
        source = (
            ".text\n.Lcrunch_as_num_0_1_4:\nnop\njmp 1f\n1:\n"
            ".data\n.quad " + ",".join(["1b"] * 100) + "\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        ours = self.assemble(source, "numeric-expansion")
        command("ld", "-r", "-o", self.path / "numeric-linked.o", ours)
        binary = self.path / "numeric-data.bin"
        command("objcopy", "--dump-section", f".data={binary}", ours)
        self.assertEqual(len(binary.read_bytes()), 800)
        self.assertEqual(len(relocations(ours)), 100)

    def test_symbol_operands_and_deferred_relocations(self):
        source = (
            ".text\n"
            "movabs $external + 4, %rax\n"
            "mov external + 8(%rip), %rax\n"
            "mov %rax, external - 4(%rip)\n"
            "call *external(%rip)\n"
            "call external@PLT\n"
            "jmp 1f\nnop\n1:\nret\n"
            ".data\n.quad external + 4, external - 8\n.long external + 3\n"
        )
        ours = self.assemble(source, "symbols-ours")
        gnu = self.assemble(source, "symbols-gnu", "as")
        self.assertEqual(relocations(ours), relocations(gnu))
        for name in (".text", ".data"):
            outputs = []
            for obj in (ours, gnu):
                binary = self.path / f"{obj.stem}{name}.bin"
                command("objcopy", "--dump-section", f"{name}={binary}", obj)
                outputs.append(binary.read_bytes())
            self.assertEqual(*outputs, msg=f"{name} differs from GNU as")

    def test_symbol_declaration_metadata_matches_gnu(self):
        source = (
            ".text\n"
            ".globl alpha, beta\n.global gamma, delta,\n"
            ".weak weak_a, weak_b, sticky, missing_weak, unused_weak\n"
            ".global sticky\n.local sticky\n"
            ".local local_a, local_b, local_to_global, missing_local\n"
            ".local missing_single\n"
            ".globl local_to_global\n"
            ".globl global_to_local\n.local global_to_local\n"
            ".hidden alpha, beta\n.protected gamma, delta\n"
            ".internal weak_a, weak_b\n"
            ".extern extern_local, unused_extern\n"
            ".extern extern_single\n.extern unused_extern_single\n"
            ".globl versioned\n.symver versioned, versioned@VERS_1\n"
            "alpha: ret\nbeta: ret\ngamma: ret\ndelta: ret\n"
            "weak_a: ret\nweak_b: ret\nsticky: ret\n"
            "local_a: ret\nlocal_b: ret\nlocal_to_global: ret\n"
            "global_to_local: ret\nextern_local: ret\nextern_single: ret\n"
            "versioned: ret\n"
            ".data\n.quad missing_weak, missing_local, missing_single\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        ours = self.assemble(source, "declarations-ours")
        gnu = self.assemble(source, "declarations-gnu", "as")
        native, reference = symbol_records(ours), symbol_records(gnu)
        names = ("alpha", "beta", "gamma", "delta", "weak_a", "weak_b", "sticky",
                 "local_a", "local_b", "local_to_global", "global_to_local",
                 "extern_local", "extern_single", "missing_weak", "missing_local",
                 "missing_single", "versioned", "versioned@VERS_1")
        for name in names:
            with self.subTest(symbol=name):
                self.assertIn(name, reference)
                self.assertEqual(native.get(name), reference[name])
        for name in ("unused_weak", "unused_extern", "unused_extern_single"):
            self.assertNotIn(name, reference)
            self.assertNotIn(name, native)

    def test_long_symbol_declaration_lists(self):
        names = [f"symbol_{index}" for index in range(150)]
        source = ".globl " + ",".join(names) + "\n.hidden " + ",".join(names) + "\n"
        ours = self.assemble(source, "long-declarations-ours")
        gnu = self.assemble(source, "long-declarations-gnu", "as")
        native, reference = symbol_records(ours), symbol_records(gnu)
        for name in names:
            with self.subTest(symbol=name):
                self.assertIn(name, reference)
                self.assertEqual(native.get(name), reference[name])

    def test_section_alignment_matches_gnu(self):
        sections = (
            (".text", ".text", False),
            (".data", ".data", False),
            (".bss", ".bss", True),
            (".section .rodata", ".rodata", False),
            ('.section .extra,"ax",@progbits', ".extra", False),
        )
        directives = (
            ".p2align 0",
            ".align 0",
            ".balign 0",
            ".balign 64,0",
            ".balign 64,85",
            ".align 128,0",
            ".p2align 6,0,1",
            ".p2align 6,0,0",
            ".p2align 6,0,",
            ".p2align 6,",
            ".p2align 6,,1",
            ".p2align 6,,",
        )
        for section_index, (select, name, nobits) in enumerate(sections):
            for directive_index, directive in enumerate(directives):
                if nobits and directive == ".balign 64,85":
                    continue
                with self.subTest(section=name, directive=directive):
                    byte = ".zero 1" if nobits else ".byte 1"
                    source = f"{select}\n{byte}\n{directive}\n.globl aligned\naligned: {byte}\n"
                    stem = f"align-{section_index}-{directive_index}"
                    ours = self.assemble(source, stem + "-ours")
                    gnu = self.assemble(source, stem + "-gnu", "as")
                    native, reference = named_section(ours, name), named_section(gnu, name)
                    self.assertEqual((native[5], native[8]), (reference[5], reference[8]))
                    self.assertEqual(symbol_records(ours)["aligned"], symbol_records(gnu)["aligned"])
                    if not nobits and directive != ".p2align 6,,":
                        our_data, gnu_data = ours.read_bytes(), gnu.read_bytes()
                        self.assertEqual(our_data[native[4]:native[4] + native[5]],
                                         gnu_data[reference[4]:reference[4] + reference[5]])

    def test_alignment_during_branch_relaxation(self):
        source = (".text\n.globl start\nstart: jmp target\n"
                  ".p2align 5,0\ntarget: ret\n")
        ours = self.assemble(source, "align-relax-ours")
        gnu = self.assemble(source, "align-relax-gnu", "as")
        self.assertEqual(symbol_records(ours)["target"], symbol_records(gnu)["target"])
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(native[8], reference[8])
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        largest = self.assemble(".data\n.p2align 20\n.byte 0\n", "align-limit")
        self.assertEqual(named_section(largest, ".data")[8], 1048576)

    def test_section_alignment_rejects_invalid_arguments(self):
        for section in (".text", ".data", ".bss", '.section .extra,"a",@progbits'):
            for directive in (".align 3", ".balign 24", ".p2align 21",
                              ".balign 2097152", ".p2align 4,0,-1"):
                with self.subTest(section=section, directive=directive):
                    self.diagnostic(f"{section}\n{directive}\n")
        self.diagnostic(".bss\n.byte 0\n.balign 16,1\n")
        self.diagnostic(".data\n.zero 1048575\n.p2align 20\n.byte 1\n")

    def test_executable_alignment_default_padding(self):
        source = (
            '.section .extra,"ax",@progbits\n.globl aligned_function\n'
            "aligned_function:\nnop\n.p2align 4,,\nmovl $42, %eax\nret\n"
            ".text\n.globl _start\n_start:\nnop\n.p2align 4\n"
            "call aligned_function\nmovl %eax, %edi\nmovl $60, %eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu")):
            obj = self.assemble(source, f"align-executable-{suffix}", assembler)
            exe = self.path / f"align-executable-{suffix}"
            command("ld", "-o", exe, obj)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_section_alignment_cross_object_linking(self):
        caller = (
            ".data\n.byte 0\n.section .rodata\n.byte 0\n"
            ".text\n.globl _start\n_start:\n"
            "leaq aligned_text(%rip), %rax\nandq $255, %rax\njne fail\n"
            "leaq aligned_data(%rip), %rax\nandq $255, %rax\njne fail\n"
            "leaq aligned_rodata(%rip), %rax\nandq $255, %rax\njne fail\n"
            "movl $42, %edi\nmovl $60, %eax\nsyscall\n"
            "fail: movl $1, %edi\nmovl $60, %eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        provider = (
            ".text\n.p2align 8\n.globl aligned_text\naligned_text: ret\n"
            ".data\n.p2align 8\n.globl aligned_data\naligned_data: .byte 0\n"
            ".section .rodata\n.p2align 8\n.globl aligned_rodata\naligned_rodata: .byte 0\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        pairs = [(self.assemble(caller, f"align-caller-{suffix}", assembler),
                  self.assemble(provider, f"align-provider-{suffix}", assembler))
                 for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu"))]
        for caller_obj, _ in pairs:
            for _, provider_obj in pairs:
                exe = self.path / f"{caller_obj.stem}-{provider_obj.stem}"
                command("ld", "-o", exe, caller_obj, provider_obj)
                self.assertEqual(subprocess.run([str(exe)]).returncode, 42,
                                 msg=f"{caller_obj} + {provider_obj}")

    def test_mergeable_section_metadata_and_padding(self):
        source = (
            ".equ entity, 2+2\n"
            '.section .merge.str,"aMS",@progbits,1\n.asciz "hello"\n'
            '.section .merge.wide,"aMS",@progbits,2\n.word 65,0\n'
            '.section .merge.fixed,"aM",@progbits,entity\n.globl chunk\nchunk: .byte 42\n'
            '.section .merge.odd,"aM",@progbits,6\n.byte 3\n'
            '.section .merge.bss,"awM",@nobits,4\n.zero 1\n'
            '.section .merge.array,"awM",@init_array,4\n.long 0\n'
            '.section .merge.exec,"axM",@progbits,4\nnop\n'
            '.section .merge.fixed\n.byte 7\n'
            '.section .merge.fixed,"aM",@progbits,4\n.byte 9\n'
            '.size chunk,.-chunk\n'
            '.section .note.GNU-stack,"",@progbits\n'
        )
        ours = self.assemble(source, "merge-metadata-ours")
        gnu = self.assemble(source, "merge-metadata-gnu", "as")
        self.assertEqual(symbol_records(ours)["chunk"], symbol_records(gnu)["chunk"])
        for name in (".merge.str", ".merge.wide", ".merge.fixed", ".merge.odd",
                     ".merge.bss", ".merge.array", ".merge.exec"):
            with self.subTest(section=name):
                native, reference = named_section(ours, name), named_section(gnu, name)
                self.assertEqual(tuple(native[i] for i in (1, 2, 5, 8, 9)),
                                 tuple(reference[i] for i in (1, 2, 5, 8, 9)))
                if native[1] != 8 and name != ".merge.exec":
                    self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                                     gnu.read_bytes()[reference[4]:reference[4] + reference[5]])

    def test_string_directives_match_gnu(self):
        source = "\n".join((
            ".data",
            r'.ascii "A\x42","A\102"',
            r'.ascii "\x4\x4G\x100\x414243\Xff\x\Xg"',
            r'.ascii "\x000000000000000000000000000000041"',
            r'.ascii "\0\00\000\0123\0777\777\400\8\89\999\8888"',
            r'.ascii "\b\f\n\r\t\v\a\e\q\#\"\\1f"',
            r'.ascii "first" "second",,"third",',
            r'.asciz "one","two","", "\x41\102"',
            r'.asciz , "ad" "jacent",,"last", # comment',
            r'.string "one","two","", "\x41\102"',
            r'.string , "ad" "jacent",,"last", # comment',
            ".ascii ,",
            ".asciz ,,,",
            "",
        ))
        ours = self.assemble(source, "strings-ours")
        gnu = self.assemble(source, "strings-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        data = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(data, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertTrue(data.startswith(b"ABAB"))
        self.assertTrue(data.endswith(b"one\0two\0\0AB\0adjacent\0last\0" * 2))

    def test_string_directives_reject_invalid_input(self):
        statements = (
            '.ascii "one" junk',
            '.asciz "one", 123',
            '.string "one" junk',
            '.string "one", 123',
            '.stringXYZ "wrong directive"',
            '.ascii "one", +',
            '.asciiXYZ "wrong directive"',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                source = f".data\n{statement}\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "string-invalid.o")],
                                     input=source, capture_output=True, text=True)
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        self.assertIn("unterminated string", self.diagnostic('.ascii "unterminated\n'))
        output = self.path / "string-preserved.o"
        output.write_bytes(b"unchanged")
        result = subprocess.run([str(ASSEMBLER), "-o", str(output)],
                                input='.data\n.ascii "one" junk\n', capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"unchanged")

    def test_string_directives_in_nobits(self):
        source = (
            '.bss\n.ascii "\\000\\x00"\n.asciz "","\\0"\n.string "","\\0"\n'
            '.section .zeroes,"aw",@nobits\n.asciz "\\x00"\n'
        )
        ours = self.assemble(source, "strings-nobits-ours")
        gnu = self.assemble(source, "strings-nobits-gnu", "as")
        for name in (".bss", ".zeroes"):
            self.assertEqual(named_section(ours, name)[5], named_section(gnu, name)[5])
        for section in (".bss", '.section .zeroes,"aw",@nobits'):
            with self.subTest(section=section):
                self.assertIn("cannot emit nonzero", self.diagnostic(section + '\n.ascii "\\x01"\n'))

    def test_file_directive_elf_symbols_and_linking(self):
        source = (
            '.file "same"\n.file "same"\n.file "source\\056c"\n'
            '.data\n.globl same\nsame: .long 42\n'
            '.text\n.globl _start\n_start: mov same(%rip),%edi\n'
            'mov $60,%eax\nsyscall\n'
        )
        ours = self.assemble(source, "files-ours")
        gnu = self.assemble(source, "files-gnu", "as")
        for obj in (ours, gnu):
            output = command("readelf", "-sW", obj).stdout
            self.assertEqual(len(re.findall(r"FILE\s+LOCAL\s+DEFAULT\s+ABS\s+same$", output,
                                            re.MULTILINE)), 2)
            self.assertRegex(output, r"FILE\s+LOCAL\s+DEFAULT\s+ABS\s+source\.c")
            self.assertEqual(symbol_records(obj)["same"][2:], ("NOTYPE", "GLOBAL", "DEFAULT", ".data"))
        self.assertEqual(relocations(ours), relocations(gnu))
        for linker in ("ld", ASSEMBLER.parent / "crunch-ld"):
            executable = self.path / ("file-program-" + pathlib.Path(linker).name)
            command(linker, "-nostdlib", "-o", executable, ours)
            self.assertEqual(subprocess.run([str(executable)]).returncode, 42)

    def test_file_directive_invalid_and_multiple_inputs(self):
        for statement in ('.file', '.file foo', '.file "unterminated',
                          '.file "name" extra', '.file 1 "debug.c"'):
            with self.subTest(statement=statement):
                self.diagnostic(statement + "\n")
        self.assertIn("DWARF", self.diagnostic('.file 1 "debug.c"\n'))
        first, second = self.path / "first.s", self.path / "second.s"
        first.write_text('.file "first.c"\n.text\n.globl first\nfirst: ret\n')
        second.write_text('.file "second.c"\n.text\n.globl second\nsecond: ret\n')
        obj = self.path / "multiple.o"
        command(ASSEMBLER, "-o", obj, first, second)
        records = symbol_records(obj)
        for name in ("first.c", "second.c"):
            self.assertEqual(records[name], (0, 0, "FILE", "LOCAL", "DEFAULT", "ABS"))

    def test_file_directive_scopes_local_symbols(self):
        source = ('.file "first.c"\n.text\nfirst_local: nop\n'
                  '.file "second.c"\nsecond_local: nop\n'
                  '.globl global_symbol\nglobal_symbol: ret\n')
        for obj in (self.assemble(source, "file-order-ours"),
                    self.assemble(source, "file-order-gnu", "as")):
            output = command("readelf", "-sW", obj).stdout
            names = re.findall(r"^\s*\d+:.*\s(first\.c|second\.c|first_local|second_local|global_symbol)$",
                               output, re.MULTILINE)
            self.assertEqual(names, ["first.c", "first_local", "second.c",
                                     "second_local", "global_symbol"])
        partial = self.path / "file-partial.o"
        command(ASSEMBLER.parent / "crunch-ld", "-r", "-o", partial,
                self.path / "file-order-ours.o")
        for name in ("first.c", "second.c"):
            self.assertEqual(symbol_records(partial)[name][2:], ("FILE", "LOCAL", "DEFAULT", "ABS"))

    def test_string_directives_in_macro_and_repetition(self):
        source = "\n".join((
            ".macro emit value",
            r'.asciz "\value", "\x41\n\101\q"',
            r'.ascii "\\value", "\\\value", "\"\x42", "\\"',
            ".endm",
            ".macro shadow n",
            r'.ascii "\n"',
            ".endm",
            ".data",
            "emit Z",
            "shadow Q",
            ".irp item,Hi,Yo",
            r'.asciz "\item" "\x21"',
            ".endr",
            ".irpc ch,ab",
            r'.ascii "\ch" "\101"',
            ".endr",
            ".rept 2",
            r'.ascii "\102"',
            ".endr",
            "",
        ))
        ours = self.assemble(source, "macro-strings-ours")
        gnu = self.assemble(source, "macro-strings-gnu", "as")
        native, reference = named_section(ours, ".data"), named_section(gnu, ".data")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])

    def test_mergeable_section_rejects_invalid_attributes(self):
        statements = (
            '.section .foo,"aM",@progbits',
            '.section .foo,"aM",@progbits,0',
            '.section .foo,"aM",@progbits,-1',
            '.section .foo,"aM",@progbits,1048577',
            '.section .foo,"aM",@progbits,invalid+symbol',
            '.section .foo,"a",@progbits,4',
            '.section .foo,"a"junk,@progbits',
            '.section .foo,"aG",@progbits',
            '.section .text,"aM",@progbits,4',
            '.section .bss,"aM",@nobits,4',
            '.section .foo,"aM",@progbits,4\n.section .foo,"aM",@progbits,8',
            '.section .foo,"aM",@progbits,4\n.section .foo,"a",@progbits',
            '.section .foo,"aM",@progbits,1048576\n.byte 1\n.zero 1048575\n.byte 1',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.diagnostic(statement + "\n")

    def test_section_groups_match_gnu_metadata(self):
        source = (
            '.section .text.pick,"axG",@progbits,pick,comdat\n'
            ".globl pick\npick: ret\n"
            '.pushsection .data.pick,"awG",@progbits,pick,comdat\n.quad external\n'
            ".popsection\n.byte 42\n"
            '.section .merge.group,"aMG",@progbits,4,.Llocal_sig,comdat\n.long 7\n'
            '.section .plain.group,"aG",@progbits,plain_sig\n.byte 1\n'
            '.section .same,"aG",@progbits,first_sig,comdat\n.byte 2\n.quad external\n'
            '.section .same,"aG",@progbits,second_sig,comdat\n.byte 3\n.quad external\n'
            '.section .same,"aG",@progbits,first_sig,comdat\n.byte 4\n'
            '.section .group.bss,"awG",@nobits,bss_sig,comdat\n.zero 8\n'
        )
        ours = self.assemble(source, "groups-ours")
        gnu = self.assemble(source, "groups-gnu", "as")
        for obj in (ours, gnu):
            output = command("readelf", "-gW", obj).stdout
            for signature in ("pick", ".Llocal_sig", "plain_sig", "first_sig", "second_sig", "bss_sig"):
                self.assertIn(f"[{signature}]", output)
            self.assertIn(".rela.data.pick", output)
            symbols = symbol_records(obj)
            self.assertEqual(symbols["pick"][-1], ".text.pick")
            for signature in (".Llocal_sig", "plain_sig", "first_sig", "second_sig", "bss_sig"):
                self.assertEqual((symbols[signature][3], symbols[signature][-1]),
                                 ("LOCAL", ".group"))
        for name in (".text.pick", ".data.pick", ".rela.data.pick", ".merge.group",
                     ".plain.group", ".group.bss"):
            native, reference = named_section(ours, name), named_section(gnu, name)
            self.assertEqual(tuple(native[i] for i in (1, 2, 5, 8, 9)),
                             tuple(reference[i] for i in (1, 2, 5, 8, 9)), name)
        self.assertEqual(symbol_records(ours)["pick"], symbol_records(gnu)["pick"])
        self.assertEqual(relocations(ours), relocations(gnu))
        groups = command("readelf", "-gW", ours).stdout
        self.assertEqual(groups.count(".same"), 4)
        same = named_section(ours, ".same")
        self.assertEqual(ours.read_bytes()[same[4]:same[4] + same[5]], b"\x02" + bytes(8) + b"\x04")
        command("ld", "-r", "-o", self.path / "group-partial.o", ours)

    def test_grouped_tls_does_not_shadow_tls_directive(self):
        source = ('.section .tdata,"awTG",@progbits,tls_sig,comdat\n.byte 5\n'
                  ".tdata\n.byte 6\n.globl plain_tls\nplain_tls: .byte 7\n")
        obj = self.assemble(source, "group-tls")
        data = obj.read_bytes()
        index = int(re.search(r"\s(\d+)\s+plain_tls$", command("readelf", "-sW", obj).stdout,
                              re.MULTILINE).group(1))
        header = section(data, index)
        self.assertFalse(header[2] & 0x200)
        self.assertEqual(data[header[4]:header[4] + header[5]], b"\x06\x07")
        self.assertIn("[tls_sig]", command("readelf", "-gW", obj).stdout)

    def test_grouped_and_ungrouped_sections_with_same_name(self):
        source = ('.section .same,"aG",@progbits,sig,comdat\n.byte 1\n'
                  '.section .same,"a",@progbits\n.byte 2\n.section .same\n.byte 3\n')
        for obj in (self.assemble(source, "same-name-ours"),
                    self.assemble(source, "same-name-gnu", "as")):
            data = obj.read_bytes()
            names = string_table(data, section(data, struct.unpack_from("<H", data, 62)[0]))
            contents = []
            for index in range(struct.unpack_from("<H", data, 60)[0]):
                header = section(data, index)
                start = header[0]
                if names[start:names.index(b"\0", start)] == b".same":
                    contents.append((bool(header[2] & 0x200),
                                     data[header[4]:header[4] + header[5]]))
            self.assertEqual(contents, [(True, b"\x01"), (False, b"\x02\x03")])

    def test_section_group_signatures_and_rejections(self):
        source = (
            ".globl external_signature\n"
            '.section .global,"aG",@progbits,external_signature,comdat\n.byte 1\n'
            ".weak weak_signature\n"
            '.section .weak,"aG",@progbits,weak_signature,comdat\n.byte 2\n'
            '.section .referenced,"aG",@progbits,used_signature,comdat\n'
            ".quad used_signature\n"
            ".weak defined_signature\n"
            '.section .defined,"axG",@progbits,defined_signature,comdat\n'
            "defined_signature: ret\n"
        )
        ours = self.assemble(source, "group-signatures-ours")
        gnu = self.assemble(source, "group-signatures-gnu", "as")
        for name in ("external_signature", "weak_signature", "used_signature", "defined_signature"):
            self.assertEqual(symbol_records(ours)[name], symbol_records(gnu)[name])
        statements = (
            '.section .foo,"aG",@progbits',
            '.section .foo,"aG",@progbits,,comdat',
            '.section .foo,"aG",@progbits,123,comdat',
            '.section .foo,"aG",@progbits,sig,unknown',
            '.section .foo,"aG",@progbits,sig,comdat,extra',
            '.section .foo,"aMG",@progbits,sig,comdat',
            '.section .foo,"aG",@progbits,sig,comdat\n.section .foo\n',
            '.section .foo,"aG",@progbits,sig,comdat\n.section .bar,"aG",@progbits,sig',
            '.section .foo,"aG",@progbits,sig,comdat\n.section .foo,"awG",@progbits,sig,comdat',
            '.section .text,"axG",@progbits,sig,comdat',
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.diagnostic(statement + "\n")
        output = self.path / "group-preserved.o"
        output.write_bytes(b"unchanged")
        result = subprocess.run([str(ASSEMBLER), "-o", str(output)],
                                input=statements[0] + "\n", capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"unchanged")

    def test_mergeable_sections_cross_object_linking(self):
        caller = (
            ".text\n.globl _start\n_start:\n"
            "leaq str_a(%rip), %rax\nleaq str_b(%rip), %rbx\n"
            "cmpq %rbx, %rax\njne fail\nleaq str_other(%rip), %rbx\n"
            "cmpq %rbx, %rax\nje fail\ncmpb $104, str_a(%rip)\njne fail\n"
            "leaq const_a(%rip), %rax\nleaq const_b(%rip), %rbx\n"
            "cmpq %rbx, %rax\njne fail\nleaq const_other(%rip), %rbx\n"
            "cmpq %rbx, %rax\nje fail\n"
            "cmpl $42, const_a(%rip)\njne fail\n"
            "movl $42, %edi\nmovl $60, %eax\nsyscall\n"
            "fail: movl $1, %edi\nmovl $60, %eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        first = (
            '.section .rodata.str1.1,"aMS",@progbits,1\n'
            '.globl str_a, str_other\nstr_a: .asciz "\\x68" "ello"\nstr_other: .asciz "world"\n'
            '.section .rodata.cst4,"aM",@progbits,4\n.p2align 2\n'
            ".globl const_a, const_other\nconst_a: .long 42\nconst_other: .long 43\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        second = (
            '.section .rodata.str1.1,"aMS",@progbits,1\n'
            '.globl str_b\nstr_b: .asciz "\\150\\145llo"\n'
            '.section .rodata.cst4,"aM",@progbits,4\n.p2align 2\n'
            ".globl const_b\nconst_b: .long 42\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        objects = [[self.assemble(source, f"merge-{index}-{suffix}", assembler)
                    for index, source in enumerate((caller, first, second))]
                   for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu"))]
        for caller_obj, _, _ in objects:
            for _, first_obj, _ in objects:
                for _, _, second_obj in objects:
                    exe = self.path / f"{caller_obj.stem}-{first_obj.stem}-{second_obj.stem}"
                    command("ld", "-o", exe, caller_obj, first_obj, second_obj)
                    self.assertEqual(subprocess.run([str(exe)]).returncode, 42,
                                     msg=f"{caller_obj} + {first_obj} + {second_obj}")

    def test_common_symbol_metadata_matches_gnu(self):
        sizes = (0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 24)
        sources = [f".comm common_{size},{size}\n" for size in sizes]
        sources += [f".lcomm local_{size},{size}\n" for size in sizes]
        sources += [
            ".comm zero_align,9,0\n",
            ".comm repeated,4,16\n.comm repeated,4,2\n",
            ".comm initially_zero,0,1\n.comm initially_zero,8,16\n",
            ".local unaligned\n.comm unaligned,3\n",
            ".local aligned\n.hidden aligned\n.comm aligned,7,64\n",
            ".local local_then_global\n.globl local_then_global\n.comm local_then_global,4,4\n",
            ".local exported\n.comm exported,4,4\n.globl exported\n",
            ".weak weak_local\n.local weak_local\n.comm weak_local,4,4\n",
            ".globl exported_lcomm\n.lcomm exported_lcomm,3\n",
            ".weak weak_lcomm\n.lcomm weak_lcomm,5\n",
            ".comm still_common,4,4\n.local still_common\n",
            ".extern external_common\n.comm external_common,8\n",
            ".bss\n.p2align 7\n.zero 1\n",
        ]
        source = "".join(sources)
        ours = self.assemble(source, "common-metadata-ours")
        gnu = self.assemble(source, "common-metadata-gnu", "as")
        native, reference = symbol_records(ours), symbol_records(gnu)
        names = ([f"common_{size}" for size in sizes] +
                 [f"local_{size}" for size in sizes] +
                 ["zero_align", "repeated", "initially_zero", "unaligned", "aligned",
                  "local_then_global", "exported", "weak_local", "exported_lcomm",
                  "weak_lcomm", "still_common", "external_common"])
        for name in names:
            with self.subTest(symbol=name):
                self.assertIn(name, reference)
                self.assertEqual(native.get(name), reference[name])
        self.assertEqual(named_section(ours, ".bss")[5:6], named_section(gnu, ".bss")[5:6])
        self.assertEqual(named_section(ours, ".bss")[8], named_section(gnu, ".bss")[8])

    def test_common_redeclaration_warning_and_last_alignment(self):
        source = (".text\njmp done\nnop\ndone: ret\n"
                  ".comm value,4,16\n.comm value,8,2\n")
        src, obj = self.path / "common-warning.s", self.path / "common-warning.o"
        src.write_text(source)
        result = command(ASSEMBLER, "-o", obj, src)
        self.assertEqual(result.stderr.count("warning:"), 1)
        self.assertIn(f"{src}:6: warning:", result.stderr)
        self.assertIn("already 4", result.stderr)
        gnu = self.assemble(source, "common-warning-gnu", "as")
        self.assertEqual(symbol_records(obj)["value"], symbol_records(gnu)["value"])

    def test_local_common_layout_and_deferred_difference(self):
        source = (".lcomm item,4\n.local other\n.comm other,2,8\n"
                  ".bss\nbase: .zero 3\n"
                  ".data\n.quad item-base, other-item\n")
        ours = self.assemble(source, "common-layout-ours")
        gnu = self.assemble(source, "common-layout-gnu", "as")
        for name in ("item", "other", "base"):
            self.assertEqual(symbol_records(ours)[name], symbol_records(gnu)[name])
        for obj in (ours, gnu):
            command("objcopy", "--dump-section", f".data={self.path / (obj.stem + '.bin')}", obj)
        self.assertEqual((self.path / "common-layout-ours.bin").read_bytes(),
                         (self.path / "common-layout-gnu.bin").read_bytes())

    def test_large_nobits_sections(self):
        for directive in (".bss", '.section .large,"aw",@nobits',
                          '.section .large,"awM",@nobits,4'):
            obj = self.assemble(f"{directive}\n.zero 67108864\n", "large-nobits")
            name = ".bss" if directive == ".bss" else ".large"
            self.assertEqual(named_section(obj, name)[5], 67108864)
            self.assertLess(obj.stat().st_size, 4096)
            self.diagnostic(f"{directive}\n.zero 67108864\n.byte 0\n")
        obj = self.assemble('.section .large,"awM",@nobits,4\n.zero 67108863\n',
                            "large-merge-nobits")
        self.assertEqual(named_section(obj, ".large")[5], 67108864)

    def test_common_allocation_rejects_invalid_input(self):
        statements = (
            ".comm x,-1", ".comm x,4,-1", ".comm x,4,3",
            ".local x\n.comm x,4,3", ".lcomm x,4,3",
            ".local x\n.comm x,67108865,1", ".lcomm x,67108865",
            ".bss\n.zero 67108864\n.local x\n.comm x,1,16",
            ".bss\n.zero 67108863\n.lcomm x,2,16",
            ".comm x,4\nx: ret", "x: ret\n.comm x,4",
            ".local x\n.comm x,4\n.comm x,4", ".lcomm x,4\n.lcomm x,4",
            ".lcomm x,4\n.comm x,4", ".weak x\n.comm x,4",
            ".comm x,4\n.weak x",
            ".comm x,4\n.local x\n.comm x,4", ".comm x,4\n.lcomm x,4",
            ".lcomm x,4\n.set alias,x", ".lcomm x,4\n.set x,1",
            ".lcomm x,4\n.bss\n.size x,.-x",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                self.diagnostic(statement + "\n")
        extension = self.assemble(".lcomm x,4,64\n", "lcomm-alignment-extension")
        self.assertEqual(named_section(extension, ".bss")[8], 64)
        self.assertEqual(symbol_records(extension)["x"], (0, 4, "OBJECT", "LOCAL", "DEFAULT", ".bss"))

    def test_common_cross_object_linking_and_alignment(self):
        caller = (
            ".comm shared,4,4\n.local buffer\n.comm buffer,4,64\n"
            ".text\n.globl _start\n_start:\n"
            "leaq buffer(%rip), %rax\nandq $63, %rax\njne fail\n"
            "movl $20, buffer(%rip)\nmovl $1, shared(%rip)\ncall provider\n"
            "cmpl $20, buffer(%rip)\njne fail\ncmpl $2, shared(%rip)\njne fail\n"
            "addl buffer(%rip), %eax\nmovl %eax, %edi\nmovl $60, %eax\nsyscall\n"
            "fail: movl $1, %edi\nmovl $60, %eax\nsyscall\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        provider_body = (
            ".local buffer\n.comm buffer,4,64\n"
            ".text\n.globl provider\nprovider:\n"
            "leaq buffer(%rip), %rax\nandq $63, %rax\njne fail_provider\n"
            "movl $22, buffer(%rip)\naddl $1, shared(%rip)\n"
            "movl buffer(%rip), %eax\nret\n"
            "fail_provider: movl $1, %eax\nret\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        sources = (
            ".comm shared,8,8\n" + provider_body,
            ".data\n.globl shared\nshared: .long 0\n.long 0\n" + provider_body,
        )
        callers = [self.assemble(caller, f"common-caller-{suffix}", assembler)
                   for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu"))]
        for kind, source in enumerate(sources):
            providers = [self.assemble(source, f"common-provider-{kind}-{suffix}", assembler)
                         for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu"))]
            for caller_obj in callers:
                for provider_obj in providers:
                    exe = self.path / f"{caller_obj.stem}-{provider_obj.stem}"
                    command("ld", "-o", exe, caller_obj, provider_obj)
                    self.assertEqual(subprocess.run([str(exe)]).returncode, 42,
                                     msg=f"{caller_obj} + {provider_obj}")

    def test_symbol_declarations_cross_object_linking(self):
        provider = (
            ".text\n.globl first, second\n"
            "first: mov $20, %eax\nret\n"
            "second: mov $22, %eax\nret\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        caller = (
            ".weak optional\n.data\nweakptr: .quad optional\n"
            ".text\n.globl _start\n.local first, second\n"
            "_start:\ncmpq $0, weakptr(%rip)\njne fail\n"
            "call first\nmov %eax, %ebx\ncall second\n"
            "add %eax, %ebx\nmov %ebx, %edi\nmov $60, %eax\nsyscall\n"
            "fail:\nmov $1, %edi\nmov $60, %eax\nsyscall\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        objects = []
        for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu")):
            objects.append((self.assemble(provider, f"provider-{suffix}", assembler),
                            self.assemble(caller, f"caller-{suffix}", assembler)))
        for provider_obj, _ in objects:
            for _, caller_obj in objects:
                exe = self.path / f"{provider_obj.stem}-{caller_obj.stem}"
                command("ld", "-o", exe, caller_obj, provider_obj)
                self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_symbol_declarations_reject_invalid_names(self):
        statements = (
            ".globl first,,second", ".global first+second", ".local first second",
            ".weak first,,second", ".hidden first,,second",
            ".protected first+second", ".internal first second",
            "invalid+name: ret", ".equ invalid+name,1",
            ".set invalid+name,1", ".comm invalid+name,4",
            ".lcomm invalid+name,4", ".type invalid+name,@object",
            ".size invalid+name,4",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                source = f".text\n{statement}\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "invalid-symbol.o")],
                                     input=source, capture_output=True, text=True)
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        for statement in ('.globl "quoted name"', ".extern invalid+name"):
            with self.subTest(unsupported=statement):
                self.diagnostic(f".text\n{statement}\n")
        for alias in ("invalid+name@VER", "unversioned"):
            with self.subTest(version_alias=alias):
                source = f".text\nsource: ret\n.symver source,{alias}\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "invalid-version.o")],
                                     input=source, capture_output=True, text=True)
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        source = ".text\nsource: ret\n.symver source,versioned@@@VER\n"
        gnu = subprocess.run(["as", "-o", str(self.path / "gnu-triple-at.o")],
                             input=source, capture_output=True, text=True)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        self.diagnostic(source)

    def test_symbol_expression_relocations(self):
        source = (
            ".text\n"
            "movabs $external + 4, %rax\n"
            "movl $external - 8, %r9d\n"
            "pushq $external + 12\n"
            "movq external + 7(%rip), %r10\n"
            "call external + 3@PLT\n"
            "jmp external - 5\n"
            "je external + 6\n"
            "loop external - 3\n"
            ".data\n.quad external + 11, external - 9\n"
            ".quad external + 9223372036854775807, external - 9223372036854775808\n"
            ".quad tls + 4@TPOFF, tls - 8@DTPOFF\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        ours = self.assemble(source, "expressions-ours")
        gnu = self.assemble(source, "expressions-gnu", "as")
        self.assertEqual(sorted(relocations(ours)), sorted(relocations(gnu)))
        for name in (".text", ".data"):
            outputs = []
            for obj in (ours, gnu):
                binary = self.path / f"{obj.stem}{name}.bin"
                command("objcopy", "--dump-section", f"{name}={binary}", obj)
                outputs.append(binary.read_bytes())
            self.assertEqual(*outputs, msg=f"{name} differs from GNU as")

    def test_symbol_expression_rejects_malformed_operands(self):
        cases = (
            "movq $left+right, %rax", "movq $left-right, %rax",
            "movq $left right, %rax", "pushq $left+right",
            "call target+garbage", "jmp target-garbage",
            "je target+garbage", "loop target+garbage",
            "movq left+right(%rax), %rdx", ".quad left+right",
            ".quad left+right@TPOFF", ".quad left right@DTPOFF",
            ".set alias,left+right",
        )
        for statement in cases:
            with self.subTest(statement=statement):
                source = f".text\n{statement}\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "invalid-expression.o")],
                                     input=source, capture_output=True, text=True)
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        for statement in ("movq $external+9223372036854775808, %rax",
                          "jmp external-9223372036854775809",
                          "loop external-9223372036854775808"):
            with self.subTest(statement=statement):
                self.diagnostic(f".text\n{statement}\n")
        for expression in ("start-end-9223372036854775808",
                           "end-start+9223372036854775807"):
            with self.subTest(expression=expression):
                source = f".data\nstart:\n.byte 0\nend:\n.quad {expression}\n"
                self.assertIn("symbol difference out of range", self.diagnostic(source))

    def test_instruction_differential_matrix(self):
        registers = {
            "b": ("%al", "%bl", "%spl", "%dil", "%r8b", "%r13b"),
            "w": ("%ax", "%bx", "%sp", "%di", "%r8w", "%r13w"),
            "l": ("%eax", "%ebx", "%esp", "%edi", "%r8d", "%r13d"),
            "q": ("%rax", "%rbx", "%rsp", "%rdi", "%r8", "%r13"),
        }
        instructions = []
        for suffix, regs in registers.items():
            for operation in ("mov", "add", "sub", "and", "or", "xor", "cmp"):
                for source in regs:
                    for destination in regs:
                        instructions.append(f"{operation}{suffix} {source}, {destination}")
                for memory in ("(%rax)", "(%r13)", "(%rsp)", "127(%r12,%r9,4)",
                               "-129(%r13,%r15,8)", "external+7(%rip)",
                               "external+8(%r12)"):
                    for register in (regs[1], regs[-1]):
                        instructions.append(f"{operation}{suffix} {register}, {memory}")
                        instructions.append(f"{operation}{suffix} {memory}, {register}")
            for operation in ("add", "sub", "and", "or", "xor", "cmp"):
                for immediate in (-129, -128, -1, 0, 1, 127, 128, 255):
                    if suffix == "b" and immediate < -128:
                        continue
                    for register in (regs[1], regs[2], regs[-1]):
                        instructions.append(f"{operation}{suffix} ${immediate}, {register}")
        for memory in ("(%rax)", "(%r13)", "(%rsp)", "127(%r12,%r9,4)",
                       "-129(%r13,%r15,8)", "external+7(%rip)", "external+8(%r12)"):
            for destination in ("%rbx", "%r13"):
                instructions.append(f"leaq {memory}, {destination}")
        instructions.extend((
            "movb $external, %r8b", "movw $external, %r9w",
            "movl $external, %r10d", "movabsq $external, %r11",
            "movq 0xffffffffffffffff(%rax), %r13",
            "addq %r13, 0xffffffff80000000(%rax)",
            "addl $127, external+8(%rip)", "addq $128, external-4(%rip)",
            "subb $1, external(%rip)", "cmpw $256, external(%rip)",
            "testb $1, external(%rip)", "testl $42, external+4(%rip)",
            "testq $-1, external-4(%rip)",
            "call *%r13", "jmp *%r8", "call *external+8(%rip)",
            "jmp *external-4(%rip)", "call external@PLT", "jmp external@PLT",
            "call external", "jmp external", "je external",
        ))
        source = ".text\n" + "".join(
            f"case{index:04d}:\n{instruction}\n"
            for index, instruction in enumerate(instructions)
        ) + f"case{len(instructions):04d}:\n"
        ours = self.assemble(source, "matrix-ours")
        gnu = self.assemble(source, "matrix-gnu", "as")
        ours_records = instruction_records(ours, len(instructions))
        gnu_records = instruction_records(gnu, len(instructions))
        differences = [
            f"{instruction}: native={native!r}, GNU={reference!r}"
            for instruction, native, reference in zip(instructions, ours_records, gnu_records)
            if native != reference
        ]
        self.assertFalse(bool(differences), f"{len(differences)} encoding/relocation mismatches:\n" +
                         "\n".join(differences[:20]))

    def test_instruction_matrix_rejects_invalid_operands(self):
        for instruction in ("movq %eax, %rax", "movb %al, %rax",
                            "addb %spl, %rax", "addl $1, %rax", "testl $1, %rax",
                            "call *%eax", "jmp *%r8d", "movq 2147483648(%rax), %rcx",
                            "addq %rax, -2147483649(%r13)",
                            "leaq 2147483648(%rip), %rax"):
            with self.subTest(instruction=instruction):
                source = f".text\n{instruction}\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "invalid-gnu.o")],
                                     input=source, capture_output=True, text=True)
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        self.assertIn("branch relocation addend out of range",
                      self.diagnostic(".text\ncall external-9223372036854775808\n"))
        self.assertIn("branch target out of range",
                      self.diagnostic(".text\nnop\nlocal:\njmp local+9223372036854775807\n"))

    def test_memory_operand_encodings(self):
        operands = (
            "(,%rcx)", "(,%r9,4)", "(,%r12,8)", "(,%r13,)",
            "8(,%r9)", "-128(,%r12,2)", "external+8(,%r9,2)",
            "external-4(,%r12,8)", "( %rax , %r9 , 4 )",
            "(%rax,%rcx,1+1)", "(%rax,%rcx,(1<<2))", "4+(3*2)(%r8)",
            "( %r13 )", "(%r13,%r12,8)", "(external+8)(%r13)",
            "(external+4)", "external+4(%rip)",
        )
        instructions = [f"{operation}q {operand}, %r10"
                        for operation in ("mov", "add", "lea")
                        for operand in operands]
        instructions.extend(("movq %r10, 8(,%r9,4)",
                             "movq $42, external+4(,%r12,8)",
                             "call *(,%r9,4)", "movq %fs:8(,%r9,4), %r10",
                             "movq external@GOTPCREL(%rip), %r10",
                             "leaq external@TLSGD(%rip), %r10"))
        registers = ("%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi",
                     "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15")
        for index in (register for register in registers if register != "%rsp"):
            for scale in (1, 2, 4, 8):
                instructions.append(f"movq 16(,{index},{scale}), %r10")
                for base in registers:
                    instructions.append(f"movq 128({base},{index},{scale}), %r10")
        source = ".text\n" + "".join(
            f"case{index:04d}:\n{instruction}\n"
            for index, instruction in enumerate(instructions)
        ) + f"case{len(instructions):04d}:\n"
        ours = self.assemble(source, "memory-ours")
        gnu = self.assemble(source, "memory-gnu", "as")
        native = instruction_records(ours, len(instructions))
        reference = instruction_records(gnu, len(instructions))
        for instruction, actual, expected in zip(instructions, native, reference):
            with self.subTest(instruction=instruction):
                self.assertEqual(actual, expected)

    def test_32_bit_address_encodings_and_relocations(self):
        bases = ("%eax", "%ecx", "%edx", "%ebx", "%esp", "%ebp", "%esi", "%edi",
                 "%r8d", "%r9d", "%r10d", "%r11d", "%r12d", "%r13d", "%r14d", "%r15d")
        instructions = []
        for base in bases:
            for displacement in ("", "127", "-128", "128", "0xffffffff", "external+4"):
                instructions.append(f"movq {displacement}({base}),%r10")
            for index in (reg for reg in bases if reg != "%esp"):
                for scale in (1, 2, 4, 8):
                    instructions.append(f"movl 128({base},{index},{scale}),%r11d")
        instructions.extend(f"movq external(,{index},4),%r10"
                            for index in bases if index != "%esp")
        instructions.extend((
            "movw (%eax),%cx", "movq %r10,(%r8d,%r9d,4)",
            "movl $42,external+4(%eax)", "addq $1,external(%r8d)",
            "leaq external(%eip),%r10", "movq external@GOTPCREL(%eip),%r10",
            "call *external(%eax)", "jmp *(,%r12d,8)",
            "movq %fs:external(%r8d),%r10", "lock xaddl %ecx,%fs:(%eax)",
            "addsd (%eax),%xmm1", "fldl (%r8d)", "movq 0x100000000(%eax),%r10",
            "movq -2147483649(%eax),%r10",
        ))
        source = ".text\n" + "".join(
            f"case{index:04d}:\n{instruction}\n"
            for index, instruction in enumerate(instructions)
        ) + f"case{len(instructions):04d}:\n"
        ours = self.assemble(source, "address32-ours")
        gnu = self.assemble(source, "address32-gnu", "as")
        native = instruction_records(ours, len(instructions))
        reference = instruction_records(gnu, len(instructions))
        differences = [f"{instruction}: native={actual!r}, GNU={expected!r}"
                       for instruction, actual, expected in zip(instructions, native, reference)
                       if actual != expected]
        self.assertFalse(differences, "\n".join(differences[:20]))

    def test_32_bit_address_invalid_operands(self):
        for operand in ("(%eax,%r9)", "(%rax,%r9d)", "(%eip,%eax)",
                        "(,%esp,2)", "(%ax)", "(%al)", "(%r8d,%rsp,2)"):
            with self.subTest(operand=operand):
                source = f".text\nmovq {operand},%rdx\n"
                result = subprocess.run(["as", "-o", str(self.path / "invalid-address.o")],
                                        input=source, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.diagnostic(source)

    def test_32_bit_address_execution(self):
        source = (
            ".data\narray: .long 10,20,30,40\n"
            ".text\n.globl _start\n_start:\n"
            "movl $array,%r8d\nmovabsq $4294967296,%r10\norq %r10,%r8\n"
            "movl $1,%r9d\n"
            "movl 4(%r8d,%r9d,4),%eax\n"
            "movl $12,4(%r8d,%r9d,4)\naddl 4(%r8d,%r9d,4),%eax\n"
            "movl array(%eip),%ecx\ncmpl $10,%ecx\njne fail\n"
            "movl array(,%r9d,4),%ecx\ncmpl $20,%ecx\njne fail\n"
            "movl %eax,%edi\nmovl $60,%eax\nsyscall\n"
            "fail: movl $1,%edi\nmovl $60,%eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        for assembler, suffix in (("as", "gnu"), (ASSEMBLER, "crunch")):
            with self.subTest(assembler=suffix):
                obj = self.assemble(source, f"address32-exec-{suffix}", assembler)
                exe = self.path / f"address32-exec-{suffix}"
                command("ld", "-o", exe, obj)
                self.assertEqual(subprocess.run([str(exe)], timeout=10).returncode, 42)

    def test_memory_operand_rejects_malformed_forms(self):
        operands = (
            "(%rax,%rcx,2,8)", "(%rax,%rcx,8,2)", "(%rax,%rcx,3)",
            "(%rax,,4)", "(%rax,)", "(,)", "()", "(,,4)",
            "(%rip,%r9,4)", "(%rip,%r9)", "(,%rsp,2)",
            "(%rax,%rsp,2)", "(%eax,%r9,4)", "4(%rax)(%rcx)",
            "(%rax)junk", "symbol+other(%rax)", "symbol+(%rax",
        )
        for operand in operands:
            with self.subTest(operand=operand):
                source = f".text\nmovq {operand}, %rdx\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "invalid-memory.o")],
                                     input=source, capture_output=True, text=True)
                self.assertNotEqual(gnu.returncode, 0)
                self.diagnostic(source)
        for operand in ("external+(1)(%r9)", "1+external(%r9)"):
            with self.subTest(unsupported=operand):
                source = f".text\nmovq {operand}, %rdx\n"
                gnu = subprocess.run(["as", "-o", str(self.path / "supported-gnu.o")],
                                     input=source, capture_output=True, text=True)
                self.assertEqual(gnu.returncode, 0, gnu.stderr)
                self.diagnostic(source)

    def test_index_only_memory_execution(self):
        source = (
            ".data\narray:\n.quad 17,42\n"
            ".text\n.globl _start\n_start:\n"
            "movq $1, %r9\n"
            "movq array(,%r9,8), %rdi\n"
            "mov $60, %eax\nsyscall\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        for assembler, name in ((ASSEMBLER, "index-ours"), ("as", "index-gnu")):
            obj = self.assemble(source, name, assembler)
            exe = self.path / f"{name}-program"
            command("ld", "-o", exe, obj)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_branch_distances_and_symbol_bindings(self):
        source = (
            ".text\n"
            "jmp 1f\n.zero 127\n1:\n"
            "je 2f\n.zero 128\n2:\n"
            "3:\n.zero 126\njmp 3b\n"
            "4:\n.zero 127\njne 4b\n"
            "call local\njmp local\nje local\njmp local@PLT\nlocal:\nret\n"
            ".globl exported\ncall exported\njmp exported\nje exported\njmp exported@PLT\n"
            "exported:\nret\n"
            ".weak optional\ncall optional\njmp optional\nje optional\noptional:\nret\n"
        )
        ours = self.assemble(source, "branches-ours")
        gnu = self.assemble(source, "branches-gnu", "as")
        for obj in (ours, gnu):
            output = self.path / f"{obj.stem}.bin"
            command("objcopy", "--dump-section", f".text={output}", obj)
        self.assertEqual((self.path / "branches-ours.bin").read_bytes(),
                         (self.path / "branches-gnu.bin").read_bytes())
        self.assertEqual(sorted(relocations(ours)), sorted(relocations(gnu)))

    def test_loop_local_displacement_boundaries(self):
        cases = (
            ("forward-zero", "{op} target\n.zero 0\ntarget: ret", True, 2),
            ("forward-max", "{op} target\n.zero 127\ntarget: ret", True, 2),
            ("forward-over", "{op} target\n.zero 128\ntarget: ret", False, 2),
            ("forward-addend", "{op} target+1\n.zero 126\ntarget: ret", True, 2),
            ("forward-addend-over", "{op} target+2\n.zero 126\ntarget: ret", False, 2),
            ("backward-min", "target: nop\n.zero 125\n{op} target", True, 4),
            ("backward-over", "target: nop\n.zero 126\n{op} target", False, 4),
            ("backward-addend-over", "target: nop\n.zero 125\n{op} target-1", False, 4),
        )
        for mnemonic in ("loop", "loope", "loopz", "loopne", "loopnz"):
            for name, body, valid, line in cases:
                with self.subTest(mnemonic=mnemonic, case=name):
                    source = ".text\n" + body.format(op=mnemonic) + "\n"
                    if valid:
                        ours = self.assemble(source, f"{mnemonic}-{name}-ours")
                        gnu = self.assemble(source, f"{mnemonic}-{name}-gnu", "as")
                        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
                        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
                        self.assertEqual(relocations(ours), [])
                        self.assertEqual(relocations(gnu), [])
                    else:
                        gnu = subprocess.run(["as", "-o", str(self.path / "loop-invalid.o")],
                                             input=source, capture_output=True, text=True)
                        self.assertNotEqual(gnu.returncode, 0)
                        diagnostic = self.diagnostic(source)
                        self.assertIn(f"<stdin>:{line}: error: loop target is out of range",
                                      diagnostic)

    def test_loop_binding_and_relocations_match_gnu(self):
        source = (
            ".text\n"
            ".local local_target\n"
            "loop local_target+1\nloope exported+2\nloopne weak_target-1\n"
            "loop undefined+4\nloop 1f\nnop\n1:\n"
            ".globl exported\n.weak weak_target\n"
            "local_target: nop\nexported: nop\nweak_target: ret\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        ours = self.assemble(source, "loop-bindings-ours")
        gnu = self.assemble(source, "loop-bindings-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(relocations(ours), relocations(gnu))
        self.assertEqual([entry[1] for entry in relocations(ours)], ["R_X86_64_PC8"] * 3)

        for binding in (".globl", ".weak"):
            with self.subTest(binding=binding):
                distant = f"{binding} target\n.text\nloop target\n.zero 200\ntarget: ret\n"
                ours = self.assemble(distant, f"loop-distant-{binding[1:]}-ours")
                gnu = self.assemble(distant, f"loop-distant-{binding[1:]}-gnu", "as")
                self.assertEqual(relocations(ours), relocations(gnu))

        cross = ".text\nloop target\n.data\ntarget: .byte 0\n"
        ours = self.assemble(cross, "loop-cross-section-ours")
        gnu = self.assemble(cross, "loop-cross-section-gnu", "as")
        self.assertEqual([entry[1] for entry in relocations(ours)], ["R_X86_64_PC8"])
        self.assertEqual([entry[1] for entry in relocations(gnu)], ["R_X86_64_PC8"])
        script = self.path / "loop-sections.ld"
        script.write_text("SECTIONS { . = 0x10000; .text : { *(.text) } "
                          ".data : { *(.data) } }\n")
        code = []
        for obj in (ours, gnu):
            exe = self.path / (obj.stem + "-linked")
            command("ld", "-T", script, "-o", exe, obj)
            header = named_section(exe, ".text")
            code.append(exe.read_bytes()[header[4]:header[4] + header[5]])
        self.assertEqual(*code)

    def test_loop_range_checked_after_branch_relaxation(self):
        valid = (".text\njmp external\n.zero 12\nloop target\n.zero 120\n"
                 ".p2align 4,0\ntarget: ret\n")
        ours = self.assemble(valid, "loop-relax-ours")
        gnu = self.assemble(valid, "loop-relax-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(relocations(ours), relocations(gnu))
        invalid = (".text\nloop target\njmp external\n.zero 124\n"
                   ".p2align 4,0\ntarget: ret\n")
        gnu = subprocess.run(["as", "-o", str(self.path / "loop-relax-invalid.o")],
                             input=invalid, capture_output=True, text=True)
        self.assertNotEqual(gnu.returncode, 0)
        self.assertIn("<stdin>:2: error: loop target is out of range", self.diagnostic(invalid))

    def test_loop_local_and_cross_object_execution(self):
        local = (
            ".text\n.globl _start\n_start:\nxorl %edi, %edi\n"
            "movl $2, %ecx\n1: leaq 1(%rdi), %rdi\nloop 1b\n"
            "movl $2, %ecx\ncmpl %edi, %edi\n2: leaq 1(%rdi), %rdi\nloope 2b\n"
            "movl $2, %ecx\ncmpl %edi, %edi\n3: leaq 1(%rdi), %rdi\nloopz 3b\n"
            "movl $2, %ecx\ncmpl $0, %edi\n4: leaq 1(%rdi), %rdi\nloopne 4b\n"
            "movl $2, %ecx\ncmpl $0, %edi\n5: leaq 1(%rdi), %rdi\nloopnz 5b\n"
            "cmpl $10, %edi\njne fail\nmovl $42, %edi\n"
            "movl $60, %eax\nsyscall\nfail: movl $1, %edi\nmovl $60, %eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        caller = (
            ".text\n.globl _start\n_start:\nmovl $2, %ecx\nloop target\n"
            "movl $1, %edi\nmovl $60, %eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        provider = (
            ".text\n.globl target\ntarget: movl $42, %edi\nmovl $60, %eax\nsyscall\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        pairs = []
        for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu")):
            local_obj = self.assemble(local, f"loop-local-{suffix}", assembler)
            exe = self.path / f"loop-local-{suffix}"
            command("ld", "-o", exe, local_obj)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 42)
            pairs.append((self.assemble(caller, f"loop-caller-{suffix}", assembler),
                          self.assemble(provider, f"loop-provider-{suffix}", assembler)))
        for caller_obj, _ in pairs:
            for _, provider_obj in pairs:
                exe = self.path / f"{caller_obj.stem}-{provider_obj.stem}"
                command("ld", "-o", exe, caller_obj, provider_obj)
                self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_branch_relaxation_alignment_boundaries(self):
        case = 0
        for mnemonic in ("jmp", "je"):
            for lead in (13, 14, 15):
                for gap in (119, 120, 121):
                    for directive in (".p2align 4,0", ".p2align 4,0,2"):
                        with self.subTest(mnemonic=mnemonic, lead=lead, gap=gap,
                                          directive=directive):
                            source = (f".text\n.zero {lead}\n{mnemonic} target\n"
                                      f".zero {gap}\n{directive}\ntarget: ret\n")
                            ours = self.assemble(source, f"branch-align-{case}-ours")
                            gnu = self.assemble(source, f"branch-align-{case}-gnu", "as")
                            native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
                            self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                                             gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
                            case += 1
            for gap in (110, 119, 120, 126, 127, 128):
                for directive in (".p2align 4,0", ".p2align 4,0,2"):
                    with self.subTest(backward=mnemonic, gap=gap, directive=directive):
                        source = (f".text\ntarget: nop\n.zero {gap}\n{directive}\n"
                                  f"{mnemonic} target\n")
                        ours = self.assemble(source, f"branch-align-{case}-ours")
                        gnu = self.assemble(source, f"branch-align-{case}-gnu", "as")
                        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
                        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
                        case += 1

    def test_branch_relaxation_cascades_beyond_sixteen_passes(self):
        count = 24
        events = [(100 * i, "branch", i) for i in range(count)]
        events += [(100 * i + 129 + (i == count - 1), "target", i)
                   for i in range(count)]
        lines, offset = [".text"], 0
        for position, kind, index in sorted(events):
            if position > offset:
                lines.append(f".zero {position - offset}")
                offset = position
            if kind == "branch":
                lines.append(f"branch_{index}: jmp target_{index}")
                offset += 2
            else:
                lines.append(f"target_{index}:")
        lines.append("ret")
        source = "\n".join(lines) + "\n"
        ours = self.assemble(source, "branch-cascade-ours")
        gnu = self.assemble(source, "branch-cascade-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        text = ours.read_bytes()[native[4]:native[4] + native[5]]
        self.assertEqual(text, gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        symbols = symbol_records(ours)
        for index in range(count):
            self.assertEqual(text[symbols[f"branch_{index}"][0]], 0xe9)

    def test_branch_relaxation_addends_and_external_cascade(self):
        sources = [
            f".text\n{mnemonic} target{addend}\n.zero 126\ntarget: ret\n"
            for mnemonic in ("jmp", "je") for addend in ("-1", "+1", "+2")
        ]
        sources.append(".text\nje target\njmp external\n.zero 124\n"
                       ".p2align 4,0\ntarget: ret\n")
        for index, source in enumerate(sources):
            with self.subTest(source=source):
                ours = self.assemble(source, f"branch-addend-{index}-ours")
                gnu = self.assemble(source, f"branch-addend-{index}-gnu", "as")
                native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
                self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                                 gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
                self.assertEqual(relocations(ours), relocations(gnu))

    def test_branch_relaxation_alignment_execution(self):
        for mnemonic, prefix, lead in (("jmp", "", 14), ("je", "xorl %eax, %eax\n", 12)):
            source = (
                f".text\n.zero {lead}\n.globl _start\n_start:\n{prefix}"
                f"{mnemonic} target\n.zero 120\n.p2align 4,0\n"
                "target: movl $42, %edi\nmovl $60, %eax\nsyscall\n"
                '.section .note.GNU-stack,"",@progbits\n'
            )
            for assembler, suffix in ((ASSEMBLER, "ours"), ("as", "gnu")):
                with self.subTest(mnemonic=mnemonic, assembler=suffix):
                    obj = self.assemble(source, f"branch-exec-{mnemonic}-{suffix}", assembler)
                    exe = self.path / f"branch-exec-{mnemonic}-{suffix}"
                    command("ld", "-o", exe, obj)
                    self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_byte_register_and_immediate_relocation_execution(self):
        source = (
            ".text\n.globl _start\n_start:\n"
            "movb $value, %dil\nmovw $value, %r9w\n"
            "cmpw $42, %r9w\njne fail\n"
            "testb $1, data_value(%rip)\njz fail\n"
            "movb $1, %al\naddb %al, %dil\nsubb %al, %dil\n"
            "addb $1, %dil\nsubb $1, %dil\n"
            "mov $60, %eax\nsyscall\n"
            "fail:\nmov $1, %edi\nmov $60, %eax\nsyscall\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        definition = self.assemble(
            ".globl value\n.equ value,42\n.data\n.globl data_value\n"
            "data_value:\n.byte 1,0\n", "value"
        )
        for assembler, name in ((ASSEMBLER, "byte-ours"), ("as", "byte-gnu")):
            obj = self.assemble(source, name, assembler)
            exe = self.path / f"{name}-program"
            command("ld", "-o", exe, obj, definition)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_global_function_call_interposition(self):
        source = (
            ".text\n.globl entry\n.type entry,@function\nentry:\n"
            "subq $8, %rsp\ncall target\naddq $8, %rsp\nret\n"
            ".globl target\n.type target,@function\ntarget:\nmovl $1, %eax\nret\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        obj = self.assemble(source, "interposition")
        lib = self.path / "libinterposition.so"
        command("cc", "-shared", obj, "-o", lib)
        main, override = self.path / "main.c", self.path / "override.c"
        main.write_text("extern int entry(void); int main(void) { return entry(); }\n")
        override.write_text("int target(void) { return 42; }\n")
        preload = self.path / "override.so"
        command("cc", "-shared", "-fPIC", override, "-o", preload)
        exe = self.path / "interposition-program"
        command("cc", main, lib, f"-Wl,-rpath,{self.path}", "-o", exe)
        result = subprocess.run([str(exe)], env={**os.environ, "LD_PRELOAD": str(preload)},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_gotpcrel_implicit_got_symbol(self):
        source = ".text\nmovq external@GOTPCREL(%rip),%rax\nret\n"
        native = self.assemble(source, "got-native")
        gnu = self.assemble(source, "got-gnu", "as")
        native_symbols, gnu_symbols = symbol_records(native), symbol_records(gnu)
        self.assertEqual(native_symbols["_GLOBAL_OFFSET_TABLE_"],
                         gnu_symbols["_GLOBAL_OFFSET_TABLE_"])
        self.assertEqual(relocations(native), relocations(gnu))
        plain = self.assemble(".text\nret\n", "no-got")
        self.assertNotIn("_GLOBAL_OFFSET_TABLE_", symbol_records(plain))

    def test_pic_shared_library_interoperability(self):
        provider = (
            ".data\n.globl shared_data\n.type shared_data,@object\n"
            "shared_data: .long 5\n.size shared_data,.-shared_data\n"
            ".globl hidden_data\n.hidden hidden_data\n.type hidden_data,@object\n"
            "hidden_data: .long 7\n.size hidden_data,.-hidden_data\n"
            ".text\n.globl target\n.type target,@function\n"
            "target: movl $10,%eax\nret\n.size target,.-target\n"
            ".globl hidden_function\n.hidden hidden_function\n.type hidden_function,@function\n"
            "hidden_function: movl $11,%eax\nret\n.size hidden_function,.-hidden_function\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        consumer = (
            ".text\n.globl get_data\n.type get_data,@function\nget_data:\n"
            "movq shared_data@GOTPCREL(%rip),%rax\nmovl (%rax),%eax\nret\n"
            ".size get_data,.-get_data\n"
            ".globl set_data\n.type set_data,@function\nset_data:\n"
            "movq shared_data@GOTPCREL(%rip),%rax\nmovl %edi,(%rax)\nret\n"
            ".size set_data,.-set_data\n"
            ".globl calculate\n.type calculate,@function\ncalculate:\n"
            "pushq %rbx\n"
            "movq shared_data@GOTPCREL(%rip),%rax\nmovl (%rax),%ebx\n"
            "addl hidden_data(%rip),%ebx\n"
            "movq external_data@GOTPCREL(%rip),%rax\naddl (%rax),%ebx\n"
            "call target@PLT\naddl %eax,%ebx\n"
            "call hidden_function\naddl %eax,%ebx\n"
            "call external_function@PLT\naddl %ebx,%eax\npopq %rbx\nret\n"
            ".size calculate,.-calculate\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        runner = self.path / "shared-runner.c"
        runner.write_text(
            "#include <dlfcn.h>\n#include <stdio.h>\n#include <stdlib.h>\n"
            "int external_data = 3;\nint external_function(void) { return 4; }\n"
            "int main(int argc, char **argv) {\n"
            "  if (argc != 4) return 1;\n"
            "  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);\n"
            "  if (!handle) { fprintf(stderr, \"%s\\n\", dlerror()); return 2; }\n"
            "  int (*calculate)(void) = dlsym(handle, \"calculate\");\n"
            "  int (*get_data)(void) = dlsym(handle, \"get_data\");\n"
            "  void (*set_data)(int) = dlsym(handle, \"set_data\");\n"
            "  int *data = dlsym(handle, \"shared_data\");\n"
            "  if (!calculate || !get_data || !set_data || !data || *data != 5) return 3;\n"
            "  if (dlsym(handle, \"hidden_data\") || dlsym(handle, \"hidden_function\")) return 4;\n"
            "  if (calculate() != atoi(argv[2])) return 5;\n"
            "  set_data(9);\n"
            "  if (get_data() != 9 || calculate() != atoi(argv[3])) return 6;\n"
            "  return dlclose(handle) != 0;\n"
            "}\n"
        )
        override = self.path / "shared-override.c"
        override.write_text(
            "int shared_data = 20;\nint hidden_data = 100;\n"
            "int target(void) { return 30; }\nint hidden_function(void) { return 100; }\n"
        )
        executable, preload = self.path / "shared-runner", self.path / "shared-override.so"
        command("cc", "-std=c11", "-rdynamic", runner, "-ldl", "-o", executable)
        command("cc", "-shared", "-fPIC", override, "-o", preload)
        env = {key: value for key, value in os.environ.items()
               if key not in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")}
        reference_relocations = None
        for assembler, suffix in (("as", "gnu"), (ASSEMBLER, "crunch")):
            with self.subTest(assembler=suffix):
                provider_obj = self.assemble(provider, f"shared-provider-{suffix}", assembler)
                consumer_obj = self.assemble(consumer, f"shared-consumer-{suffix}", assembler)
                entries = relocations(consumer_obj)
                important = [(kind, symbol, addend) for _, kind, symbol, addend in entries]
                self.assertIn(("R_X86_64_REX_GOTPCRELX", "shared_data", -4), important)
                self.assertIn(("R_X86_64_REX_GOTPCRELX", "external_data", -4), important)
                self.assertIn(("R_X86_64_PLT32", "target", -4), important)
                self.assertIn(("R_X86_64_PLT32", "external_function", -4), important)
                if reference_relocations is None:
                    reference_relocations = entries
                else:
                    self.assertEqual(entries, reference_relocations)
                symbols = symbol_records(provider_obj)
                self.assertEqual(symbols["hidden_data"][4], "HIDDEN")
                self.assertEqual(symbols["hidden_function"][4], "HIDDEN")
                library = self.path / f"libshared-{suffix}.so"
                command("ld", "-shared", "-z", "text", "-o", library,
                        consumer_obj, provider_obj)
                header = command("readelf", "-hW", library).stdout
                self.assertRegex(header, r"Type:\s+DYN\b")
                dynamic = command("readelf", "-rW", library).stdout
                for kind, name in (("GLOB_DAT", "shared_data"), ("GLOB_DAT", "external_data"),
                                   ("JUMP_SLOT", "target"), ("JUMP_SLOT", "external_function")):
                    self.assertRegex(dynamic, rf"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+\s+"
                                              rf"R_X86_64_{kind}\s+.*\b{name}\b")
                for name in ("hidden_data", "hidden_function"):
                    self.assertNotIn(name, dynamic)
                for preload_path, before, after in ((None, 40, 44), (preload, 75, 64)):
                    test_env = dict(env)
                    if preload_path:
                        test_env["LD_PRELOAD"] = str(preload_path)
                    result = subprocess.run([str(executable), str(library), str(before), str(after)],
                                            env=test_env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0,
                                     f"{suffix}, preload={preload_path}: {result.stderr}")
                native_library = self.path / f"libshared-native-{suffix}.so"
                command(ASSEMBLER.parent / "crunch-ld", "-nostdlib", "-shared", "-o", native_library,
                        consumer_obj, provider_obj)
                dynamic = command("readelf", "-rW", native_library).stdout
                for name in ("shared_data", "external_data", "target", "external_function"):
                    self.assertRegex(dynamic, rf"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+\s+"
                                              rf"R_X86_64_GLOB_DAT\s+.*\b{name}\b")
                for preload_path, before, after in ((None, 40, 44), (preload, 75, 64)):
                    test_env = dict(env)
                    if preload_path:
                        test_env["LD_PRELOAD"] = str(preload_path)
                    result = subprocess.run([str(executable), str(native_library), str(before), str(after)],
                                            env=test_env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0,
                                     f"native linker, {suffix}, preload={preload_path}: {result.stderr}")

    def test_native_linker_shared_dependency_interoperability(self):
        provider_source = (".text\n.globl answer\n.type answer,@function\n"
                           "answer: movl $42,%eax\nret\n"
                           '.section .note.GNU-stack,"",@progbits\n')
        consumer_source = (".text\n.globl query\n.type query,@function\n"
                           "query: jmp answer@PLT\n"
                           '.section .note.GNU-stack,"",@progbits\n')
        native_ld = ASSEMBLER.parent / "crunch-ld"
        env = {key: value for key, value in os.environ.items()
               if key not in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")}
        env["LD_LIBRARY_PATH"] = str(self.path)
        for assembler in ("as", ASSEMBLER):
            provider = self.assemble(provider_source, f"dep-{pathlib.Path(assembler).name}", assembler)
            consumer = self.assemble(consumer_source, f"use-{pathlib.Path(assembler).name}", assembler)
            for provider_linker in ("ld", native_ld):
                library = self.path / "libdep.so.1"
                output = self.path / "libuser.so"
                command(provider_linker, "-nostdlib", "-shared", "-soname", "libdep.so.1",
                        "-o", library, provider)
                command(native_ld, "-nostdlib", "-shared", "-o", output, consumer, library)
                dynamic = command("readelf", "-dW", output).stdout
                self.assertIn("Shared library: [libdep.so.1]", dynamic)
                result = subprocess.run(
                    [sys.executable, "-c",
                     "import ctypes,sys; assert ctypes.CDLL(sys.argv[1]).query() == 42", str(output)],
                    env=env, capture_output=True, text=True, timeout=30
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_linker_shared_data_relocation_interoperability(self):
        source = (
            '.section .data.rel.ro,"aw",@progbits\n'
            ".globl ptr\nptr: .quad external_array+4\n"
            ".globl weak_ptr\n.weak absent\nweak_ptr: .quad absent\n"
            "local_value: .long 19\n"
            ".globl local_ptr\nlocal_ptr: .quad local_value\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        provider_source = (
            ".data\n.globl external_array\nexternal_array: .long 20,42\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        native_ld = ASSEMBLER.parent / "crunch-ld"
        env = {key: value for key, value in os.environ.items()
               if key not in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")}
        env["LD_LIBRARY_PATH"] = str(self.path)
        provider = self.assemble(provider_source, "data-provider", "as")
        command("ld", "-shared", "-soname", "data-provider.so",
                "-o", self.path / "data-provider.so", provider)
        for assembler in ("as", ASSEMBLER):
            obj = self.assemble(source, f"data-{pathlib.Path(assembler).name}", assembler)
            for linker in ("ld", native_ld):
                output = self.path / "data-consumer.so"
                command(linker, "-nostdlib", "-shared", "-o", output, obj, self.path / "data-provider.so")
                relocations = command("readelf", "-rW", output).stdout
                self.assertIn("R_X86_64_RELATIVE", relocations)
                self.assertIn("R_X86_64_64", relocations)
                result = subprocess.run(
                    [sys.executable, "-c",
                     "import ctypes,sys; l=ctypes.CDLL(sys.argv[1]); "
                     "p=lambda n: ctypes.c_void_p.in_dll(l,n).value; "
                     "assert ctypes.c_int.from_address(p('ptr')).value == 42; "
                     "assert ctypes.c_int.from_address(p('local_ptr')).value == 19; "
                     "assert p('weak_ptr') is None", str(output)],
                    env=env, capture_output=True, text=True, timeout=30
                )
                self.assertEqual(result.returncode, 0,
                                 f"{assembler}, {linker}: {result.stderr}")

    def test_native_linker_shared_constructor_interoperability(self):
        source = self.path / "constructors.c"
        source.write_text(
            "extern void record(int);\n"
            "__attribute__((constructor(200))) static void init2(void) { record(2); }\n"
            "__attribute__((constructor(101))) static void init1(void) { record(1); }\n"
            "__attribute__((constructor)) static void init3(void) { record(3); }\n"
            "__attribute__((destructor(101))) static void fini6(void) { record(6); }\n"
            "__attribute__((destructor)) static void fini4(void) { record(4); }\n"
            "__attribute__((destructor(200))) static void fini5(void) { record(5); }\n"
        )
        assembly = self.path / "constructors.s"
        command("cc", "-S", "-fPIC", "-fno-stack-protector",
                "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
                "-o", assembly, source)
        provider_source = (
            ".data\n.hidden log_value\nlog_value: .long 0\n"
            ".text\n.globl record\nrecord: movl log_value(%rip),%eax\n"
            "imull $10,%eax,%eax\naddl %edi,%eax\nmovl %eax,log_value(%rip)\nret\n"
            ".globl get_log\nget_log: movl log_value(%rip),%eax\nret\n"
            '.section .note.GNU-stack,"",@progbits\n'
        )
        provider = self.assemble(provider_source, "constructor-provider", "as")
        command("ld", "-shared", "-soname", "constructor-provider.so", "-o",
                self.path / "constructor-provider.so", provider)
        native_ld = ASSEMBLER.parent / "crunch-ld"
        env = {key: value for key, value in os.environ.items()
               if key not in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")}
        env["LD_LIBRARY_PATH"] = str(self.path)
        code = "\n".join(line for line in assembly.read_text().splitlines()
                         if not line.strip().startswith((".file", ".ident"))) + (
                             "\n.text\ninit_nine: subq $8,%rsp\nmovl $9,%edi\n"
                             "call record@PLT\naddq $8,%rsp\nret\n"
                             '.section .init_array.65535,"aw"\n.quad init_nine\n'
                         )
        for assembler in ("as", ASSEMBLER):
            obj = self.assemble(code, f"constructors-{pathlib.Path(assembler).name}",
                                assembler)
            sections = command("readelf", "-SW", obj).stdout
            self.assertRegex(sections, r"\.init_array\.00101\s+INIT_ARRAY")
            self.assertRegex(sections, r"\.fini_array\.00101\s+FINI_ARRAY")
            for linker in ("ld", native_ld):
                output = self.path / "constructors.so"
                command(linker, "-nostdlib", "-shared", "-o", output, obj, self.path / "constructor-provider.so")
                result = subprocess.run(
                    [sys.executable, "-c",
                     "import _ctypes,ctypes,sys; p=ctypes.CDLL(sys.argv[1],mode=ctypes.RTLD_GLOBAL); "
                     "l=ctypes.CDLL(sys.argv[2]); assert p.get_log()==1293; "
                     "_ctypes.dlclose(l._handle); assert p.get_log()==1293456",
                     str(self.path / "constructor-provider.so"), str(output)],
                    env=env, capture_output=True, text=True, timeout=30
                )
                self.assertEqual(result.returncode, 0,
                                 f"{assembler}, {linker}: {result.stderr}")

    def test_mov_immediate_to_memory_matches_gnu(self):
        source = (
            ".text\n"
            "movb $-128, (%rax)\n"
            "movb $255, 7(%r12,%r15,4)\n"
            "movw $65535, -128(%rbp)\n"
            "movw $-32768, 0(%r13)\n"
            "movl $4294967295, 128(%rsp)\n"
            "movl $-2147483648, 12(%rip)\n"
            "movq $2147483647, (%r8)\n"
            "movq $-2147483648, -8(%r13,%r9,8)\n"
            "movq $0xffffffffffffffff, (%rax)\n"
            "movq $0xffffffff80000000, (%rax)\n"
            "movl $1, 0xffffffffffffffff(%rax)\n"
            "movl $1, 0xffffffff80000000(%rax)\n"
            "movl $1, 2147483647(%rax)\n"
            "movl $1, -2147483648(%rip)\n"
            "movb $imm-1, target+3(%rip)\n"
            "movw $imm+2, target+3(%rip)\n"
            "movl $imm+4, target+3(%rip)\n"
            "movq $imm-8, target+3(%rip)\n"
            "movl $imm+4, target(%r12)\n"
        )
        ours = self.assemble(source, "mov-memory-ours")
        gnu = self.assemble(source, "mov-memory-gnu", "as")
        binaries = []
        for obj in (ours, gnu):
            binary = self.path / f"{obj.stem}.bin"
            command("objcopy", "--dump-section", f".text={binary}", obj)
            binaries.append(binary.read_bytes())
        self.assertEqual(*binaries)
        self.assertEqual(relocations(ours), relocations(gnu))

    def test_mov_immediate_to_memory_rejects_out_of_range(self):
        invalid = (
            "movb $-129, (%rax)", "movb $256, (%rax)",
            "movw $-32769, (%rax)", "movw $65536, (%rax)",
            "movl $-2147483649, (%rax)", "movl $4294967296, (%rax)",
            "movq $-2147483649, (%rax)", "movq $2147483648, (%rax)",
            "movq $0xffffffff, (%rax)", "movq $0xffffffff7fffffff, (%rax)",
        )
        for instruction in invalid:
            with self.subTest(instruction=instruction):
                self.assertIn("mov memory immediate out of range",
                              self.diagnostic(f".text\n{instruction}\n"))
        self.assertIn("invalid or out-of-range integer immediate",
                      self.diagnostic(".text\nmovq $0x10000000000000000, (%rax)\n"))
        self.assertIn("movabs does not support",
                      self.diagnostic(".text\nmovabs $1, (%rax)\n"))
        self.assertIn("invalid operand",
                      self.diagnostic(".text\nmovq $left+right, (%rax)\n"))
        for displacement in ("2147483648", "-2147483649", "4294967295",
                             "0xffffffff7fffffff"):
            with self.subTest(displacement=displacement):
                self.assertIn("mov memory displacement out of range",
                              self.diagnostic(f".text\nmovl $1, {displacement}(%rax)\n"))
        self.assertIn("invalid operand",
                      self.diagnostic(".text\nmovl $1, 0x10000000000000000(%rax)\n"))
        self.assertIn("invalid operand",
                      self.diagnostic(".text\nmovl $1, left+right(%rax)\n"))
        self.assertIn("RIP-relative relocation addend out of range",
                      self.diagnostic(".text\nmovl $1, dest-9223372036854775808(%rip)\n"))

    def test_mov_immediate_to_memory_execution(self):
        source = (
            ".data\nvalue:\n.quad 0\n.long 0\n"
            ".text\n.globl _start\n_start:\n"
            "movq $0xffffffff80000000, value(%rip)\n"
            "movq value(%rip), %rax\ncmpq $-2147483648, %rax\njne fail\n"
            "movl $42, value+8(%rip)\nmovl value+8(%rip), %edi\n"
            "mov $60, %eax\nsyscall\n"
            "fail:\nmov $1, %edi\nmov $60, %eax\nsyscall\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        obj = self.assemble(source, "mov-memory-execution")
        executable = self.path / "mov-memory-program"
        command("ld", "-o", executable, obj)
        self.assertEqual(subprocess.run([str(executable)]).returncode, 42)

    @unittest.skip("requires the full Crunch runtime")
    def test_mov_immediate_in_runtime_object(self):
        runtime_obj = self.path / "clearerr.o"
        command(ASSEMBLER, "-o", runtime_obj, ROOT / "lib/clearerr.s")
        main = self.assemble(
            ".data\nerrno_slot: .long 0\nstream: .quad 0\n.long 7\n"
            ".text\n.globl _start\n_start:\n"
            "xor %edi, %edi\ncall __crunch_clearerr\n"
            "movl errno_slot(%rip), %eax\ncmp $22, %eax\njne fail\n"
            "lea stream(%rip), %rdi\ncall __crunch_clearerr\n"
            "movl stream+8(%rip), %edi\nadd $38, %edi\n"
            "mov $60, %eax\nsyscall\n"
            "fail:\nmov $1, %edi\nmov $60, %eax\nsyscall\n"
            ".globl _crunch_errno_location\n_crunch_errno_location:\n"
            "lea errno_slot(%rip), %rax\nret\n"
            ".section .note.GNU-stack,\"\",@progbits\n", "clearerr-main"
        )
        executable = self.path / "clearerr-program"
        command("ld", "-o", executable, main, runtime_obj)
        self.assertEqual(subprocess.run([str(executable)]).returncode, 42)

    def test_runtime_instruction_encodings(self):
        source = (
            ".text\n"
            "cmpb $'=', (%r10)\ncmpb $'#', (%r10)\ncmpb $'1', (%r10)\n"
            "cmpb $'\\n', (%r10)\ncmp $'+', %dl\n"
            "addb (%r12), %r9b\ncmpq 48(%r13), %rax\n"
            "subl external(%rip), %r9d\n"
            "imul $10, %rcx\nimul $1000, external(%rip), %r9\n"
            "cmova %rsi, %rcx\ncmovb %r13, %r8\ncmovaew %r9w, %r10w\n"
            "movabs $0x8000000000000000, %rax\n"
            "movq %xmm8, %r9\nmovq %r9, %xmm8\n"
            "movq (%r12), %xmm9\nmovq %xmm9, (%r12)\nmovq %xmm9, %xmm8\n"
            "ucomisd %xmm8, %xmm9\nucomisd external(%rip), %xmm9\n"
            "mulsd %xmm8, %xmm9\naddsd (%r12), %xmm9\n"
            "subsd external(%rip), %xmm9\ndivsd %xmm8, %xmm9\n"
            "pxor %xmm8, %xmm9\ncvttsd2siq %xmm8, %r9\n"
            "cvttsd2sil (%r12), %r9d\n"
            "cvtsi2sdq %r9, %xmm10\ncvtsi2sdl %r9d, %xmm10\n"
            "cvtsi2sdq external(%rip), %xmm10\ncltd\n"
            "ucomiss %xmm8, %xmm9\nucomiss external(%rip), %xmm9\n"
            "mulss %xmm8, %xmm9\naddss (%r12), %xmm9\n"
            "subss external(%rip), %xmm9\ndivss %xmm8, %xmm9\n"
            "cvtss2sd %xmm8, %xmm9\ncvtsd2ss external(%rip), %xmm9\n"
            "cvtsi2ssq %r9, %xmm10\ncvtsi2ssl %r9d, %xmm10\n"
            "cvtsi2ssq external(%rip), %xmm10\n"
            "stmxcsr 4(%r12)\nldmxcsr external(%rip)\n"
            "fldl 8(%rsp)\nfstpl (%rsp)\nfyl2x\nfld %st(0)\n"
            "frndint\nfxch %st(1)\nfsub %st(1), %st\n"
            "f2xm1\nfld1\nfaddp\nfscale\nfstp %st(1)\n"
        )
        ours = self.assemble(source, "runtime-instructions-ours")
        gnu = self.assemble(source, "runtime-instructions-gnu", "as")
        binaries = []
        for obj in (ours, gnu):
            binary = self.path / f"{obj.stem}.bin"
            command("objcopy", "--dump-section", f".text={binary}", obj)
            binaries.append(binary.read_bytes())
        self.assertEqual(*binaries)
        self.assertEqual(relocations(ours), relocations(gnu))
        for instruction in ("movq %xmm0, %eax", "mulsd %rax, %xmm0",
                            "ucomisd %xmm0, %rax", "fld %st(8)",
                            "fsub %st(1), %st(2)", "cmova %eax, %rcx",
                            "mov $'ab', %eax", "cvtsi2sdq %eax, %xmm0",
                            "cvtsi2sdl %rax, %xmm0", "subsd %rax, %xmm0",
                            "addss %rax, %xmm0", "ucomiss %xmm0, %rax",
                            "cvtsi2ssq %eax, %xmm0", "cvtss2sd %xmm0, %rax",
                            "stmxcsr %eax", "ldmxcsr %xmm0"):
            with self.subTest(instruction=instruction):
                self.diagnostic(f".text\n{instruction}\n")

    def test_implicit_shift_and_cqto_match_gnu(self):
        source = (
            ".text\n"
            "shr %rcx\nshrl %eax\nshrb %sil\nshrq (%r8)\n"
            "rolb %r9b\nrorw %r10w\nrcll %r11d\nrcrq %r12\n"
            "shll external(%rip)\nsarq 8(%r13)\nsalb %al\n"
            "cqto\ncqo\n"
        )
        ours = self.assemble(source, "implicit-shifts-ours")
        gnu = self.assemble(source, "implicit-shifts-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(relocations(ours), relocations(gnu))
        for instruction in ("shr", "shr $1", "shr %rax,%rbx,%rcx", "cqto %rax"):
            with self.subTest(instruction=instruction):
                source = f".text\n{instruction}\n"
                gnu_result = subprocess.run(
                    ["as", "-o", str(self.path / "invalid-shift.o")],
                    input=source, capture_output=True, text=True
                )
                self.assertNotEqual(gnu_result.returncode, 0)
                self.diagnostic(source)

    def test_mov_extend_byte_registers_match_gnu(self):
        source_regs = ("%al", "%cl", "%dl", "%bl", "%spl", "%bpl", "%sil", "%dil",
                       "%r8b", "%r9b", "%r15b")
        dest_regs = (("w", "%ax", "%r9w"), ("l", "%eax", "%r9d"),
                     ("q", "%rax", "%r9"))
        instructions = [
            f"mov{extend}b{suffix} {src}, {dst}"
            for extend in ("z", "s")
            for suffix, low, high in dest_regs
            for dst in (low, high)
            for src in source_regs
        ]
        instructions.extend(("movzbl (%rdi), %eax", "movsbl (%r8), %eax",
                             "movzwl (%rdi), %eax", "movswl (%r8), %eax",
                             "movzbl external(%rip), %esi"))
        source = ".text\n" + "\n".join(instructions) + "\n"
        ours = self.assemble(source, "mov-extend-ours")
        gnu = self.assemble(source, "mov-extend-gnu", "as")
        native, reference = named_section(ours, ".text"), named_section(gnu, ".text")
        self.assertEqual(ours.read_bytes()[native[4]:native[4] + native[5]],
                         gnu.read_bytes()[reference[4]:reference[4] + reference[5]])
        self.assertEqual(relocations(ours), relocations(gnu))

    @unittest.skip("requires the full Crunch runtime")
    def test_native_strchr_byte_argument(self):
        runtime = self.path / "strchr.o"
        command(ASSEMBLER, "-o", runtime, ROOT / "lib/strchr.s")
        main = self.assemble(
            '.section .rodata\ntext: .asciz "abc"\n'
            ".text\n.globl _start\n_start:\n"
            "leaq text(%rip), %rdi\nmov $98, %esi\ncall __crunch_strchr\n"
            "leaq text+1(%rip), %rcx\ncmp %rcx, %rax\njne fail\n"
            "leaq text(%rip), %rdi\nmov $122, %esi\ncall __crunch_strchr\n"
            "test %rax, %rax\njne fail\n"
            "leaq text(%rip), %rdi\nxor %esi, %esi\ncall __crunch_strchr\n"
            "leaq text+3(%rip), %rcx\ncmp %rcx, %rax\njne fail\n"
            "mov $42, %edi\nmov $60, %eax\nsyscall\n"
            "fail: mov $1, %edi\nmov $60, %eax\nsyscall\n",
            "strchr-execution"
        )
        exe = self.path / "strchr-execution"
        command("ld", "-o", exe, main, runtime)
        self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    @unittest.skip("requires the full Crunch compiler")
    def test_generated_unsigned_and_bitwise_programs(self):
        driver = ASSEMBLER.parent / "crunch"
        for source in (ROOT / "tests/fixtures/units/types/unsigned_runtime.bc",
                       ROOT / "tests/fixtures/units/expressions/hex_bitwise.bc"):
            with self.subTest(source=source.name):
                exe = self.path / "generated-program"
                command(driver, "--with-crunch-as", source, "-o", exe)
                self.assertEqual(subprocess.run([str(exe)]).returncode, 42)

    def test_section_aliases_and_full_width_data(self):
        source = (
            ".data\n.globl base\n.globl alias\n.hidden alias\n"
            ".type base,@object\n.size base,16\nbase:\n"
            ".quad 0x8000000000000000, 0xffffffffffffffff\n"
            ".set alias, base+8\n.set earlier, alias-8\n"
            ".type override,@function\n.size override,7\n.set override,base\n"
            ".quad alias\n"
            ".text\n.globl _start\n_start:\n"
            "movq alias(%rip), %rax\ncmpq $-1, %rax\njne fail\n"
            "mov $42, %edi\nmov $60, %eax\nsyscall\n"
            "fail:\nmov $1, %edi\nmov $60, %eax\nsyscall\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        ours = self.assemble(source, "alias-ours")
        gnu = self.assemble(source, "alias-gnu", "as")
        for obj in (ours, gnu):
            exe = self.path / f"{obj.stem}-program"
            command("ld", "-o", exe, obj)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 42)
        for name in ("base", "alias", "earlier", "override"):
            records = []
            for obj in (ours, gnu):
                text = command("readelf", "-sW", obj).stdout
                match = re.search(
                    r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+"
                    r"(\S+)\s+(\S+)\s+" + name + r"$", text, re.MULTILINE
                )
                self.assertIsNotNone(match)
                value, size, kind, bind, visibility, index = match.groups()
                records.append((int(value, 16), int(size), kind, bind, visibility,
                                symbol_section(obj, index)))
            self.assertEqual(*records)
        self.assertIn("already-resolved", self.diagnostic(".set a, missing+1\n"))
        self.assertIn("out of range", self.diagnostic(".data\nbase:\n.set a, base-1\n"))
        self.assertIn("out-of-range data integer",
                      self.diagnostic(".data\n.quad 0x10000000000000000\n"))

    def test_nobits_zero_and_init_array(self):
        source = (
            ".bss\n.balign 8\n.globl value\nvalue:\n.byte 0\n.word 0\n.long 0\n.quad 0\n"
            ".text\ninitializer:\nmovl $42, value(%rip)\nret\n"
            ".section .init_array,\"aw\",@init_array\n.balign 8\n.quad initializer\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        main = self.path / "main.c"
        main.write_text("extern int value; int main(void) { return value != 42; }\n")
        headers = []
        for assembler, name in ((ASSEMBLER, "nobits-ours"), ("as", "nobits-gnu")):
            obj = self.assemble(source, name, assembler)
            data = obj.read_bytes()
            count, shstr_index = struct.unpack_from("<HH", data, 60)
            names = string_table(data, section(data, shstr_index))
            found = {}
            for index in range(count):
                header = section(data, index)
                start = header[0]
                found[names[start:names.index(b"\0", start)].decode()] = header
            headers.append([(found[key][1], found[key][2], found[key][5],
                             found[key][8], found[key][9])
                            for key in (".bss", ".init_array")])
            exe = self.path / f"{name}-program"
            command("cc", "-no-pie", main, obj, "-o", exe)
            command(exe)
        self.assertEqual(*headers)
        for value in (".byte 1", ".long -1", ".quad missing", ".quad end-start"):
            with self.subTest(value=value):
                self.diagnostic(f".bss\n{value}\n")

    @unittest.skip("requires the full Crunch compiler and runtime")
    def test_runtime_assembly_and_execution(self):
        sources = sorted((ROOT / "lib").rglob("*.s"))
        self.assertTrue(sources)
        generated = self.path / "format_extended.s"
        expanded = self.path / "format_extended.pp"
        ir = self.path / "format_extended.bir"
        expanded.write_text(command(ASSEMBLER.parent / "crunch-pp", "-I", ROOT / "include",
                                    ROOT / "lib/format_extended.bc").stdout)
        ir.write_text(command(ASSEMBLER.parent / "crunch-ir", "--module", expanded).stdout)
        generated.write_text(command(ASSEMBLER.parent / "crunch-asm", ir).stdout)
        sources.append(generated)
        self.assertEqual(len({source.stem for source in sources}), len(sources))
        objects = []
        for source in sources:
            obj = self.path / f"{source.stem}.o"
            command(ASSEMBLER, "-o", obj, source)
            gnu_obj = self.path / "gnu.o"
            command("as", "-o", gnu_obj, source)
            undefined = []
            for candidate in (obj, gnu_obj):
                text = command("nm", "-u", candidate).stdout
                undefined.append({line.split()[-1] for line in text.splitlines() if line.split()})
            self.assertEqual(*undefined, msg=f"undefined symbols differ for {source}")
            linked = self.path / "linked.o"
            self.assertEqual(command("ld", "-r", "-o", linked, obj).stderr, "")
            objects.append(obj)
        archive = self.path / "libcrunch.a"
        command("ar", "rcs", archive, *objects)
        executable = self.path / "runtime-test"
        for fixture, extra in (
            ("expressions/power_helper.c", ["-lm"]),
            ("library/stdio_open_internal.c", []),
            ("library/allocator_pool.c", ["-Wl,--wrap=_crunch_mmap,--wrap=_crunch_munmap"]),
        ):
            command("cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    ROOT / "tests/fixtures/units" / fixture, archive, *extra, "-o", executable)
            command(executable)
        environment = self.path / "environment.c"
        environment.write_text(
            "#include <string.h>\n"
            "extern char *__crunch_env_get(char **, const char *);\n"
            "int main(void) { char *env[] = {\"NAME=value\", \"NEXT=ok\", 0};\n"
            "char *value = __crunch_env_get(env, \"NAME\");\n"
            "return !value || strcmp(value, \"value\") || "
            "__crunch_env_get(env, \"NAM\") != 0; }\n"
        )
        command("cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                environment, archive, "-o", executable)
        command(executable)
        assembly, obj = self.path / "snprintf.s", self.path / "snprintf-app.o"
        command(ASSEMBLER.parent / "crunch", "-S",
                ROOT / "tests/fixtures/units/library/stdio_snprintf.bc", "-o", assembly)
        command(ASSEMBLER, "-o", obj, assembly)
        command("ld", "-o", executable, obj, archive)
        command(executable)

    def test_string_tables_and_linking(self):
        """Validate string tables and link two independently assembled objects."""
        main = self.assemble(
            ".text\n.globl _start\n.type _start, @function\n_start:\n"
            "call answer@PLT\nmov %eax, %edi\nmov $60, %eax\nsyscall\n"
            ".size _start, .-_start\n.section .note.GNU-stack,\"\",@progbits\n", "main"
        )
        answer = self.assemble(
            ".text\n.globl answer\n.type answer, @function\nanswer:\n"
            "mov $42, %eax\nret\n.size answer, .-answer\n"
            ".section .note.GNU-stack,\"\",@progbits\n", "answer"
        )
        for obj in (main, answer):
            data = obj.read_bytes()
            self.assertEqual(data[:6], b"\x7fELF\x02\x01")
            count, shstr_index = struct.unpack_from("<HH", data, 60)
            shstr = string_table(data, section(data, shstr_index))
            for index in range(count):
                header = section(data, index)
                self.assertLess(header[0], len(shstr))
                self.assertNotEqual(shstr.find(b"\0", header[0]), -1)
                if header[1] == 3:
                    string_table(data, header)
            for flags in ("-SW", "-sW", "-rW"):
                self.assertEqual(command("readelf", flags, obj).stderr, "")
        combined, executable = self.path / "combined.o", self.path / "program"
        self.assertEqual(command("ld", "-r", "-o", combined, main, answer).stderr, "")
        self.assertEqual(command("ld", "-o", executable, combined).stderr, "")
        self.assertEqual(subprocess.run([str(executable)]).returncode, 42)

    def test_gnu_bytes_relocations_and_symbols(self):
        """Compare supported instruction bytes, relocations and symbol metadata."""
        source = (
            ".text\n.global example\n.type example, @function\nexample:\n"
            "mov $42, %eax\nmov %rax, %r8\npush %r8\npop %r9\n"
            "movslq %eax, %rax\n"
            "call external@PLT\nret\n.size example, .-example\n"
            ".data\n.globl value\n.type value, @object\nvalue:\n"
            ".quad external+4\n.size value, .-value\n"
            ".weak optional\n.hidden optional\n.quad optional\n"
            ".section .note.GNU-stack,\"\",@progbits\n"
        )
        ours = self.assemble(source, "ours")
        gnu = self.assemble(source, "gnu", "as")
        for name in (".text", ".data"):
            outputs = []
            for obj in (ours, gnu):
                binary = self.path / f"{obj.stem}{name}.bin"
                command("objcopy", "--dump-section", f"{name}={binary}", obj)
                outputs.append(binary.read_bytes())
            self.assertEqual(*outputs, msg=f"{name} differs from GNU as")
        expected = relocations(gnu)
        self.assertEqual(len(expected), 3)
        self.assertEqual(relocations(ours), expected)
        for name in ("example", "value", "optional", "external"):
            records = []
            for obj in (ours, gnu):
                text = command("readelf", "-sW", obj).stdout
                match = re.search(
                    r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+"
                    r"(\S+)\s+(\S+)\s+" + name + r"$", text, re.MULTILINE
                )
                self.assertIsNotNone(match, f"{name} missing from {obj}")
                value, size, kind, bind, visibility, index = match.groups()
                records.append((int(value, 16), int(size), kind, bind, visibility,
                                symbol_section(obj, index)))
            self.assertEqual(*records, msg=f"{name} differs from GNU as")


if __name__ == "__main__":
    unittest.main()

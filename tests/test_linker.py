#!/usr/bin/env python3
"""Standalone assembler and linker integration checks."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
AS = ROOT / "build/crunch-as"
LD = ROOT / "build/crunch-ld"


class LinkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="crunch-standalone-")
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name)
        self.env = dict(os.environ, CRUNCH_CONF_FILE=str(self.path / "absent.conf"))

    def command(self, *args, check=True):
        return subprocess.run([str(x) for x in args], capture_output=True,
                              text=True, env=self.env, check=check)

    def assemble(self, name, source):
        path = self.path / (name + ".s")
        obj = self.path / (name + ".o")
        path.write_text(source)
        self.command(AS, "-c", "-o", obj, path)
        return obj

    def test_static_relocatable_and_archive(self):
        main = self.assemble("main", ".text\n.globl _start\n_start:\n"
                             "call answer\nmov %eax,%edi\nmov $60,%eax\nsyscall\n")
        answer = self.assemble("answer", ".text\n.globl answer\nanswer:\n"
                               "mov $42,%eax\nret\n")
        archive = self.path / "answers.a"
        partial = self.path / "partial.o"
        executable = self.path / "program"
        self.command("ar", "rcs", archive, answer)
        self.command(LD, "-r", "-o", partial, main, archive)
        self.command(LD, "-nostdlib", "-o", executable, partial)
        self.assertEqual(self.command(executable, check=False).returncode, 42)

    def test_shared_library_with_system_loader(self):
        obj = self.assemble("shared", ".text\n.globl answer\n.type answer,@function\n"
                            "answer:\nmov $42,%eax\nret\n")
        library = self.path / "libanswer.so"
        source = self.path / "main.c"
        executable = self.path / "program"
        source.write_text("int answer(void); int main(void) { return answer(); }\n")
        self.command(LD, "-nostdlib", "-shared", "-soname", "libanswer.so",
                     "-o", library, obj)
        self.command("cc", source, "-L", self.path, "-lanswer",
                     "-Wl,-rpath," + str(self.path), "-o", executable)
        self.assertEqual(self.command(executable, check=False).returncode, 42)

    def test_undefined_symbol_rejected(self):
        obj = self.assemble("missing", ".text\n.globl _start\n_start:\ncall missing\n")
        result = self.command(LD, "-nostdlib", "-o", self.path / "program",
                              obj, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr)

    def test_assembler_links_by_default_and_c_produces_objects(self):
        main = self.path / "main.s"
        answer = self.path / "answer.s"
        main.write_text(".text\n.globl _start\n_start:\n"
                        "call answer\nmov %eax,%edi\nmov $60,%eax\nsyscall\n")
        answer.write_text(".text\n.globl answer\nanswer:\nmov $42,%eax\nret\n")
        env = dict(self.env, TMPDIR=str(self.path))
        subprocess.run([AS, "-nostdlib", main, answer], cwd=self.path,
                       env=env, check=True, capture_output=True)
        self.assertEqual(self.command(self.path / "a.out", check=False).returncode, 42)
        self.assertEqual(sorted(p.name for p in self.path.iterdir()),
                         ["a.out", "answer.s", "main.s"])
        subprocess.run([AS, "-c", main, answer], cwd=self.path,
                       env=env, check=True, capture_output=True)
        for name in ("main.o", "answer.o"):
            self.assertEqual((self.path / name).read_bytes()[16:18], b"\x01\x00")
        combined = self.path / "combined.o"
        self.command(AS, "-c", "-o", combined, main, answer)
        self.assertEqual(combined.read_bytes()[16:18], b"\x01\x00")

    def test_assembler_link_failure_and_missing_linker_cleanup(self):
        source = self.path / "missing.s"
        source.write_text(".text\n.globl _start\n_start:\ncall missing\n")
        env = dict(self.env, TMPDIR=str(self.path))
        result = subprocess.run([AS, "-nostdlib", "-o", self.path / "program", source],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr)
        self.assertFalse(list(self.path.glob("crunch-as-*")))
        isolated = self.path / "isolated"
        isolated.mkdir()
        shutil.copy2(AS, isolated / "crunch-as")
        result = subprocess.run([isolated / "crunch-as", source], cwd=self.path,
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot execute crunch-ld", result.stderr)
        self.assertFalse(list(self.path.glob("crunch-as-*")))

    def test_linked_inputs_keep_local_symbols_separate(self):
        first = self.path / "first.s"
        second = self.path / "second.s"
        first.write_text(".text\n.globl _start\n_start:\n"
                         "call answer\nmov %eax,%edi\nmov $60,%eax\nsyscall\n"
                         ".Llocal:\nret\n")
        second.write_text(".text\n.globl answer\nanswer:\n"
                          "mov $42,%eax\nret\n.Llocal:\nret\n")
        executable = self.path / "program"
        self.command(AS, "-nostdlib", "-o", executable, first, second)
        self.assertEqual(self.command(executable, check=False).returncode, 42)

    def test_assembler_stdin_and_failure_preserves_output(self):
        output = self.path / "program"
        env = dict(self.env, TMPDIR=str(self.path))
        source = ".text\n.globl _start\n_start:\nmov $42,%edi\nmov $60,%eax\nsyscall\n"
        subprocess.run([AS, "-nostdlib", "-o", output], input=source, text=True,
                       env=env, check=True, capture_output=True)
        self.assertEqual(self.command(output, check=False).returncode, 42)
        result = subprocess.run([AS, "-o", output], input="invalid_instruction\n",
                                text=True, env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.command(output, check=False).returncode, 42)
        self.assertFalse(list(self.path.glob("crunch-as-*")))


if __name__ == "__main__":
    unittest.main()

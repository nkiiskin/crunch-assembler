#!/usr/bin/env python3
"""Standalone assembler and linker integration checks."""

import os
import pathlib
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
        self.command(AS, "-o", obj, path)
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


if __name__ == "__main__":
    unittest.main()

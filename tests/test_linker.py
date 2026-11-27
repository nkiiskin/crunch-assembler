#!/usr/bin/env python3
"""Standalone assembler and linker integration checks."""

import os
import pathlib
import resource
import signal
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

    def test_assembler_rejects_output_aliasing_input(self):
        source = self.path / "program.s"
        original = (".text\n.globl _start\n_start:\n"
                    "mov $42,%edi\nmov $60,%eax\nsyscall\n")
        source.write_text(original)
        hardlink = self.path / "hardlink"
        symlink = self.path / "symlink"
        os.link(source, hardlink)
        symlink.symlink_to(source)
        for output in (source, hardlink, symlink):
            for flags in (["-c"], ["-nostdlib"]):
                with self.subTest(output=output, flags=flags):
                    result = self.command(AS, *flags, "-o", output, source, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("same file as input", result.stderr)
                    self.assertEqual(source.read_text(), original)
        with source.open() as stdin:
            result = subprocess.run([AS, "-c", "-o", hardlink], stdin=stdin,
                                    env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same file as input", result.stderr)
        self.assertEqual(source.read_text(), original)
        other = self.path / "other.s"
        other.write_text(".text\nnop\n")
        for flags in (["-c"], ["-nostdlib"]):
            result = self.command(AS, *flags, "-o", source, other, source, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("same file as input", result.stderr)
            self.assertEqual(source.read_text(), original)
            self.assertEqual(other.read_text(), ".text\nnop\n")

        default_output = self.path / "a.out"
        default_output.hardlink_to(source)
        result = subprocess.run([AS, "-nostdlib", source], cwd=self.path,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same file as input", result.stderr)
        self.assertEqual(source.read_text(), original)

    def test_assembler_checks_all_inputs_before_default_outputs(self):
        first = self.path / "first.s"
        second = self.path / "first.o"
        first.write_text(".text\nret\n")
        second.write_text(".text\nnop\n")
        result = subprocess.run([AS, "-c", first, second], cwd=self.path,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same file as input", result.stderr)
        self.assertEqual(first.read_text(), ".text\nret\n")
        self.assertEqual(second.read_text(), ".text\nnop\n")
        self.assertFalse((self.path / "first.o.o").exists())

    def test_assembler_rejects_output_aliasing_nested_include(self):
        includes = self.path / "includes"
        includes.mkdir()
        nested = includes / "nested.inc"
        original = ".text\n.globl _start\n_start:\nmov $42,%edi\nmov $60,%eax\nsyscall\n"
        nested.write_text(original)
        (includes / "outer.inc").write_text('.include "nested.inc"\n')
        source = self.path / "program.s"
        source.write_text('.include "outer.inc"\n')
        hardlink = self.path / "hardlink"
        symlink = self.path / "symlink"
        os.link(nested, hardlink)
        symlink.symlink_to(nested)
        for output in (nested, hardlink, symlink):
            for flags in (["-c"], ["-nostdlib"]):
                with self.subTest(output=output, flags=flags):
                    result = self.command(AS, *flags, "-I", includes, "-o", output,
                                          source, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("same file as include", result.stderr)
                    self.assertEqual(nested.read_text(), original)
        output = self.path / "program"
        self.command(AS, "-nostdlib", "-I", includes, "-o", output, source)
        self.assertEqual(self.command(output, check=False).returncode, 42)

    def test_default_outputs_cannot_overwrite_later_include(self):
        first = self.path / "first.s"
        second = self.path / "second.s"
        included = self.path / "first.o"
        first.write_text(".text\nret\n")
        second.write_text('.include "first.o"\n')
        included.write_text(".text\nnop\n")
        result = subprocess.run([AS, "-c", first, second], cwd=self.path,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same file as include", result.stderr)
        self.assertEqual(included.read_text(), ".text\nnop\n")
        self.assertFalse((self.path / "second.o").exists())

    def test_default_object_cannot_alias_include(self):
        source = self.path / "main.s"
        included = self.path / "included.s"
        included.write_text(".text\nret\n")
        (self.path / "main.o").symlink_to(included)
        source.write_text('.include "included.s"\n')
        result = subprocess.run([AS, "-c", source], cwd=self.path,
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same file as include", result.stderr)
        self.assertEqual(included.read_text(), ".text\nret\n")

    def test_duplicate_default_object_names_are_rejected(self):
        first_dir = self.path / "first"
        second_dir = self.path / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        first, second = first_dir / "same.s", second_dir / "same.s"
        first.write_text(".text\nret\n")
        second.write_text(".text\nnop\n")
        output = self.path / "same.o"
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    output.write_bytes(b"preserved")
                result = subprocess.run([AS, "-c", first, second], cwd=self.path,
                                        env=self.env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("same file", result.stderr)
                if existing:
                    self.assertEqual(output.read_bytes(), b"preserved")
                else:
                    self.assertFalse(output.exists())
        output.unlink()
        subprocess.run([AS, "-c", "-o", output, first, second], cwd=self.path,
                       env=self.env, check=True, capture_output=True)
        self.assertEqual(output.read_bytes()[:4], b"\x7fELF")

    def test_aliasing_default_object_paths_are_rejected(self):
        first, second = self.path / "first.s", self.path / "second.s"
        first.write_text(".text\nret\n")
        second.write_text(".text\nnop\n")
        first_obj, second_obj = self.path / "first.o", self.path / "second.o"
        for kind in ("hardlink", "symlink", "dangling"):
            with self.subTest(kind=kind):
                if kind != "dangling":
                    first_obj.write_bytes(b"preserved")
                if kind == "hardlink":
                    os.link(first_obj, second_obj)
                else:
                    second_obj.symlink_to(first_obj)
                result = subprocess.run([AS, "-c", first, second], cwd=self.path,
                                        env=self.env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("dangling" if kind == "dangling" else "same file", result.stderr)
                if kind != "dangling":
                    self.assertEqual(first_obj.read_bytes(), b"preserved")
                    first_obj.unlink()
                else:
                    self.assertFalse(first_obj.exists())
                second_obj.unlink()

    def test_object_write_failure_preserves_existing_file(self):
        source = self.path / "program.s"
        source.write_text(".text\nret\n")
        output = self.path / "program.o"
        output.write_bytes(b"existing object")
        output.chmod(0o640)

        def limit_output():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))

        for args in (["-c", "-o", output, source], ["-c", source]):
            with self.subTest(args=args):
                result = subprocess.run([AS, *args], cwd=self.path, env=self.env,
                                        capture_output=True, text=True, preexec_fn=limit_output)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_bytes(), b"existing object")
                self.assertEqual(output.stat().st_mode & 0o777, 0o640)
                self.assertFalse(list(self.path.glob(".crunch-as-*")))
        subprocess.run([AS, "-c", "-o", output, source], cwd=self.path,
                       env=self.env, check=True, capture_output=True)
        self.assertEqual(output.read_bytes()[:4], b"\x7fELF")
        self.assertEqual(output.stat().st_mode & 0o777, 0o640)
        output.unlink()
        subprocess.run([AS, "-c", "-o", output, source], cwd=self.path,
                       env=self.env, check=True, capture_output=True,
                       preexec_fn=lambda: os.umask(0o027))
        self.assertEqual(output.stat().st_mode & 0o777, 0o640)

    def test_linked_and_nonregular_object_outputs_are_rejected(self):
        source = self.path / "program.s"
        source.write_text(".text\nret\n")
        target = self.path / "target"
        target.write_bytes(b"existing object")
        output = self.path / "program.o"
        for kind in ("symlink", "dangling", "hardlink", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    output.symlink_to(target)
                elif kind == "dangling":
                    output.symlink_to(self.path / "missing")
                elif kind == "hardlink":
                    os.link(target, output)
                else:
                    output.mkdir()
                result = subprocess.run([AS, "-c", "-o", output, source], cwd=self.path,
                                        env=self.env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_bytes(), b"existing object")
                if kind == "directory":
                    output.rmdir()
                else:
                    output.unlink()

    def test_multi_object_copy_failure_preserves_output(self):
        library_source = self.path / "fail-write.c"
        library = self.path / "fail-write.so"
        library_source.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
size_t fwrite(const void *data, size_t size, size_t count, FILE *stream) {
    char fdpath[64], path[PATH_MAX];
    const char *dir = getenv("CRUNCH_TEST_FAIL_DIRECTORY");
    snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fileno(stream));
    ssize_t n = readlink(fdpath, path, sizeof path - 1);
    if (n >= 0 && dir) {
        path[n] = 0;
        size_t length = strlen(dir);
        if (!strncmp(path, dir, length) && !strncmp(path + length, "/.crunch-as-", 12)) {
            errno = ENOSPC;
            return 0;
        }
    }
    size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = dlsym(RTLD_NEXT, "fwrite");
    return real_fwrite(data, size, count, stream);
}
int rename(const char *old_path, const char *new_path) {
    const char *fail = getenv("CRUNCH_TEST_FAIL_RENAME");
    if (fail && !strcmp(fail, new_path)) {
        errno = EACCES;
        return -1;
    }
    int (*real_rename)(const char *, const char *) = dlsym(RTLD_NEXT, "rename");
    return real_rename(old_path, new_path);
}
''')
        self.command("cc", "-shared", "-fPIC", library_source, "-ldl", "-o", library)
        first, second = self.path / "first.s", self.path / "second.s"
        first.write_text(".text\nret\n")
        second.write_text(".text\nnop\n")
        first_obj, second_obj = self.path / "first.o", self.path / "second.o"
        first_obj.write_bytes(b"first original")
        second_obj.write_bytes(b"second original")
        temp = self.path / "temp"
        temp.mkdir()
        env = dict(self.env, TMPDIR=str(temp), LD_PRELOAD=str(library),
                   CRUNCH_TEST_FAIL_DIRECTORY=str(self.path))
        result = subprocess.run([AS, "-c", first, second], cwd=self.path, env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(first_obj.read_bytes(), b"first original")
        self.assertEqual(second_obj.read_bytes(), b"second original")
        self.assertFalse(list(self.path.glob(".crunch-as-*")))
        self.assertEqual(list(temp.iterdir()), [])
        env = dict(self.env, TMPDIR=str(temp), LD_PRELOAD=str(library),
                   CRUNCH_TEST_FAIL_RENAME=second_obj.name)
        result = subprocess.run([AS, "-c", first, second], cwd=self.path, env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(first_obj.read_bytes()[:4], b"\x7fELF")
        self.assertEqual(second_obj.read_bytes(), b"second original")
        self.assertFalse(list(self.path.glob(".crunch-as-*")))
        self.assertEqual(list(temp.iterdir()), [])

    def test_only_opened_includes_are_protected(self):
        source = self.path / "main.s"
        output = self.path / "main.o"
        source.write_text('.if 0\n.include "main.o"\n.endif\n'
                          '# 1 "main.o"\n.text\nret\n')
        output.write_text("not an include\n")
        subprocess.run([AS, "-c", source], cwd=self.path, env=self.env,
                       check=True, capture_output=True)
        self.assertEqual(output.read_bytes()[:4], b"\x7fELF")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import generate_compile_commands


class CompileCommandsTests(unittest.TestCase):
    def test_generated_entries_use_current_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            clang = workspace / "llvm" / "clang.exe"
            clang_cl = workspace / "llvm" / "clang-cl.exe"
            msvc = workspace / "msvc" / "include"
            kit = workspace / "kit" / "10.0.26100.0"
            entries = generate_compile_commands.generate(
                workspace, clang, clang_cl, msvc, kit
            )

        self.assertEqual(
            [entry["file"] for entry in entries],
            [
                "driver/driver.c",
                "driver/process.c",
                "driver/image.c",
                "driver/memory.c",
                "driver/queue.c",
                "driver/ioctl.c",
                "logger/logger.c",
                "reader/reader.c",
                "tests/logger_runtime_test.c",
                "tests/reader_format_test.c",
            ],
        )
        driver_args = entries[0]["arguments"]
        self.assertIn("/D_KERNEL_MODE=1", driver_args)
        self.assertIn(
            (Path(temp) / "kit" / "10.0.26100.0" / "km").as_posix(),
            driver_args,
        )
        self.assertIn(clang.as_posix(), entries[6]["arguments"])
        self.assertIn(clang_cl.as_posix(), entries[7]["arguments"])

    def test_generated_json_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            output = workspace / "compile_commands.json"
            exit_code = generate_compile_commands.main(
                [
                    "--workspace",
                    str(workspace),
                    "--clang",
                    str(workspace / "clang.exe"),
                    "--clang-cl",
                    str(workspace / "clang-cl.exe"),
                    "--msvc-include",
                    str(workspace / "msvc"),
                    "--kit-include",
                    str(workspace / "kit"),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(parsed), 10)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pefile
import capstone

from tools import analyze_targets


class TargetAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.targets = ROOT / "target_dlls"
        if not cls.targets.is_dir():
            raise unittest.SkipTest("target_dlls is not installed")
        cls.analyses = analyze_targets.analyze_all(cls.targets)

    def test_module_ids_and_names_are_fixed(self) -> None:
        self.assertEqual(
            [(item.module_id, item.name) for item in self.analyses],
            [
                (0, "ntdll.dll"),
                (1, "KernelBase.dll"),
                (2, "kernel32.dll"),
            ],
        )
        self.assertEqual(
            [item.canonical_image_name for item in self.analyses],
            [
                "\\SystemRoot\\System32\\ntdll.dll",
                "\\SystemRoot\\System32\\KernelBase.dll",
                "\\SystemRoot\\System32\\kernel32.dll",
            ],
        )

    def test_every_installable_patch_has_exact_original_bytes(self) -> None:
        for analysis in self.analyses:
            for item in analysis.installable:
                self.assertGreaterEqual(item.patch_length, 5)
                self.assertGreaterEqual(len(item.original_bytes_hex), 10)
                self.assertEqual(
                    len(bytes.fromhex(item.original_bytes_hex)),
                    item.patch_length,
                )

    def test_stub_layout_matches_plan(self) -> None:
        expected = {
            "ntdll.dll": 86048,
            "KernelBase.dll": 80992,
            "kernel32.dll": 26272,
        }
        for analysis in self.analyses:
            size = 16 + sum(
                (40 + item.patch_length + 15) & ~15
                for item in analysis.installable
            )
            self.assertEqual(size, expected[analysis.name])
            self.assertLessEqual(size, 0x40000)

    def test_skipped_reasons_are_nonempty(self) -> None:
        for analysis in self.analyses:
            for item in analysis.skipped:
                self.assertTrue(item.reason)
                self.assertNotEqual(item.reason, "ok")

    def test_canonical_name_is_first_sorted_alias(self) -> None:
        for analysis in self.analyses:
            for item in analysis.installable + analysis.skipped:
                self.assertEqual(item.canonical_name, min(item.aliases))

    def test_emit_is_deterministic(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = analyze_targets.emit(
                self.targets, root / "b1", root / "d1", root / "r1"
            )
            second = analyze_targets.emit(
                self.targets, root / "b2", root / "d2", root / "r2"
            )
            self.assertEqual(first, second)
            for relative in (
                "skipped_exports.csv",
                "analysis.json",
            ):
                self.assertEqual(
                    (root / "b1" / relative).read_bytes(),
                    (root / "b2" / relative).read_bytes(),
                )
            generated_names = (
                root / "r1" / "generated_names.h"
            ).read_text(encoding="utf-8-sig")
            self.assertIn(
                f"LOGGER_MODULE_NAME_ENTRY_COUNT {len(self.analyses)}u",
                generated_names,
            )
            self.assertIn('{0u, "ntdll"}', generated_names)
            self.assertIn('{1u, "KernelBase"}', generated_names)
            self.assertIn('{2u, "kernel32"}', generated_names)
            self.assertNotIn("trusted_modules", generated_names)
            self.assertNotIn("uint32_t hookable", generated_names)


class PatchDecodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.decoder = capstone.Cs(
            capstone.CS_ARCH_X86, capstone.CS_MODE_64
        )
        self.decoder.detail = True

    def decode(self, code: bytes):
        return analyze_targets._decode_patch(
            code, 0, len(code), (), self.decoder
        )

    def test_exact_five_byte_boundary(self) -> None:
        length, original, failure = self.decode(b"\x90" * 5 + b"\xC3")
        self.assertIsNone(failure)
        self.assertEqual(length, 5)
        self.assertEqual(original, b"\x90" * 5)

    def test_long_first_instruction_crosses_five_bytes(self) -> None:
        code = b"\x48\xB8" + b"\x11" * 8 + b"\xC3"
        length, original, failure = self.decode(code)
        self.assertIsNone(failure)
        self.assertEqual(length, 10)
        self.assertEqual(original, code[:10])

    def test_rip_relative_instruction_is_rejected(self) -> None:
        _length, _original, failure = self.decode(
            b"\x48\x8B\x05\x00\x00\x00\x00"
        )
        self.assertEqual(failure, "first-instruction-uses-rip-relative-operand")

    def test_relative_control_flow_is_rejected(self) -> None:
        _length, _original, failure = self.decode(b"\xE9\x00\x00\x00\x00")
        self.assertEqual(
            failure, "first-instruction-is-relative-control-flow"
        )

    def test_return_is_rejected(self) -> None:
        _length, _original, failure = self.decode(b"\xC3\x90\x90\x90\x90")
        self.assertEqual(failure, "first-instruction-is-ret")


if __name__ == "__main__":
    unittest.main()

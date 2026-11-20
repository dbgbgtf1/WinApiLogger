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
            "ntdll.dll": 88112,
            "KernelBase.dll": 88880,
            "kernel32.dll": 67552,
        }
        for analysis in self.analyses:
            size = 16 + sum(
                (40 + item.patch_length + 15) & ~15
                for item in analysis.installable
            )
            self.assertEqual(size, expected[analysis.name])
            self.assertLessEqual(size, 0x40000)

    def test_rip_relative_fixups_are_installable(self) -> None:
        self.assertEqual(
            {
                analysis.name: analysis.rip_fixup_count
                for analysis in self.analyses
            },
            {
                "ntdll.dll": 38,
                "KernelBase.dll": 132,
                "kernel32.dll": 851,
            },
        )
        for analysis in self.analyses:
            self.assertFalse(
                any(
                    item.reason
                    == "first-instruction-uses-rip-relative-operand"
                    for item in analysis.skipped
                )
            )

    def test_current_target_has_one_reviewed_overlap_override(self) -> None:
        self.assertEqual(len(analyze_targets.RIP_RELATIVE_OVERLAP_OVERRIDES), 1)
        item = next(
            item
            for item in self.analyses[0].installable
            if item.rva == 0x124800
        )
        self.assertEqual(item.rip_mnemonic, "lea")
        self.assertEqual(item.rip_target_rva, 0x16AA40)

    def test_exception_dispatcher_is_always_excluded(self) -> None:
        self.assertIn(
            "KiUserExceptionDispatcher",
            analyze_targets.EXPORT_SAFETY_EXCLUSIONS,
        )
        self.assertEqual(
            analyze_targets._safety_exclusion_reason(
                ("SomeOtherAlias", "KiUserExceptionDispatcher")
            ),
            "exception-dispatcher-reentrancy-risk",
        )
        item = next(
            item
            for item in self.analyses[0].skipped
            if item.rva == 0x16A450
        )
        self.assertEqual(
            item.reason, "exception-dispatcher-reentrancy-risk"
        )

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
                "rip_relative.csv",
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
        decoded = self.decode(b"\x90" * 5 + b"\xC3")
        self.assertIsNone(decoded.failure)
        self.assertEqual(decoded.length, 5)
        self.assertEqual(decoded.original, b"\x90" * 5)

    def test_long_first_instruction_crosses_five_bytes(self) -> None:
        code = b"\x48\xB8" + b"\x11" * 8 + b"\xC3"
        decoded = self.decode(code)
        self.assertIsNone(decoded.failure)
        self.assertEqual(decoded.length, 10)
        self.assertEqual(decoded.original, code[:10])

    def test_rip_relative_instruction_records_fixup(self) -> None:
        decoded = self.decode(
            b"\x48\x8B\x05\x78\x56\x34\x12"
        )
        self.assertIsNone(decoded.failure)
        self.assertEqual(decoded.length, 7)
        self.assertEqual(decoded.rip_disp_offset, 3)
        self.assertEqual(decoded.rip_old_disp, 0x12345678)
        self.assertEqual(decoded.rip_target_rva, 0x12345678 + 7)
        self.assertEqual(decoded.rip_mnemonic, "mov")

    def test_rip_fixup_offset_includes_prior_instructions(self) -> None:
        decoded = self.decode(
            b"\x48\x83\xEC\x28"
            b"\x80\x3D\x78\x56\x34\x12\x00"
        )
        self.assertIsNone(decoded.failure)
        self.assertEqual(decoded.length, 11)
        self.assertEqual(decoded.rip_disp_offset, 6)
        self.assertEqual(decoded.rip_old_disp, 0x12345678)

    def test_relative_control_flow_is_rejected(self) -> None:
        decoded = self.decode(b"\xE9\x00\x00\x00\x00")
        self.assertEqual(
            decoded.failure,
            "first-instruction-is-relative-control-flow",
        )

    def test_return_is_rejected(self) -> None:
        decoded = self.decode(b"\xC3\x90\x90\x90\x90")
        self.assertEqual(decoded.failure, "first-instruction-is-ret")


class RipRelativeValidationTests(unittest.TestCase):
    def make_item(
        self,
        rva: int,
        *,
        rip_old_disp: int | None = None,
        rip_target_rva: int | None = None,
        rip_disp_offset: int | None = 3,
        name: str = "test",
    ):
        return analyze_targets.ExportDecision(
            module_id=0,
            module_name="test.dll",
            rva=rva,
            aliases=(name,),
            canonical_name=name,
            patch_length=6,
            original_bytes_hex="00" * 6,
            rip_disp_offset=(
                None if rip_old_disp is None else rip_disp_offset
            ),
            rip_old_disp=rip_old_disp,
            rip_target_rva=rip_target_rva,
            rip_mnemonic="mov" if rip_old_disp is not None else None,
            installable=True,
            reason="ok",
        )

    def make_module(self, items):
        items = tuple(items)
        rips = tuple(
            item for item in items if item.rip_disp_offset is not None
        )
        return analyze_targets.ModuleAnalysis(
            module_id=0,
            name="test.dll",
            canonical_image_name="\\SystemRoot\\System32\\test.dll",
            sha256="A" * 64,
            timestamp=1,
            size_of_image=0x10000,
            executable_end_rva=0x8000,
            exports_seen=len(items),
            installable=items,
            skipped=(),
            rip_fixup_count=len(rips),
            rip_target_min_rva=(
                min(item.rip_target_rva for item in rips) if rips else None
            ),
            rip_target_max_rva=(
                max(item.rip_target_rva for item in rips) if rips else None
            ),
            rip_disp_min=(
                min(item.rip_old_disp for item in rips) if rips else None
            ),
            rip_disp_max=(
                max(item.rip_old_disp for item in rips) if rips else None
            ),
        )

    def test_rip_target_in_patch_range_is_fatal(self) -> None:
        item = self.make_item(
            0x1000, rip_old_disp=0, rip_target_rva=0x1002
        )
        with self.assertRaisesRegex(
            analyze_targets.AnalysisError, "target overlaps"
        ):
            analyze_targets._validate_rip_relative_layouts(
                (self.make_module((item,)),)
            )

    def test_conflicting_rip_displacements_are_fatal(self) -> None:
        first = self.make_item(
            0x1000,
            rip_old_disp=analyze_targets.INT32_MAX,
            rip_target_rva=0x180000,
            name="first",
        )
        second = self.make_item(
            0x2000,
            rip_old_disp=analyze_targets.INT32_MIN,
            rip_target_rva=0x280000,
            name="second",
        )
        with self.assertRaisesRegex(
            analyze_targets.AnalysisError, "No near-stub address"
        ):
            analyze_targets._validate_rip_relative_layouts(
                (self.make_module((first, second)),)
            )


if __name__ == "__main__":
    unittest.main()

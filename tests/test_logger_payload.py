from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import build_logger_payload


class LoggerPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.object_path = ROOT / "build" / "logger.obj"
        if not cls.object_path.is_file():
            raise unittest.SkipTest("build/logger.obj is not available")
        cls.coff = build_logger_payload.parse_coff(cls.object_path)
        cls.payload, cls.symbols, cls.sections = build_logger_payload.build_payload(
            cls.coff
        )

    def test_payload_has_required_symbols(self) -> None:
        for name in ("LoggerEntry", "LoggerHandle"):
            self.assertIn(name, self.symbols)
            self.assertGreaterEqual(self.symbols[name], 0)
        for name in ("FindExecutor", "g_context_slot"):
            self.assertNotIn(name, self.symbols)

    def test_payload_is_executable_alignment(self) -> None:
        self.assertGreater(len(self.payload), 256)
        self.assertIn(b"\x0f\x1e\xfa", self.payload)

    def test_header_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "payload.h"
            build_logger_payload.write_header(output, self.payload, self.symbols)
            text = output.read_text(encoding="utf-8")
            self.assertIn(
                f"#define LOGGER_PAYLOAD_SIZE {len(self.payload)}u", text
            )
            self.assertIn("g_logger_payload", text)

    def test_sections_are_ordered_and_aligned(self) -> None:
        self.assertEqual([section.name for section in self.sections], [".text"])
        for section in self.sections:
            self.assertEqual(section.image_rva % 16, 0)

    def test_entry_uses_cet_landing_pad_and_no_simd_registers(self) -> None:
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        instructions = list(decoder.disasm(self.payload, 0))
        self.assertTrue(instructions)
        entry = next(
            instruction
            for instruction in instructions
            if instruction.address == self.symbols["LoggerEntry"]
        )
        self.assertEqual(entry.mnemonic, "endbr64")
        for instruction in instructions:
            for operand in instruction.operands:
                if operand.type != capstone.CS_OP_REG:
                    continue
                name = instruction.reg_name(operand.reg).casefold()
                self.assertFalse(
                    name.startswith(("xmm", "ymm", "zmm")),
                    f"SIMD register used at 0x{instruction.address:X}",
                )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from pathlib import Path

import pefile


ROOT = Path(__file__).resolve().parents[1]


class DriverImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = ROOT / "build" / "WinApiLogger.sys"
        if not cls.path.is_file():
            raise unittest.SkipTest("WinApiLogger.sys has not been built")
        cls.pe = pefile.PE(str(cls.path))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pe.close()

    def test_driver_is_x64_native_with_force_integrity(self) -> None:
        self.assertEqual(self.pe.FILE_HEADER.Machine, 0x8664)
        self.assertEqual(self.pe.OPTIONAL_HEADER.Subsystem, 1)
        self.assertNotEqual(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0)
        self.assertTrue(
            self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x80,
            "PsSetCreateProcessNotifyRoutineEx requires /INTEGRITYCHECK",
        )

    def test_driver_imports_only_ntoskrnl(self) -> None:
        imports = {
            entry.dll.decode("ascii").lower()
            for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", [])
        }
        self.assertEqual(imports, {"ntoskrnl.exe"})


if __name__ == "__main__":
    unittest.main()

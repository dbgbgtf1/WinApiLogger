from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureTests(unittest.TestCase):
    def test_driver_is_split_by_responsibility(self) -> None:
        expected = {
            "driver.c",
            "process.c",
            "image.c",
            "memory.c",
            "queue.c",
            "ioctl.c",
            "logger_internal.h",
            "state.h",
        }
        self.assertTrue(expected.issubset(
            {path.name for path in (ROOT / "driver").iterdir()}
        ))

    def test_shared_payload_contract_has_no_executor_state(self) -> None:
        paths = [
            ROOT / "common" / "protocol.h",
            ROOT / "logger" / "logger.c",
            ROOT / "driver" / "image.c",
        ]
        combined = "\n".join(
            path.read_text(encoding="utf-8-sig") for path in paths
        ).casefold()
        self.assertNotIn("findexecutor", combined)
        self.assertNotIn("g_context_slot", combined)
        self.assertNotIn("loggerexecutorentry", combined)

    def test_module_id_rva_naming_is_uniform(self) -> None:
        paths = [
            ROOT / "common" / "protocol.h",
            ROOT / "driver" / "image.c",
            ROOT / "logger" / "logger.c",
            ROOT / "reader" / "reader.c",
            ROOT / "tests" / "logger_runtime_test.c",
        ]
        combined = "\n".join(
            path.read_text(encoding="utf-8-sig").casefold()
            for path in paths
        )
        legacy_terms = (
            "hook" + " site",
            "hook" + "_site",
            "hook" + "site",
        )
        for legacy_term in legacy_terms:
            self.assertNotIn(legacy_term, combined)
        self.assertIn("moduleidrva", combined)
        self.assertIn("module_id_rva", combined)

    def test_logger_and_driver_record_names_are_distinct(self) -> None:
        protocol = (ROOT / "common" / "protocol.h").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("WIN_API_LOGGER_LOG_RECORD_SIZE 32u", protocol)
        self.assertIn("WIN_API_LOGGER_DRIVER_RECORD_SIZE 72u", protocol)
        self.assertIn("} LOGGER_LOG_RECORD;", protocol)
        self.assertIn("} LOGGER_DRIVER_RECORD;", protocol)
        self.assertNotIn("LOGGER_QUEUE_RECORD", protocol)

    def test_vm_test_helpers_are_present(self) -> None:
        self.assertTrue((ROOT / "tools" / "sign_test_driver.ps1").is_file())
        self.assertTrue((ROOT / "tests" / "vm_preflight.ps1").is_file())
        self.assertTrue((ROOT / "tests" / "vm_smoke.ps1").is_file())

    def test_vm_smoke_rejects_target_crash(self) -> None:
        text = (ROOT / "tests" / "vm_smoke.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("target_exit_code", text)
        self.assertIn("if ($target.ExitCode -ne 0)", text)

    def test_stub_context_slot_uses_process_user_va(self) -> None:
        text = (ROOT / "driver" / "image.c").read_text(encoding="utf-8-sig")
        self.assertIn("State->Data.UserVa + LOGGER_CONTEXT_OFFSET", text)

    def test_stub_builder_uses_per_stub_offsets_for_local_writes(self) -> None:
        text = (ROOT / "driver" / "image.c").read_text(encoding="utf-8-sig")
        self.assertIn("stub + module_id_rva_in_stub", text)
        self.assertNotIn("stub + module_id_rva_offset", text)
        self.assertIn(
            "RtlFillMemory (stub + module_id_rva_in_stub",
            text,
        )

    def test_target_patch_keeps_original_entry_address(self) -> None:
        text = (ROOT / "driver" / "memory.c").read_text(
            encoding="utf-8-sig"
        )
        function = text[text.index("LoggerWriteTargetRange"):]
        self.assertIn("ProbeForWrite (Address", function)
        self.assertIn("RtlEqualMemory (Address", function)
        self.assertIn("RtlCopyMemory (Address", function)
        self.assertIn("*BytesChanged = TRUE", function)
        self.assertNotIn("RtlCopyMemory (base", function)

    def test_stub_layout_constants_are_generated(self) -> None:
        metadata = (
            ROOT / "driver" / "generated" / "generated_metadata.h"
        ).read_text(encoding="utf-8-sig")
        image = (ROOT / "driver" / "image.c").read_text(
            encoding="utf-8-sig"
        )
        memory = (ROOT / "driver" / "memory.c").read_text(
            encoding="utf-8-sig"
        )
        for name in (
            "LOGGER_STUB_HEADER_SIZE",
            "LOGGER_STUB_FIXED_SIZE",
            "LOGGER_STUB_ORIGINAL_OFFSET",
            "LOGGER_NEAR_STUB_START",
            "LOGGER_NEAR_STUB_STEP",
            "LOGGER_NEAR_STUB_LIMIT",
            "LOGGER_RIP_DISP_NONE",
        ):
            self.assertIn(f"#define {name}", metadata)
        self.assertNotIn("#define LOGGER_STUB_HEADER_SIZE", image)
        self.assertNotIn("#define LOGGER_NEAR_STUB_START", memory)
        self.assertIn("LOGGER_RIP_DISP_NONE", image)
        self.assertIn("LoggerFailureRipRelocationFailed", image)

    def test_rip_relative_failure_reason_is_shared(self) -> None:
        protocol = (ROOT / "common" / "protocol.h").read_text(
            encoding="utf-8-sig"
        )
        reader = (ROOT / "reader" / "reader.c").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("LoggerFailureRipRelocationFailed = 19", protocol)
        self.assertIn(
            "case LoggerFailureRipRelocationFailed", reader
        )

    def test_driver_uses_generated_module_names_and_paths(self) -> None:
        image = (ROOT / "driver" / "image.c").read_text(encoding="utf-8-sig")
        process = (ROOT / "driver" / "process.c").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("canonical_image_name", image)
        self.assertNotIn('L"\\\\SystemRoot\\\\System32\\\\', image)
        self.assertIn("g_static_modules[index].base_name", process)
        self.assertNotIn('L"ntdll.dll"', process)

    def test_driver_build_uses_all_modules(self) -> None:
        text = (ROOT / "build.ps1").read_text(encoding="utf-8-sig")
        for name in (
            "driver",
            "process",
            "image",
            "memory",
            "queue",
            "ioctl",
        ):
            self.assertRegex(text, rf"(?m)^\s*'{name}',?$")

    def test_generated_metadata_drops_gateway_fields(self) -> None:
        text = (ROOT / "driver" / "generated" / "generated_metadata.h") \
            .read_text(encoding="utf-8-sig")
        self.assertNotRegex(text, re.compile(r"\bgateway_rva\b", re.IGNORECASE))

    def test_reader_uses_generated_target_module_table(self) -> None:
        text = (ROOT / "reader" / "generated" / "generated_names.h") \
            .read_text(encoding="utf-8-sig")
        self.assertIn("g_module_name_entries", text)
        self.assertIn("LOGGER_MODULE_NAME_ENTRY_COUNT 3u", text)
        self.assertIn('"ntdll"', text)
        self.assertIn('"KernelBase"', text)
        self.assertIn('"kernel32"', text)
        self.assertNotIn("trusted_modules", text)


if __name__ == "__main__":
    unittest.main()

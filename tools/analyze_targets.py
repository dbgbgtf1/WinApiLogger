#!/usr/bin/env python3
"""Analyze the configured hook targets and generate build-time metadata.

`target_dlls/` selects the modules that are actually patched and supplies the
module names used by the reader.  Caller module names are resolved from the
target process PEB at READ_STREAM time.  The analyzer intentionally works from
the supplied hook-target files only.  It does not resolve the copies loaded by
the build machine and it does not use the IDA database.  All decisions that
affect hook safety are recorded in build/skipped_exports.csv.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import dataclasses
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path
from typing import Iterable, Sequence

import capstone
import capstone.x86 as x86
import pefile


TARGET_IDENTITIES: tuple[tuple[int, str, str, int, int], ...] = (
    (
        0,
        "ntdll.dll",
        "A0F81BF5C610C0FF0A550ADC020A58446F214790C748057BB575042E972E6A34",
        0xA2B84216,
        0x26C000,
    ),
    (
        1,
        "KernelBase.dll",
        "9EB6768C3020992F8F616F7EDFEAD6254DD6D4C6042D1468D790EC3004CB4BBC",
        0xA3FF6954,
        0x409000,
    ),
    (
        2,
        "kernel32.dll",
        "970E5E15EED7D53C8B88E06DDC71884C31804F1CB5286ABF01FBCE39B7F0E29F",
        0x28B50DC0,
        0xCB000,
    ),
)

EXPECTED_FILE_VERSION = "10.0.26100.9974"
EXPECTED_MACHINE = 0x8664
EXPECTED_MAGIC = 0x20B
MAX_COPY_INSTRUCTION_BYTES = 15
RELOCATION_PADDING = 16
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
STUB_HEADER_SIZE = 16
STUB_FIXED_SIZE = 40
STUB_ORIGINAL_OFFSET = 27
STUB_ALIGNMENT = 16
STUB_SEARCH_START = 0x01000000
STUB_SEARCH_STEP = 0x01000000
STUB_SEARCH_LIMIT = 0x60000000
RIP_DISP_NONE = 0xFF

# Exact, hash-bound exceptions for cases reviewed as target-specific handling.
# The value is the instruction mnemonic that must still be present.
# This ntdll lea returns the other entry's address; preserving that address is
# intentional, and executing it later enters the target entry's own stub.
RIP_RELATIVE_OVERLAP_OVERRIDES: dict[tuple[str, int, int], str] = {
    (
        "A0F81BF5C610C0FF0A550ADC020A58446F214790C748057BB575042E972E6A34",
        0x124800,
        0x16AA40,
    ): "lea",
}

# These exports are unsafe to detour even when their operand relocation is
# mechanically possible. KiUserExceptionDispatcher must stay untouched because
# any fault raised while logging is routed back through the patched dispatcher.
EXPORT_SAFETY_EXCLUSIONS: dict[str, str] = {
    "KiUserExceptionDispatcher": "exception-dispatcher-reentrancy-risk",
}


class AnalysisError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ExportAlias:
    name: str
    ordinal: int


@dataclasses.dataclass(frozen=True)
class ExportDecision:
    module_id: int
    module_name: str
    rva: int
    aliases: tuple[str, ...]
    canonical_name: str
    patch_length: int
    original_bytes_hex: str
    rip_disp_offset: int | None
    rip_old_disp: int | None
    rip_target_rva: int | None
    rip_mnemonic: str | None
    installable: bool
    reason: str


@dataclasses.dataclass(frozen=True)
class ModuleAnalysis:
    module_id: int
    name: str
    canonical_image_name: str
    sha256: str
    timestamp: int
    size_of_image: int
    executable_end_rva: int
    exports_seen: int
    installable: tuple[ExportDecision, ...]
    skipped: tuple[ExportDecision, ...]
    rip_fixup_count: int
    rip_target_min_rva: int | None
    rip_target_max_rva: int | None
    rip_disp_min: int | None
    rip_disp_max: int | None


@dataclasses.dataclass(frozen=True)
class PatchDecode:
    length: int
    original: bytes
    failure: str | None
    rip_disp_offset: int | None = None
    rip_old_disp: int | None = None
    rip_target_rva: int | None = None
    rip_mnemonic: str | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _version_tuple(value: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+){3}", value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(0).split("."))


def _validate_identity(
    path: Path,
    expected_name: str,
    expected_sha256: str,
    expected_timestamp: int,
    expected_size_of_image: int,
    pe: pefile.PE,
) -> None:
    if path.name.casefold() != expected_name.casefold():
        raise AnalysisError(
            f"{path}: expected file name {expected_name!r}, got {path.name!r}"
        )
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise AnalysisError(
            f"{path}: SHA-256 mismatch (expected {expected_sha256}, got {actual_sha256})"
        )

    header = pe.OPTIONAL_HEADER
    if pe.FILE_HEADER.Machine != EXPECTED_MACHINE:
        raise AnalysisError(
            f"{path}: expected machine 0x{EXPECTED_MACHINE:04X}, "
            f"got 0x{pe.FILE_HEADER.Machine:04X}"
        )
    if header.Magic != EXPECTED_MAGIC:
        raise AnalysisError(
            f"{path}: expected PE32+ magic 0x{EXPECTED_MAGIC:04X}, "
            f"got 0x{header.Magic:04X}"
        )
    if int(pe.FILE_HEADER.TimeDateStamp) != expected_timestamp:
        raise AnalysisError(
            f"{path}: TimeDateStamp mismatch "
            f"(expected 0x{expected_timestamp:08X}, "
            f"got 0x{int(pe.FILE_HEADER.TimeDateStamp):08X})"
        )
    if int(header.SizeOfImage) != expected_size_of_image:
        raise AnalysisError(
            f"{path}: SizeOfImage mismatch "
            f"(expected 0x{expected_size_of_image:X}, "
            f"got 0x{int(header.SizeOfImage):X})"
        )

    file_version = str(getattr(pe, "FileInfo", [{}])[0]).strip()
    # pefile does not always expose a stable version string.  Fall back to
    # Windows' FileVersionInfo when available (the build runs on Windows).
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            version = wintypes.LPVOID()
            size = ctypes.windll.version.GetFileVersionInfoSizeW(str(path), None)
            if not size:
                raise ctypes.WinError()
            block = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(
                str(path), 0, size, block
            ):
                raise ctypes.WinError()
            value = wintypes.LPVOID()
            length = wintypes.UINT()
            if not ctypes.windll.version.VerQueryValueW(
                block,
                "\\",
                ctypes.byref(value),
                ctypes.byref(length),
            ):
                raise ctypes.WinError()
            fixed = ctypes.cast(value, ctypes.POINTER(wintypes.DWORD * 13)).contents
            # VS_FIXEDFILEINFO stores the four numeric components in two
            # 32-bit version fields after dwSignature/dwStrucVersion.
            version_ms = int(fixed[2])
            version_ls = int(fixed[3])
            file_version = ".".join(
                str(part)
                for part in (
                    version_ms >> 16,
                    version_ms & 0xFFFF,
                    version_ls >> 16,
                    version_ls & 0xFFFF,
                )
            )
        except (AttributeError, OSError):
            pass

    expected_version = _version_tuple(EXPECTED_FILE_VERSION)
    actual_version = _version_tuple(file_version)
    if actual_version and actual_version[:4] != expected_version:
        raise AnalysisError(
            f"{path}: file version mismatch (expected {EXPECTED_FILE_VERSION}, "
            f"got {file_version})"
        )


def _image_bytes(path: Path, pe: pefile.PE) -> bytes:
    return pe.get_memory_mapped_image()


def _section_for_rva(pe: pefile.PE, rva: int) -> pefile.SectionStructure | None:
    for section in pe.sections:
        start = int(section.VirtualAddress)
        end = start + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva < end:
            return section
    return None


def _executable_sections(pe: pefile.PE) -> list[pefile.SectionStructure]:
    sections: list[pefile.SectionStructure] = []
    for section in pe.sections:
        characteristics = int(section.Characteristics)
        if characteristics & 0x20000000 and not characteristics & 0x02000000:
            sections.append(section)
    return sorted(sections, key=lambda item: int(item.VirtualAddress))


def _parse_exports(pe: pefile.PE) -> dict[int, tuple[ExportAlias, ...]]:
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        raise AnalysisError("image has no export directory")
    by_rva: dict[int, list[ExportAlias]] = {}
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if symbol.address == 0:
            continue
        name = symbol.name.decode("ascii", "strict") if symbol.name else f"#{symbol.ordinal}"
        by_rva.setdefault(int(symbol.address), []).append(
            ExportAlias(name=name, ordinal=int(symbol.ordinal))
        )
    return {
        rva: tuple(sorted(entries, key=lambda item: (item.name, item.ordinal)))
        for rva, entries in by_rva.items()
    }


def _relocation_ranges(pe: pefile.PE) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ()) or ():
        for entry in block.entries:
            if entry.type == 0:
                continue
            ranges.append((int(entry.rva), int(entry.rva) + 8))
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _overlaps_any(
    start: int, end: int, ranges: Sequence[tuple[int, int]]
) -> bool:
    index = bisect.bisect_right(ranges, (start, sys.maxsize)) - 1
    if index >= 0 and ranges[index][1] > start:
        return True
    next_index = index + 1
    return next_index < len(ranges) and ranges[next_index][0] < end


def _decode_patch(
    image: bytes,
    rva: int,
    section_end: int,
    relocations: Sequence[tuple[int, int]],
    decoder: capstone.Cs,
) -> PatchDecode:
    if rva + 5 > section_end or rva + 5 > len(image):
        return PatchDecode(0, b"", "entry-or-patch-out-of-bounds")
    if _overlaps_any(rva, rva + 5, relocations):
        return PatchDecode(0, b"", "entry-or-patch-has-relocation")

    consumed = 0
    original = bytearray()
    rip_disp_offset: int | None = None
    rip_old_disp: int | None = None
    rip_target_rva: int | None = None
    rip_mnemonic: str | None = None
    decode_end = min(section_end, rva + MAX_COPY_INSTRUCTION_BYTES)
    for insn in decoder.disasm(image[rva:decode_end], rva):
        if insn.address != rva + len(original):
            return PatchDecode(0, b"", "non-contiguous-instruction-decoding")
        if len(original) + insn.size > MAX_COPY_INSTRUCTION_BYTES:
            return PatchDecode(0, b"", "first-instructions-too-long")
        if _overlaps_any(insn.address, insn.address + insn.size, relocations):
            return PatchDecode(0, b"", "first-instruction-has-relocation")
        if insn.group(capstone.CS_GRP_RET):
            return PatchDecode(0, b"", "first-instruction-is-ret")
        is_control_flow = insn.group(capstone.CS_GRP_JUMP) or insn.group(
            capstone.CS_GRP_CALL
        )
        is_relative_control_flow = is_control_flow and any(
            operand.type == capstone.CS_OP_IMM for operand in insn.operands
        )
        if is_relative_control_flow:
            return PatchDecode(
                0, b"", "first-instruction-is-relative-control-flow"
            )
        rip_operands = [
            operand
            for operand in insn.operands
            if operand.type == capstone.CS_OP_MEM
            and operand.mem.base == x86.X86_REG_RIP
        ]
        if len(rip_operands) > 1:
            return PatchDecode(0, b"", "multiple-rip-relative-operands")
        if rip_operands:
            if rip_disp_offset is not None:
                return PatchDecode(0, b"", "multiple-rip-relative-instructions")
            encoding = insn.encoding
            if encoding.disp_size != 4:
                return PatchDecode(0, b"", "unsupported-rip-relative-encoding")
            instruction_offset = len(original)
            rip_disp_offset = instruction_offset + int(encoding.disp_offset)
            if (
                rip_disp_offset < 0
                or int(encoding.disp_offset) + 4 > len(insn.bytes)
            ):
                return PatchDecode(0, b"", "invalid-rip-relative-encoding")
            rip_old_disp = struct.unpack_from(
                "<i", insn.bytes, encoding.disp_offset
            )[0]
            if rip_old_disp != int(rip_operands[0].mem.disp):
                return PatchDecode(0, b"", "rip-relative-encoding-mismatch")
            rip_target_rva = insn.address + insn.size + rip_old_disp
            rip_mnemonic = insn.mnemonic
        original.extend(insn.bytes)
        consumed = len(original)
        if consumed >= 5:
            return PatchDecode(
                consumed,
                bytes(original),
                None,
                rip_disp_offset,
                rip_old_disp,
                rip_target_rva,
                rip_mnemonic,
            )
    return PatchDecode(0, b"", "instruction-boundary-not-found")


def _safety_exclusion_reason(names: Sequence[str]) -> str | None:
    return next(
        (
            EXPORT_SAFETY_EXCLUSIONS[name]
            for name in names
            if name in EXPORT_SAFETY_EXCLUSIONS
        ),
        None,
    )


def analyze_module(
    module_id: int,
    name: str,
    expected_sha256: str,
    expected_timestamp: int,
    expected_size_of_image: int,
    path: Path,
) -> ModuleAnalysis:
    pe = pefile.PE(str(path), fast_load=False)
    try:
        _validate_identity(
            path,
            name,
            expected_sha256,
            expected_timestamp,
            expected_size_of_image,
            pe,
        )
        image = _image_bytes(path, pe)
        exports = _parse_exports(pe)
        relocations = _relocation_ranges(pe)
        executable_sections = _executable_sections(pe)
        executable_end = int(executable_sections[-1].VirtualAddress) + max(
            int(executable_sections[-1].Misc_VirtualSize),
            int(executable_sections[-1].SizeOfRawData),
        )
        export_images = sorted(exports)
        export_positions = {rva: index for index, rva in enumerate(export_images)}
        export_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
        ]
        forwarded_range = int(export_directory.VirtualAddress)
        forwarded_end = forwarded_range + int(export_directory.Size)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        decisions: list[ExportDecision] = []
        overlapping_rvas: set[int] = set()

        # Mark both sides of any pair whose two-byte patch roots overlap.  This
        # prevents installing the inner entry even when the enclosing entry was
        # itself rejected for another reason.
        for rva in export_images:
            section = _section_for_rva(pe, rva)
            if section is None or not (
                int(section.Characteristics) & 0x20000000
            ):
                continue
            section_end = int(section.VirtualAddress) + max(
                int(section.Misc_VirtualSize), int(section.SizeOfRawData)
            )
            next_index = export_positions[rva] + 1
            next_rva = (
                export_images[next_index]
                if next_index < len(export_images)
                else section_end
            )
            decoded = _decode_patch(
                image,
                rva,
                section_end,
                relocations,
                decoder,
            )
            if (
                decoded.failure is None
                and rva + decoded.length > next_rva
            ):
                overlapping_rvas.add(rva)
                overlapping_rvas.add(next_rva)

        for rva, aliases in exports.items():
            names = tuple(alias.name for alias in aliases)
            canonical = names[0]
            section = _section_for_rva(pe, rva)
            section_end = (
                int(section.VirtualAddress)
                + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
                if section is not None
                else 0
            )
            safety_reason = _safety_exclusion_reason(names)
            reason = ""
            patch_length = 0
            original = b""
            rip_disp_offset = None
            rip_old_disp = None
            rip_target_rva = None
            rip_mnemonic = None

            if forwarded_range <= rva < forwarded_end:
                reason = "forwarded-export"
            elif section is None or not (
                int(section.Characteristics) & 0x20000000
            ):
                reason = "data-or-non-executable-export"
            elif section_end > len(image):
                reason = "section-out-of-bounds"
            elif rva in overlapping_rvas:
                reason = "overlapping-export-entry"
            elif safety_reason is not None:
                reason = safety_reason
            else:
                decoded = _decode_patch(
                    image, rva, section_end, relocations, decoder
                )
                if decoded.failure:
                    reason = decoded.failure
                else:
                    patch_length = decoded.length
                    original = decoded.original
                    rip_disp_offset = decoded.rip_disp_offset
                    rip_old_disp = decoded.rip_old_disp
                    rip_target_rva = decoded.rip_target_rva
                    rip_mnemonic = decoded.rip_mnemonic

            installable = not reason
            decisions.append(
                ExportDecision(
                    module_id=module_id,
                    module_name=name,
                    rva=rva,
                    aliases=names,
                    canonical_name=canonical,
                    patch_length=patch_length,
                    original_bytes_hex=original.hex().upper(),
                    rip_disp_offset=rip_disp_offset,
                    rip_old_disp=rip_old_disp,
                    rip_target_rva=rip_target_rva,
                    rip_mnemonic=rip_mnemonic,
                    installable=installable,
                    reason=reason or "ok",
                )
            )

        installable = tuple(item for item in decisions if item.installable)
        skipped = tuple(item for item in decisions if not item.installable)
        rip_items = tuple(
            item
            for item in installable
            if item.rip_disp_offset is not None
        )
        return ModuleAnalysis(
            module_id=module_id,
            name=name,
            canonical_image_name=rf"\SystemRoot\System32\{path.name}",
            sha256=expected_sha256,
            timestamp=int(pe.FILE_HEADER.TimeDateStamp),
            size_of_image=int(pe.OPTIONAL_HEADER.SizeOfImage),
            executable_end_rva=executable_end,
            exports_seen=len(decisions),
            installable=installable,
            skipped=skipped,
            rip_fixup_count=len(rip_items),
            rip_target_min_rva=(
                min(item.rip_target_rva for item in rip_items)
                if rip_items
                else None
            ),
            rip_target_max_rva=(
                max(item.rip_target_rva for item in rip_items)
                if rip_items
                else None
            ),
            rip_disp_min=(
                min(item.rip_old_disp for item in rip_items)
                if rip_items
                else None
            ),
            rip_disp_max=(
                max(item.rip_old_disp for item in rip_items)
                if rip_items
                else None
            ),
        )
    finally:
        pe.close()


def analyze_all(
    target_dir: Path,
) -> tuple[ModuleAnalysis, ...]:
    analyses: list[ModuleAnalysis] = []
    for (
        module_id,
        name,
        expected_hash,
        expected_timestamp,
        expected_size,
    ) in TARGET_IDENTITIES:
        path = target_dir / name
        if not path.is_file():
            raise AnalysisError(f"missing target DLL: {path}")
        analyses.append(
            analyze_module(
                module_id,
                name,
                expected_hash,
                expected_timestamp,
                expected_size,
                path,
            )
        )
    result = tuple(analyses)
    _validate_rip_relative_layouts(result)
    return result


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _module_stub_layout(
    analysis: ModuleAnalysis,
) -> tuple[dict[int, tuple[int, int]], int]:
    offsets: dict[int, tuple[int, int]] = {}
    module_bytes = 0
    for item in analysis.installable:
        stub_size = _align_up(
            STUB_FIXED_SIZE + item.patch_length, STUB_ALIGNMENT
        )
        offsets[item.rva] = (STUB_HEADER_SIZE + module_bytes, stub_size)
        module_bytes += stub_size
    return offsets, STUB_HEADER_SIZE + module_bytes


def _stub_candidate_offsets(module_size: int) -> tuple[int, ...]:
    rounded_size = _align_up(module_size, 0x10000)
    candidates: list[int] = []
    for offset in range(
        STUB_SEARCH_START, STUB_SEARCH_LIMIT + 1, STUB_SEARCH_STEP
    ):
        candidates.append(-(offset + rounded_size))
        candidates.append(offset)
    return tuple(candidates)


def _encode_rel32(source: int, destination: int) -> int | None:
    displacement = destination - (source + 5)
    if INT32_MIN <= displacement <= INT32_MAX:
        return displacement
    return None


def _module_stub_candidate_feasible(
    analysis: ModuleAnalysis,
    offsets: dict[int, tuple[int, int]],
    stub_relative_offset: int,
) -> bool:
    for item in analysis.installable:
        stub_offset, _stub_size = offsets[item.rva]
        if (
            _encode_rel32(item.rva, stub_relative_offset + stub_offset)
            is None
        ):
            return False

        continuation_source = (
            stub_relative_offset
            + stub_offset
            + STUB_ORIGINAL_OFFSET
            + item.patch_length
        )
        if (
            _encode_rel32(
                continuation_source, item.rva + item.patch_length
            )
            is None
        ):
            return False

        if item.rip_disp_offset is not None:
            assert item.rip_old_disp is not None
            delta = (
                stub_relative_offset
                + stub_offset
                + STUB_ORIGINAL_OFFSET
                - item.rva
            )
            new_disp = item.rip_old_disp - delta
            if not INT32_MIN <= new_disp <= INT32_MAX:
                return False
    return True


def _validate_rip_relative_layouts(
    analyses: Sequence[ModuleAnalysis],
) -> None:
    failures: list[str] = []
    for analysis in analyses:
        patch_ranges = [
            (item.rva, item.rva + item.patch_length, item)
            for item in analysis.installable
        ]

        module_failed = False
        for item in analysis.installable:
            if item.rip_target_rva is None:
                continue
            for start, end, destination in patch_ranges:
                if start <= item.rip_target_rva < end:
                    override = RIP_RELATIVE_OVERLAP_OVERRIDES.get(
                        (analysis.sha256, item.rva, item.rip_target_rva)
                    )
                    if (
                        override is not None
                        and item.rip_mnemonic == override
                    ):
                        break
                    failures.append(
                        "RIP-relative target overlaps an overwritten patch "
                        f"range: module={analysis.name} "
                        f"sha256={analysis.sha256} rva=0x{item.rva:X} "
                        f"symbol={item.canonical_name} "
                        f"target_rva=0x{item.rip_target_rva:X} "
                        f"patch=[0x{start:X},0x{end:X}) "
                        f"patch_symbol={destination.canonical_name}"
                    )
                    module_failed = True
                    break

        if module_failed:
            continue

        offsets, module_size = _module_stub_layout(analysis)
        candidates = _stub_candidate_offsets(module_size)
        if not any(
            _module_stub_candidate_feasible(analysis, offsets, candidate)
            for candidate in candidates
        ):
            target_min = (
                analysis.rip_target_min_rva
                if analysis.rip_target_min_rva is not None
                else 0
            )
            target_max = (
                analysis.rip_target_max_rva
                if analysis.rip_target_max_rva is not None
                else 0
            )
            failures.append(
                "No near-stub address can encode all rel32 references for "
                f"module={analysis.name} sha256={analysis.sha256}; "
                f"stub_size=0x{module_size:X} "
                f"rip_target_rva=[0x{target_min:X},0x{target_max:X}] "
                f"rip_disp=[{analysis.rip_disp_min},"
                f"{analysis.rip_disp_max}] "
                "search=[-0x"
                f"{STUB_SEARCH_LIMIT + _align_up(module_size, 0x10000):X},"
                f"+0x{STUB_SEARCH_LIMIT:X}]"
            )

    if failures:
        raise AnalysisError(
            "RIP-relative relocation requires target-specific handling:\n  "
            + "\n  ".join(failures)
        )


def _c_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _wide_c_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'L"{escaped}"'


def _write_csv(path: Path, analyses: Sequence[ModuleAnalysis]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "module",
                "rva",
                "patch_length",
                "original_bytes",
                "aliases",
                "canonical_name",
                "reason",
            ]
        )
        for analysis in analyses:
            for item in analysis.skipped:
                writer.writerow(
                    [
                        analysis.name,
                        f"0x{item.rva:X}",
                        item.patch_length,
                        item.original_bytes_hex,
                        ";".join(item.aliases),
                        item.canonical_name,
                        item.reason,
                    ]
                )


def _write_json(path: Path, analyses: Sequence[ModuleAnalysis]) -> None:
    payload = []
    for analysis in analyses:
        payload.append(
            {
                "module_id": analysis.module_id,
                "name": analysis.name,
                "canonical_image_name": analysis.canonical_image_name,
                "sha256": analysis.sha256,
                "timestamp": analysis.timestamp,
                "size_of_image": analysis.size_of_image,
                "executable_end_rva": analysis.executable_end_rva,
                "exports_seen": analysis.exports_seen,
                "installable_count": len(analysis.installable),
                "skipped_count": len(analysis.skipped),
                "installable": [
                    {
                        "rva": item.rva,
                        "canonical_name": item.canonical_name,
                        "aliases": item.aliases,
                        "patch_length": item.patch_length,
                        "original_bytes": item.original_bytes_hex,
                        "rip_disp_offset": item.rip_disp_offset,
                        "rip_old_disp": item.rip_old_disp,
                        "rip_target_rva": item.rip_target_rva,
                        "rip_mnemonic": item.rip_mnemonic,
                    }
                    for item in analysis.installable
                ],
                "skipped": [
                    {
                        "rva": item.rva,
                        "canonical_name": item.canonical_name,
                        "aliases": item.aliases,
                        "reason": item.reason,
                    }
                    for item in analysis.skipped
                ],
                "rip_fixup_count": analysis.rip_fixup_count,
                "rip_target_min_rva": analysis.rip_target_min_rva,
                "rip_target_max_rva": analysis.rip_target_max_rva,
                "rip_disp_min": analysis.rip_disp_min,
                "rip_disp_max": analysis.rip_disp_max,
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_header(path: Path, analyses: Sequence[ModuleAnalysis]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "/* Generated by tools/analyze_targets.py. Do not edit. */",
        "#ifndef WIN_API_LOGGER_GENERATED_METADATA_H",
        "#define WIN_API_LOGGER_GENERATED_METADATA_H",
        "",
        "#include <stdint.h>",
        "",
        "#pragma pack(push, 1)",
        "typedef struct _LOGGER_STATIC_MODULE {",
        "    uint64_t timestamp;",
        "    uint32_t size_of_image;",
        "    uint32_t module_id;",
        "    uint32_t executable_end_rva;",
        "    const char *name;",
        "    const WCHAR *base_name;",
        "    const WCHAR *canonical_image_name;",
        "    const char *sha256;",
        "} LOGGER_STATIC_MODULE;",
        "",
        "typedef struct _LOGGER_STATIC_EXPORT {",
        "    uint32_t module_id;",
        "    uint32_t hook_rva;",
        "    uint32_t patch_length;",
        "    uint8_t original_bytes[15];",
        "    uint8_t rip_disp_offset;",
        "    int32_t rip_target_rva;",
        "    const char *canonical_name;",
        "    const char *aliases;",
        "} LOGGER_STATIC_EXPORT;",
        "#pragma pack(pop)",
        "",
        "#define LOGGER_MODULE_COUNT 3u",
        f"#define LOGGER_STUB_HEADER_SIZE {STUB_HEADER_SIZE}u",
        f"#define LOGGER_STUB_FIXED_SIZE {STUB_FIXED_SIZE}u",
        f"#define LOGGER_STUB_ORIGINAL_OFFSET {STUB_ORIGINAL_OFFSET}u",
        f"#define LOGGER_NEAR_STUB_START 0x{STUB_SEARCH_START:X}u",
        f"#define LOGGER_NEAR_STUB_STEP 0x{STUB_SEARCH_STEP:X}u",
        f"#define LOGGER_NEAR_STUB_LIMIT 0x{STUB_SEARCH_LIMIT:X}u",
        f"#define LOGGER_RIP_DISP_NONE 0x{RIP_DISP_NONE:X}u",
        f"#define LOGGER_INSTALLABLE_EXPORT_COUNT {sum(len(a.installable) for a in analyses)}u",
        "",
        "static const LOGGER_STATIC_MODULE g_static_modules[LOGGER_MODULE_COUNT] = {",
    ]
    for analysis in analyses:
        lines.append(
            "    {"
            f"0x{analysis.timestamp:08X}ULL, 0x{analysis.size_of_image:X}u, "
            f"{analysis.module_id}u, 0x{analysis.executable_end_rva:X}u, "
            f"{_c_string(analysis.name)}, "
            f"{_wide_c_string(analysis.name)}, "
            f"{_wide_c_string(analysis.canonical_image_name)}, "
            f"{_c_string(analysis.sha256)}"
            "},"
        )
    lines.extend(
        [
            "};",
            "",
            "static const LOGGER_STATIC_EXPORT "
            "g_static_exports[LOGGER_INSTALLABLE_EXPORT_COUNT] = {",
        ]
    )
    for analysis in analyses:
        for item in analysis.installable:
            byte_values = bytes.fromhex(item.original_bytes_hex)
            padded = list(byte_values) + [0] * (15 - len(byte_values))
            byte_text = ", ".join(f"0x{value:02X}" for value in padded)
            aliases = ";".join(item.aliases)
            rip_disp_offset = (
                RIP_DISP_NONE
                if item.rip_disp_offset is None
                else item.rip_disp_offset
            )
            rip_target_rva = item.rip_target_rva or 0
            lines.append(
                "    {"
                f"{item.module_id}u, 0x{item.rva:X}u, {item.patch_length}u, "
                f"{{{byte_text}}}, {rip_disp_offset}u, "
                f"0x{rip_target_rva & 0xFFFFFFFF:X}u, "
                f"{_c_string(item.canonical_name)}, "
                f"{_c_string(aliases)}"
                "},"
            )
    lines.extend(["};", "", "#endif", ""])
    path.write_text("\r\n".join(lines), encoding="utf-8", newline="\n")


def _write_name_table(
    path: Path,
    analyses: Sequence[ModuleAnalysis],
) -> None:
    """Write a compact lookup table used by the reader."""
    path.parent.mkdir(parents=True, exist_ok=True)
    entries: list[tuple[int, int, str, str]] = []
    for analysis in analyses:
        for item in analysis.installable:
            entries.append(
                (
                    item.module_id,
                    item.rva,
                    item.canonical_name,
                    ";".join(item.aliases),
                )
            )
        for item in analysis.skipped:
            # The reader can still name a skipped RVA, but it will never receive
            # one from the logger.  Keeping those entries makes diagnostics and
            # older logs forward-compatible.
            entries.append(
                (
                    item.module_id,
                    item.rva,
                    item.canonical_name,
                    ";".join(item.aliases),
                )
            )
    entries.sort(key=lambda item: (item[0], item[1], item[2]))
    lines = [
        "/* Generated by tools/analyze_targets.py. Do not edit. */",
        "#ifndef WIN_API_LOGGER_GENERATED_NAMES_H",
        "#define WIN_API_LOGGER_GENERATED_NAMES_H",
        "",
        "#include <stdint.h>",
        "",
        "#pragma pack(push, 1)",
        "typedef struct _LOGGER_MODULE_NAME_ENTRY {",
        "    uint32_t module_id;",
        "    const char *base_name;",
        "} LOGGER_MODULE_NAME_ENTRY;",
        "",
        "typedef struct _LOGGER_NAME_ENTRY {",
        "    uint32_t module_id;",
        "    uint32_t hook_rva;",
        "    const char *canonical_name;",
        "    const char *aliases;",
        "} LOGGER_NAME_ENTRY;",
        "#pragma pack(pop)",
        "",
        f"#define LOGGER_MODULE_NAME_ENTRY_COUNT {len(analyses)}u",
        f"#define LOGGER_NAME_ENTRY_COUNT {len(entries)}u",
        "static const LOGGER_MODULE_NAME_ENTRY "
        "g_module_name_entries[LOGGER_MODULE_NAME_ENTRY_COUNT] = {",
    ]
    for analysis in analyses:
        lines.append(
            f"    {{{analysis.module_id}u, "
            f"{_c_string(Path(analysis.name).stem)}}},"
        )
    lines.extend(
        [
            "};",
            "",
        "static const LOGGER_NAME_ENTRY g_name_entries[LOGGER_NAME_ENTRY_COUNT] = {",
        ]
    )
    for module_id, rva, canonical, aliases in entries:
        lines.append(
            f"    {{{module_id}u, 0x{rva:X}u, {_c_string(canonical)}, "
            f"{_c_string(aliases)}}},"
        )
    lines.extend(["};", "", "#endif", ""])
    path.write_text("\r\n".join(lines), encoding="utf-8", newline="\n")


def _write_rip_relative_report(
    path: Path, analyses: Sequence[ModuleAnalysis]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "module",
                "rva",
                "canonical_name",
                "patch_length",
                "disp_offset",
                "old_disp",
                "target_rva",
                "mnemonic",
            ]
        )
        for analysis in analyses:
            for item in analysis.installable:
                if item.rip_disp_offset is None:
                    continue
                writer.writerow(
                    [
                        analysis.name,
                        f"0x{item.rva:X}",
                        item.canonical_name,
                        item.patch_length,
                        item.rip_disp_offset,
                        item.rip_old_disp,
                        f"0x{item.rip_target_rva & 0xFFFFFFFF:X}",
                        item.rip_mnemonic,
                    ]
                )


def emit(
    target_dir: Path,
    build_dir: Path,
    driver_include_dir: Path,
    reader_include_dir: Path,
) -> tuple[ModuleAnalysis, ...]:
    analyses = analyze_all(target_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(build_dir / "skipped_exports.csv", analyses)
    _write_json(build_dir / "analysis.json", analyses)
    _write_rip_relative_report(build_dir / "rip_relative.csv", analyses)
    _write_header(driver_include_dir / "generated_metadata.h", analyses)
    _write_name_table(reader_include_dir / "generated_names.h", analyses)
    return analyses


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=Path("target_dlls"))
    parser.add_argument("--build", type=Path, default=Path("build"))
    parser.add_argument(
        "--driver-include", type=Path, default=Path("driver/generated")
    )
    parser.add_argument(
        "--reader-include", type=Path, default=Path("reader/generated")
    )
    args = parser.parse_args(argv)
    try:
        analyses = emit(
            args.targets.resolve(),
            args.build.resolve(),
            args.driver_include.resolve(),
            args.reader_include.resolve(),
        )
    except (AnalysisError, OSError, pefile.PEFormatError) as exc:
        print(f"analyze_targets: {exc}", file=sys.stderr)
        return 1

    total_unique = sum(len(item.installable) + len(item.skipped) for item in analyses)
    total_installable = sum(len(item.installable) for item in analyses)
    total_skipped = sum(len(item.skipped) for item in analyses)
    forwarded = sum(
        item.reason == "forwarded-export"
        for analysis in analyses
        for item in analysis.skipped
    )
    data_exports = sum(
        item.reason == "data-or-non-executable-export"
        for analysis in analyses
        for item in analysis.skipped
    )
    executable_exports = total_unique - forwarded - data_exports
    print(f"modules: {len(analyses)}")
    print(f"unique export RVAs: {total_unique}")
    print(f"forwarded exports: {forwarded}")
    print(f"data exports: {data_exports}")
    print(f"unique executable exports: {executable_exports}")
    print(f"installable: {total_installable}")
    print(f"skipped executable exports: {total_skipped - forwarded - data_exports}")
    for analysis in analyses:
        print(
            f"  {analysis.module_id}: {analysis.name}: "
            f"{len(analysis.installable)} installable, "
            f"{len(analysis.skipped)} skipped"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

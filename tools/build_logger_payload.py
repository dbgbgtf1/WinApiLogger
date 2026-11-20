#!/usr/bin/env python3
"""Convert the freestanding logger COFF object into a loadable byte image."""

from __future__ import annotations

import argparse
import dataclasses
import struct
import sys
from pathlib import Path
from typing import Sequence


IMAGE_REL_AMD64_ADDR64 = 0x0001
IMAGE_REL_AMD64_REL32 = 0x0004
IMAGE_REL_AMD64_REL32_1 = 0x0005
IMAGE_REL_AMD64_REL32_2 = 0x0006
IMAGE_REL_AMD64_REL32_3 = 0x0007
IMAGE_REL_AMD64_REL32_4 = 0x0008
IMAGE_REL_AMD64_REL32_5 = 0x0009

REL32_TYPES = {
    IMAGE_REL_AMD64_REL32: 0,
    IMAGE_REL_AMD64_REL32_1: 1,
    IMAGE_REL_AMD64_REL32_2: 2,
    IMAGE_REL_AMD64_REL32_3: 3,
    IMAGE_REL_AMD64_REL32_4: 4,
    IMAGE_REL_AMD64_REL32_5: 5,
}

SELECTED_SECTIONS = (".text",)
SECTION_ALIGNMENT = 16


class PayloadError(RuntimeError):
    pass


@dataclasses.dataclass
class CoffSection:
    name: str
    raw: bytes
    characteristics: int
    relocations: list[tuple[int, int, int]] = dataclasses.field(default_factory=list)
    image_rva: int = 0


@dataclasses.dataclass(frozen=True)
class CoffSymbol:
    name: str
    value: int
    section_number: int


@dataclasses.dataclass
class CoffObject:
    sections: list[CoffSection]
    symbols: dict[int, CoffSymbol]


def _read_name(blob: bytes, offset: int, string_table: bytes) -> str:
    if blob[:4] == b"\x00\x00\x00\x00":
        name_offset = struct.unpack_from("<I", blob, 4)[0]
        if name_offset < 4 or name_offset >= len(string_table):
            raise PayloadError(f"invalid COFF string-table offset {name_offset}")
        end = string_table.find(b"\x00", name_offset)
        if end < 0:
            end = len(string_table)
        return string_table[name_offset:end].decode("utf-8", "strict")
    end = blob.find(b"\x00")
    if end < 0:
        end = len(blob)
    return blob[:end].decode("ascii", "strict")


def parse_coff(path: Path) -> CoffObject:
    blob = path.read_bytes()
    if len(blob) < 20:
        raise PayloadError("COFF object is truncated")
    machine, section_count, timestamp, symbol_table_offset, symbol_count, \
        optional_header_size, characteristics = struct.unpack_from("<HHIIIHH", blob, 0)
    if machine != 0x8664:
        raise PayloadError(f"expected AMD64 COFF object, got machine 0x{machine:04X}")
    if optional_header_size != 0:
        raise PayloadError("object unexpectedly contains an optional header")

    section_table_offset = 20
    sections: list[CoffSection] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        if offset + 40 > len(blob):
            raise PayloadError("truncated section table")
        raw_name = blob[offset:offset + 8]
        (virtual_size, virtual_address, raw_size, raw_pointer,
         relocation_pointer, line_pointer, relocation_count,
         line_count, section_characteristics) = struct.unpack_from(
            "<IIIIIIHHI", blob, offset + 8
        )
        name = raw_name.rstrip(b"\x00").decode("ascii", "strict")
        raw = blob[raw_pointer:raw_pointer + raw_size] if raw_size else b""
        if len(raw) != raw_size:
            raise PayloadError(f"section {name} raw data is truncated")
        section = CoffSection(
            name=name,
            raw=raw,
            characteristics=section_characteristics,
        )
        for relocation_index in range(relocation_count):
            relocation_offset = relocation_pointer + relocation_index * 10
            if relocation_offset + 10 > len(blob):
                raise PayloadError(f"section {name} relocations are truncated")
            (
                relocation_rva,
                symbol_index,
                relocation_type,
            ) = struct.unpack_from("<IIH", blob, relocation_offset)
            section.relocations.append(
                (int(relocation_rva), int(symbol_index), int(relocation_type))
            )
        sections.append(section)

    string_table_offset = symbol_table_offset + symbol_count * 18
    if string_table_offset + 4 > len(blob):
        raise PayloadError("COFF symbol string table is truncated")
    string_table_size = struct.unpack_from("<I", blob, string_table_offset)[0]
    string_table_end = string_table_offset + string_table_size
    if string_table_size < 4 or string_table_end > len(blob):
        raise PayloadError("invalid COFF symbol string table")
    string_table = blob[string_table_offset:string_table_end]

    symbols: dict[int, CoffSymbol] = {}
    symbol_offset = symbol_table_offset
    index = 0
    while index < symbol_count:
        if symbol_offset + 18 > len(blob):
            raise PayloadError("COFF symbols are truncated")
        raw_name = blob[symbol_offset:symbol_offset + 8]
        value, section_number, symbol_type, storage_class, auxiliary_count = \
            struct.unpack_from("<IhHBB", blob, symbol_offset + 8)
        name = _read_name(raw_name, 0, string_table)
        symbols[index] = CoffSymbol(
            name=name,
            value=int(value),
            section_number=int(section_number),
        )
        # Section symbols and file symbols are useful even if storage class is
        # static.  Auxiliary records are skipped while preserving their
        # original symbol-table indices for relocation lookup.
        step = 1 + auxiliary_count
        symbol_offset += step * 18
        index += step
    return CoffObject(sections=sections, symbols=symbols)


def _select_sections(coff: CoffObject) -> list[CoffSection]:
    selected: list[CoffSection] = []
    for name in SELECTED_SECTIONS:
        matches = [section for section in coff.sections if section.name == name]
        if len(matches) > 1:
            raise PayloadError(f"multiple {name} sections are unsupported")
        if matches:
            selected.append(matches[0])
    if not any(section.name == ".text" for section in selected):
        raise PayloadError("COFF object has no .text section")
    return selected


def build_payload(coff: CoffObject) -> tuple[bytes, dict[str, int], list[CoffSection]]:
    sections = _select_sections(coff)
    image = bytearray()
    for section in sections:
        while len(image) % SECTION_ALIGNMENT:
            image.append(0)
        section.image_rva = len(image)
        image.extend(section.raw)
    while len(image) % SECTION_ALIGNMENT:
        image.append(0)

    section_by_index = {
        index + 1: section
        for index, section in enumerate(coff.sections)
    }

    def symbol_rva(index: int) -> int:
        symbol = coff.symbols.get(index)
        if symbol is None:
            raise PayloadError(f"relocation references missing symbol {index}")
        if symbol.section_number <= 0:
            raise PayloadError(
                f"unresolved external symbol {symbol.name!r} in logger payload"
            )
        section = section_by_index.get(symbol.section_number)
        if section is None:
            raise PayloadError(
                f"symbol {symbol.name!r} references unknown section "
                f"{symbol.section_number}"
            )
        if section.name not in SELECTED_SECTIONS:
            raise PayloadError(
                f"symbol {symbol.name!r} references unsupported section {section.name}"
            )
        return section.image_rva + symbol.value

    for section in sections:
        for relocation_rva, symbol_index, relocation_type in section.relocations:
            location_rva = section.image_rva + relocation_rva
            target_rva = symbol_rva(symbol_index)
            if relocation_type == IMAGE_REL_AMD64_ADDR64:
                if location_rva + 8 > len(image):
                    raise PayloadError("ADDR64 relocation exceeds payload")
                addend = struct.unpack_from("<q", image, location_rva)[0]
                struct.pack_into("<Q", image, location_rva, target_rva + addend)
                continue
            suffix = REL32_TYPES.get(relocation_type)
            if suffix is None:
                raise PayloadError(
                    f"unsupported COFF relocation type 0x{relocation_type:04X}"
                )
            if location_rva + 4 > len(image):
                raise PayloadError("REL32 relocation exceeds payload")
            addend = struct.unpack_from("<i", image, location_rva)[0]
            displacement = target_rva + addend - (location_rva + 4 + suffix)
            try:
                struct.pack_into("<i", image, location_rva, displacement)
            except struct.error as exc:
                raise PayloadError("REL32 relocation overflow") from exc

    wanted = {
        "LoggerEntry": -1,
        "LoggerHandle": -1,
    }
    for symbol in coff.symbols.values():
        if symbol.name not in wanted or symbol.section_number <= 0:
            continue
        section = section_by_index[symbol.section_number]
        if section.name in SELECTED_SECTIONS:
            wanted[symbol.name] = section.image_rva + symbol.value
    missing = [name for name, rva in wanted.items() if rva < 0]
    if missing:
        raise PayloadError(f"missing required COFF symbols: {', '.join(missing)}")
    return bytes(image), wanted, sections


def write_binary(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def write_header(path: Path, payload: bytes, symbols: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "/* Generated by tools/build_logger_payload.py. Do not edit. */",
        "#ifndef WIN_API_LOGGER_GENERATED_PAYLOAD_H",
        "#define WIN_API_LOGGER_GENERATED_PAYLOAD_H",
        "",
        "#include <stdint.h>",
        "",
        f"#define LOGGER_PAYLOAD_SIZE {len(payload)}u",
        f"#define LOGGER_PAYLOAD_ENTRY_RVA 0x{symbols['LoggerEntry']:X}u",
        "",
        "static const uint8_t g_logger_payload[LOGGER_PAYLOAD_SIZE] = {",
    ]
    for offset in range(0, len(payload), 16):
        chunk = payload[offset:offset + 16]
        lines.append("    " + ", ".join(f"0x{value:02X}" for value in chunk) + ",")
    lines.extend(["};", "", "#endif", ""])
    path.write_text("\r\n".join(lines), encoding="utf-8", newline="\n")


def write_report(
    path: Path,
    payload: bytes,
    symbols: dict[str, int],
    sections: Sequence[CoffSection],
) -> None:
    lines = [
        "logger payload report",
        f"size=0x{len(payload):X}",
    ]
    for name, rva in symbols.items():
        lines.append(f"{name}=0x{rva:X}")
    for section in sections:
        lines.append(
            f"section {section.name}: rva=0x{section.image_rva:X}, "
            f"size=0x{len(section.raw):X}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object", type=Path)
    parser.add_argument("--binary", type=Path, default=Path("build/logger_payload.bin"))
    parser.add_argument(
        "--header",
        type=Path,
        default=Path("driver/generated/generated_payload.h"),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("build/logger_payload.txt"),
    )
    args = parser.parse_args(argv)
    try:
        coff = parse_coff(args.object.resolve())
        payload, symbols, sections = build_payload(coff)
        write_binary(args.binary.resolve(), payload)
        write_header(args.header.resolve(), payload, symbols)
        write_report(args.report.resolve(), payload, symbols, sections)
    except (OSError, PayloadError, struct.error) as exc:
        print(f"build_logger_payload: {exc}", file=sys.stderr)
        return 1
    print(
        f"logger payload: {len(payload)} bytes, "
        f"entry RVA 0x{symbols['LoggerEntry']:X}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

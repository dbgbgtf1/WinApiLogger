#!/usr/bin/env python3
"""Generate compile_commands.json from the active MSVC, SDK and LLVM installs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def _posix(path: Path) -> str:
    return path.resolve().as_posix()


def _system_include(path: Path) -> list[str]:
    return ["/imsvc", _posix(path)]


def generate(
    workspace: Path,
    clang: Path,
    clang_cl: Path,
    msvc_include: Path,
    kit_include: Path,
) -> list[dict[str, object]]:
    workspace = workspace.resolve()
    clang = clang.resolve()
    clang_cl = clang_cl.resolve()
    msvc_include = msvc_include.resolve()
    kit_include = kit_include.resolve()

    driver_sources = (
        "driver/driver.c",
        "driver/process.c",
        "driver/image.c",
        "driver/memory.c",
        "driver/queue.c",
        "driver/ioctl.c",
    )
    driver_entries = []
    for source in driver_sources:
        driver_entries.append(
            {
                "directory": _posix(workspace),
                "file": source,
                "arguments": [
                    _posix(clang_cl),
                    "--target=x86_64-pc-windows-msvc",
                    "/nologo",
                    "/c",
                    "/TC",
                    "/D_KERNEL_MODE=1",
                    "/DUNICODE",
                    "/D_UNICODE",
                    "/D_AMD64_",
                    "/D_WIN64",
                    "/DAMD64",
                    "/DWIN32=100",
                    "/D_WIN32_WINNT=0x0A00",
                    "/DNTDDI_VERSION=0x0A00000C",
                    "/I.",
                    *_system_include(kit_include / "km"),
                    *_system_include(kit_include / "shared"),
                    *_system_include(kit_include / "ucrt"),
                    *_system_include(kit_include / "um"),
                    *_system_include(msvc_include),
                    source,
                ],
            }
        )
    logger_arguments = [
        _posix(clang),
        "--target=x86_64-pc-windows-msvc",
        "-O2",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-builtin",
        "-fno-exceptions",
        "-fno-rtti",
        "-D_LOGGER_FREESTANDING",
        "-c",
        "logger/logger.c",
    ]
    reader_arguments = [
        _posix(clang_cl),
        "--target=x86_64-pc-windows-msvc",
        "/nologo",
        "/c",
        "/TC",
        "/DUNICODE",
        "/D_UNICODE",
        "/DWIN32=100",
        "/D_WIN32_WINNT=0x0A00",
        "/I.",
        *_system_include(kit_include / "ucrt"),
        *_system_include(kit_include / "shared"),
        *_system_include(kit_include / "um"),
        *_system_include(msvc_include),
        "reader/reader.c",
    ]
    runtime_test_arguments = [
        _posix(clang_cl),
        "--target=x86_64-pc-windows-msvc",
        "/nologo",
        "/c",
        "/TC",
        "/std:c11",
        "/DUNICODE",
        "/D_UNICODE",
        "/DWIN32=100",
        "/D_WIN32_WINNT=0x0A00",
        "/I.",
        *_system_include(kit_include / "ucrt"),
        *_system_include(kit_include / "shared"),
        *_system_include(kit_include / "um"),
        *_system_include(msvc_include),
        "tests/logger_runtime_test.c",
    ]
    reader_test_arguments = [
        _posix(clang_cl),
        "--target=x86_64-pc-windows-msvc",
        "/nologo",
        "/c",
        "/TC",
        "/std:c11",
        "/DUNICODE",
        "/D_UNICODE",
        "/DWIN32=100",
        "/D_WIN32_WINNT=0x0A00",
        "/I.",
        *_system_include(kit_include / "ucrt"),
        *_system_include(kit_include / "shared"),
        *_system_include(kit_include / "um"),
        *_system_include(msvc_include),
        "tests/reader_format_test.c",
    ]

    return [
        *driver_entries,
        {
            "directory": _posix(workspace),
            "file": "logger/logger.c",
            "arguments": logger_arguments,
        },
        {
            "directory": _posix(workspace),
            "file": "reader/reader.c",
            "arguments": reader_arguments,
        },
        {
            "directory": _posix(workspace),
            "file": "tests/logger_runtime_test.c",
            "arguments": runtime_test_arguments,
        },
        {
            "directory": _posix(workspace),
            "file": "tests/reader_format_test.c",
            "arguments": reader_test_arguments,
        },
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--clang-cl", type=Path, required=True)
    parser.add_argument("--msvc-include", type=Path, required=True)
    parser.add_argument("--kit-include", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("compile_commands.json"),
    )
    args = parser.parse_args(argv)

    entries = generate(
        args.workspace,
        args.clang,
        args.clang_cl,
        args.msvc_include,
        args.kit_include,
    )
    output = args.output.resolve()
    output.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"compile database: {output} ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

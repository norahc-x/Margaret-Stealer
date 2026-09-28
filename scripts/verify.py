#!/usr/bin/env python3
"""Deterministic static gates for the Margaret x64 PIC build."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Iterable


FORBIDDEN_SYMBOLS = {
    "__chkstk",
    "__chkstk_ms",
    "__security_cookie",
    "__security_check_cookie",
    "memcpy",
    "memmove",
    "memset",
    "malloc",
    "free",
    "mainCRTStartup",
    "_pei386_runtime_relocator",
}

ALLOWED_OBJECT_SECTIONS = {
    ".text$A", ".text$B", ".text$C", ".text$D", ".text$E", ".text$F",
    ".text$G", ".text$H", ".text$R", ".text$Z",
}
CODE_OBJECT_SECTIONS = {
    ".text$A", ".text$B", ".text$C", ".text$D", ".text$E", ".text$F", ".text$G", ".text$H", ".text$Z",
}
ALLOWED_AMD64_RELOCATIONS = {
    "IMAGE_REL_AMD64_REL32",
    "IMAGE_REL_AMD64_REL32_1",
    "IMAGE_REL_AMD64_REL32_2",
    "IMAGE_REL_AMD64_REL32_3",
    "IMAGE_REL_AMD64_REL32_4",
    "IMAGE_REL_AMD64_REL32_5",
}
EXPECTED_CODE_SECTION_BY_OBJECT = {
    "entry_x64.obj": [".text$A"],
    "entry.obj": [".text$B"],
    "runtime.obj": [".text$C"],
    "resolve.obj": [".text$D"],
    "adapter.obj": [".text$E", ".text$R"],
    "engine_a.obj": [".text$F"],
    "cc_layout.obj": [".text$H"],
    "end_x64.obj": [".text$Z"],
}


def run(argv: list[str]) -> str:
    proc = subprocess.run(argv, check=False, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(argv)}\n{proc.stdout}")
    return proc.stdout


def write_text(path: pathlib.Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_version(tool: str) -> str:
    return run([tool, "--version"]).splitlines()[0]


def parse_sections(text: str) -> dict[str, int]:
    sections: dict[str, int] = {}
    pattern = re.compile(r"^\s*\d+\s+(\S+)\s+([0-9A-Fa-f]+)\s+", re.MULTILINE)
    for match in pattern.finditer(text):
        sections[match.group(1)] = int(match.group(2), 16)
    return sections


def parse_section_flags(text: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    lines = text.splitlines()
    header = re.compile(r"^\s*\d+\s+(\S+)\s+([0-9A-Fa-f]+)\s+")
    for index, line in enumerate(lines):
        match = header.match(line)
        if not match:
            continue
        flags: set[str] = set()
        if index + 1 < len(lines):
            flags = {value.strip() for value in lines[index + 1].split(",")
                     if value.strip()}
        result[match.group(1)] = flags
    return result


def parse_relocation_types(text: str) -> set[str]:
    return set(re.findall(r"IMAGE_REL_AMD64_[A-Z0-9_]+", text))


def parse_nm_symbols(text: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9A-Fa-f]+)\s+\S\s+(\S+)$", line.strip())
        if match:
            symbols[match.group(2)] = int(match.group(1), 16)
    return symbols


def parse_undefined(text: str) -> set[str]:
    result: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] == "U":
            result.add(fields[-1])
        elif len(fields) == 2 and fields[0] == "U":
            result.add(fields[1])
    return result


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def gate_objects(args: argparse.Namespace) -> None:
    inspect = pathlib.Path(args.inspect_dir)
    objects = [pathlib.Path(value) for value in args.objects]
    ensure(bool(objects), "object gate received no objects")

    all_defined: set[str] = set()
    undefined_by_object: dict[str, set[str]] = {}
    report: dict[str, object] = {"gate": "objects", "objects": []}

    for obj in objects:
        ensure(obj.is_file(), f"missing object: {obj}")
        stem = obj.stem
        file_out = run(["file", str(obj)])
        ensure("x86-64 COFF object" in file_out,
               f"{obj}: input is not an x86-64 COFF object")
        detail = run([args.objdump, "-f", "-h", "-t", "-r", str(obj)])
        undefined_text = run([args.nm, "-u", str(obj)])
        defined_text = run([args.nm, "-g", "--defined-only", str(obj)])
        write_text(inspect / f"object-{stem}.txt", file_out + "\n" + detail)
        write_text(inspect / f"object-{stem}-undefined.txt",
                   undefined_text if undefined_text.strip() else "NONE\n")

        sections = parse_sections(detail)
        section_flags = parse_section_flags(detail)
        nonzero = {name: size for name, size in sections.items() if size != 0}
        unexpected = {name: size for name, size in nonzero.items()
                      if name not in ALLOWED_OBJECT_SECTIONS}
        ensure(not unexpected,
               f"{obj}: unexpected non-empty sections: {unexpected}")

        for name in nonzero:
            flags = section_flags.get(name, set())
            required = {"CONTENTS", "ALLOC", "LOAD", "READONLY"}
            ensure(required.issubset(flags),
                   f"{obj}: {name} missing required flags: {sorted(required - flags)}")
            if name in CODE_OBJECT_SECTIONS:
                ensure("CODE" in flags and "DATA" not in flags,
                       f"{obj}: {name} is not an unambiguous read-only code section")
            else:
                ensure("CODE" in flags or "DATA" in flags,
                       f"{obj}: {name} has neither CODE nor DATA classification")

        relocation_types = parse_relocation_types(detail)
        bad_relocations = sorted(relocation_types - ALLOWED_AMD64_RELOCATIONS)
        ensure(not bad_relocations,
               f"{obj}: unsafe/unreviewed COFF relocations: {bad_relocations}")

        defined = set(parse_nm_symbols(defined_text))
        undefined = parse_undefined(undefined_text)
        all_defined.update(defined)
        undefined_by_object[str(obj)] = undefined
        report["objects"].append({
            "path": str(obj),
            "sha256": sha256(obj),
            "sections": sections,
            "section_flags": {name: sorted(flags)
                              for name, flags in section_flags.items()},
            "relocation_types": sorted(relocation_types),
            "undefined": sorted(undefined),
        })

    unresolved: dict[str, list[str]] = {}
    for obj, names in undefined_by_object.items():
        missing = sorted(name for name in names if name not in all_defined)
        if missing:
            unresolved[obj] = missing

    forbidden = sorted(name for name in all_defined.union(
        set().union(*undefined_by_object.values())) if name in FORBIDDEN_SYMBOLS)
    ensure(not forbidden, f"forbidden runtime symbols present: {forbidden}")
    ensure(not unresolved, f"unresolved project symbols before link: {unresolved}")

    report["status"] = "ok"
    report["tool_versions"] = {
        "objdump": tool_version(args.objdump),
        "nm": tool_version(args.nm),
    }
    write_text(inspect / "object-gate.json",
               json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(inspect / "object-gate.ok", "ok\n")


def data_directory_is_zero(pe_text: str, index: str, label: str) -> bool:
    pattern = re.compile(
        rf"^Entry\s+{re.escape(index)}\s+0+\s+0+\s+{re.escape(label)}",
        re.MULTILINE,
    )
    return pattern.search(pe_text) is not None


def verify_map_layout(map_text: str, objects: list[pathlib.Path],
                      expected_size: int) -> dict[str, object]:
    expected_paths = [obj.as_posix() for obj in objects]
    loaded_paths = re.findall(r"^LOAD\s+(\S+\.obj)\s*$", map_text, re.MULTILINE)
    ensure(loaded_paths == expected_paths,
           f"map object manifest/order mismatch: {loaded_paths} != {expected_paths}")

    contribution_pattern = re.compile(
        r"^\s+(\.text\$[A-Z])\s+0x[0-9A-Fa-f]+\s+0x([0-9A-Fa-f]+)\s+(\S+\.obj)\s*$",
        re.MULTILINE,
    )
    contributions: list[tuple[str, str, int]] = []
    for match in contribution_pattern.finditer(map_text):
        size = int(match.group(2), 16)
        if size != 0:
            contributions.append((match.group(1), match.group(3), size))

    expected_contributions: list[tuple[str, str]] = []
    for obj in objects:
        sections = EXPECTED_CODE_SECTION_BY_OBJECT.get(obj.name)
        ensure(sections is not None,
               f"no expected code section registered for {obj.name}")
        for section in sections:
            expected_contributions.append((section, obj.as_posix()))
    actual_contributions = [(section, path) for section, path, _ in contributions]
    ensure(actual_contributions == expected_contributions,
           "map section contribution order mismatch: "
           f"{actual_contributions} != {expected_contributions}")

    def map_symbol(name: str) -> int:
        match = re.search(
            rf"^\s*0x([0-9A-Fa-f]+)\s+{re.escape(name)}(?:\s|$)",
            map_text,
            re.MULTILINE,
        )
        ensure(match is not None, f"map missing symbol: {name}")
        return int(match.group(1), 16)

    entry = map_symbol("margaret_entry")
    start = map_symbol("margaret_blob_start")
    end = map_symbol("margaret_blob_end")
    ensure(entry == 0 and start == 0,
           "map does not place entry and anchor at zero")
    ensure(end == expected_size,
           f"map end symbol {end} does not match .text size {expected_size}")

    return {
        "loaded_objects": loaded_paths,
        "contributions": [
            {"section": section, "object": path, "size": size}
            for section, path, size in contributions
        ],
        "entry": entry,
        "start": start,
        "end": end,
    }


def gate_linked(args: argparse.Namespace) -> None:
    inspect = pathlib.Path(args.inspect_dir)
    image = pathlib.Path(args.image)
    map_path = pathlib.Path(args.map)
    ensure(image.is_file(), f"missing linked image: {image}")
    ensure(map_path.is_file() and map_path.stat().st_size != 0,
           f"missing/empty map file: {map_path}")

    file_out = run(["file", str(image)])
    sections_text = run([args.objdump, "-h", str(image)])
    pe_text = run([args.objdump, "-p", str(image)])
    reloc_text = run([args.objdump, "-r", str(image)])
    symbols_text = run([args.nm, "-n", str(image)])
    undefined_text = run([args.nm, "-u", str(image)])

    write_text(inspect / "linked-file.txt", file_out)
    write_text(inspect / "linked-sections.txt", sections_text)
    write_text(inspect / "linked-pe.txt", pe_text)
    write_text(inspect / "linked-relocations.txt",
               reloc_text if "RELOCATION RECORDS FOR" in reloc_text else "NONE\n")
    write_text(inspect / "linked-symbols.txt", symbols_text)
    write_text(inspect / "linked-undefined.txt",
               undefined_text if undefined_text.strip() else "NONE\n")

    ensure("PE32+" in file_out and "x86-64" in file_out,
           "linked image is not PE32+ x86-64")
    sections = parse_sections(sections_text)
    nonzero = {name: size for name, size in sections.items() if size != 0}
    ensure(set(nonzero) == {".text"},
           f"linked image has unexpected non-empty sections: {nonzero}")
    map_text = map_path.read_text(encoding="utf-8", errors="replace")
    map_layout = verify_map_layout(
        map_text,
        [pathlib.Path(value) for value in args.objects],
        nonzero[".text"],
    )
    ensure("RELOCATION RECORDS FOR" not in reloc_text,
           "linked image contains COFF relocations")

    undefined = parse_undefined(undefined_text)
    ensure(not undefined, f"linked image retains undefined symbols: {sorted(undefined)}")
    ensure("AddressOfEntryPoint\t0000000000000000" in pe_text,
           "linked entrypoint is not RVA zero")
    ensure(data_directory_is_zero(pe_text, "1", "Import Directory [parts of .idata]"),
           "import directory is present or could not be verified")
    ensure(data_directory_is_zero(pe_text, "3", "Exception Directory [.pdata]"),
           "exception directory is present or could not be verified")
    ensure(data_directory_is_zero(pe_text, "5", "Base Relocation Directory [.reloc]"),
           "base relocation directory is present or could not be verified")
    ensure(data_directory_is_zero(pe_text, "9", "Thread Storage Directory [.tls]"),
           "TLS directory is present or could not be verified")
    ensure(data_directory_is_zero(pe_text, "c", "Import Address Table Directory"),
           "IAT directory is present or could not be verified")

    symbols = parse_nm_symbols(symbols_text)
    required = ["margaret_entry", "margaret_blob_start", "margaret_blob_end"]
    for name in required:
        ensure(name in symbols, f"missing required linked symbol: {name}")
    ensure(symbols["margaret_entry"] == 0, "margaret_entry drifted from zero")
    ensure(symbols["margaret_blob_start"] == 0,
           "margaret_blob_start drifted from zero")
    ensure(symbols["margaret_blob_end"] > 0,
           "margaret_blob_end is not after the entry")
    ensure(symbols["margaret_blob_end"] == nonzero[".text"],
           "end symbol does not match the linked .text size")
    ensure(nonzero[".text"] <= args.max_size,
           f"linked .text exceeds size limit {args.max_size}")

    report = {
        "gate": "linked",
        "status": "ok",
        "image": str(image),
        "sha256": sha256(image),
        "map": str(map_path),
        "map_sha256": sha256(map_path),
        "map_layout": map_layout,
        "sections": sections,
        "entry": symbols["margaret_entry"],
        "end": symbols["margaret_blob_end"],
        "size": nonzero[".text"],
        "tool_versions": {
            "objdump": tool_version(args.objdump),
            "nm": tool_version(args.nm),
        },
    }
    write_text(inspect / "linked-gate.json",
               json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(inspect / "linked-gate.ok", "ok\n")


def direct_branch_targets(disassembly: str) -> list[tuple[int, str, int]]:
    result: list[tuple[int, str, int]] = []
    instruction_pattern = re.compile(
        r"^(call|jmp|j[a-z0-9]+|loop[a-z0-9]*)\s+(?:0x)?([0-9A-Fa-f]+)\b",
        re.IGNORECASE,
    )
    for line in disassembly.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        address_text = parts[0].strip()
        if not address_text.endswith(":"):
            continue
        try:
            source = int(address_text[:-1], 16)
        except ValueError:
            continue
        instruction = parts[-1].strip()
        match = instruction_pattern.match(instruction)
        if match:
            result.append((source, match.group(1).lower(), int(match.group(2), 16)))
    return result


def gate_raw(args: argparse.Namespace) -> None:
    inspect = pathlib.Path(args.inspect_dir)
    image = pathlib.Path(args.image)
    blob = pathlib.Path(args.blob)
    ensure(image.is_file(), f"missing linked image: {image}")
    ensure(blob.is_file(), f"missing raw blob: {blob}")

    compare = inspect / "reextracted-text.bin"
    run([args.objcopy, "--only-section=.text", "--output-target=binary",
         str(image), str(compare)])
    blob_bytes = blob.read_bytes()
    compare_bytes = compare.read_bytes()
    ensure(blob_bytes == compare_bytes,
           "raw blob does not exactly match linked .text")
    ensure(0 < len(blob_bytes) <= args.max_size,
           f"raw blob size {len(blob_bytes)} outside configured limit")
    ensure(not blob_bytes.startswith(b"MZ"),
           "raw artifact unexpectedly begins with a DOS/PE signature")

    # .text$R is blob-owned immutable DATA (adapter tables, discovery
    # needles) merged into the extracted range by design.  A linear
    # disassembly sweep over data produces phantom instructions; the
    # code-property checks below therefore skip this map-declared window.
    rodata = (0, 0)
    map_text = pathlib.Path(args.map).read_text()
    m = re.search(r"\.text\$R\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", map_text)
    if m:
        rodata = (int(m.group(1), 16), int(m.group(1), 16) + int(m.group(2), 16))
    ensure(rodata[1] <= len(blob_bytes),
           "map .text$R window exceeds blob size")

    def in_rodata(offset: int) -> bool:
        return rodata[0] <= offset < rodata[1]

    raw_disassembly = run([
        args.objdump, "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
        str(blob),
    ])
    linked_disassembly = run([args.objdump, "-d", "-M", "intel", str(image)])
    write_text(inspect / "raw-disassembly.txt", raw_disassembly)
    write_text(inspect / "linked-disassembly.txt", linked_disassembly)

    absolute_candidates = []
    for line in raw_disassembly.splitlines():
        if "movabs" not in line and not re.search(r"\[(?:ds:)?0x[0-9a-fA-F]+\]", line):
            continue
        m = re.match(r"\s*([0-9a-f]+):", line)
        if m is None or in_rodata(int(m.group(1), 16)):
            continue
        absolute_candidates.append(line)

    branches = direct_branch_targets(raw_disassembly)
    out_of_range = [
        {"source": source, "mnemonic": mnemonic, "target": target}
        for source, mnemonic, target in branches
        if target >= len(blob_bytes) and not in_rodata(source)
    ]
    write_text(
        inspect / "raw-direct-branches.json",
        json.dumps(
            {
                "branches": [
                    {"source": source, "mnemonic": mnemonic, "target": target}
                    for source, mnemonic, target in branches
                ],
                "out_of_range": out_of_range,
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
    )
    ensure(not out_of_range,
           f"raw blob has direct branch targets outside the blob: {out_of_range}")

    digest = sha256(blob)
    pathlib.Path(args.hash_file).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.hash_file).write_text(f"{digest}  {blob.name}\n", encoding="ascii")

    report = {
        "gate": "raw",
        "status": "ok",
        "blob": str(blob),
        "sha256": digest,
        "size": len(blob_bytes),
        "matches_linked_text": True,
        "absolute_address_candidates": len(absolute_candidates),
        "direct_branch_count": len(branches),
        "out_of_range_direct_branches": len(out_of_range),
        "tool_versions": {
            "objcopy": tool_version(args.objcopy),
            "objdump": tool_version(args.objdump),
        },
    }
    write_text(inspect / "raw-gate.json",
               json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(inspect / "raw-gate.ok", "ok\n")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)

    obj = sub.add_parser("objects")
    obj.add_argument("--inspect-dir", required=True)
    obj.add_argument("--objdump", required=True)
    obj.add_argument("--nm", required=True)
    obj.add_argument("objects", nargs="+")

    linked = sub.add_parser("linked")
    linked.add_argument("--inspect-dir", required=True)
    linked.add_argument("--objdump", required=True)
    linked.add_argument("--nm", required=True)
    linked.add_argument("--image", required=True)
    linked.add_argument("--map", required=True)
    linked.add_argument("--max-size", type=int, required=True)
    linked.add_argument("--objects", nargs="+", required=True)

    raw = sub.add_parser("raw")
    raw.add_argument("--inspect-dir", required=True)
    raw.add_argument("--objcopy", required=True)
    raw.add_argument("--objdump", required=True)
    raw.add_argument("--map", required=True)
    raw.add_argument("--image", required=True)
    raw.add_argument("--blob", required=True)
    raw.add_argument("--hash-file", required=True)
    raw.add_argument("--max-size", type=int, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "objects":
            gate_objects(args)
        elif args.command == "linked":
            gate_linked(args)
        elif args.command == "raw":
            gate_raw(args)
        else:
            raise RuntimeError(f"unknown gate: {args.command}")
    except (OSError, RuntimeError) as exc:
        print(f"[verify] FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"[verify] {args.command}: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

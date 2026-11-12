#!/usr/bin/env python3
"""Host-side verification of the built lab binaries.

This does NOT execute Windows code.  It checks what can be checked safely on
the build host:

* every expected artifact exists and its SHA256 entry matches
* the generated hash header is exactly what tools/gen_api_hashes.py produces
* the quiet build contains no sensitive API strings
* loader IATs contain no Nt*/injection imports
* the marker DLL exports FootlessMarker
* the independent detector flags every loader variant and no benign sample

Run after build.sh.  The detector path can be overridden with --detector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import gen_api_hashes  # noqa: E402

SENSITIVE = (
    b"NtOpenProcess",
    b"NtAllocateVirtualMemory",
    b"NtWriteVirtualMemory",
    b"NtProtectVirtualMemory",
    b"NtCreateThreadEx",
    b"NtQueueApcThread",
    b"NtCreateSection",
    b"NtMapViewOfSection",
    b"CreateRemoteThread",
    b"LoadLibraryW",
    b"GetProcAddress",
)

LOADERS = (
    "footless_loader.exe",
    "footless_loader_seeded.exe",
    "footless_loader_module_api.exe",
    "footless_loader_quiet.exe",
    "footless_loader_seed_alt.exe",
)
BENIGN = ("benign_app.exe", "footless_target.exe", "footless_marker.dll")


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def pe_imports(path: Path) -> List[str]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    e_lfanew = u32(data, 0x3C)
    optional = e_lfanew + 4 + 20
    magic = u16(data, optional)
    is_64 = magic == 0x20B
    directory_offset = optional + (112 if is_64 else 96)
    import_rva = u32(data, directory_offset + 8)
    import_size = u32(data, directory_offset + 12)
    if not import_rva or not import_size:
        return []
    section_offset = optional + u16(data, e_lfanew + 4 + 16)
    sections: List[Tuple[int, int, int, int]] = []
    for index in range(u16(data, e_lfanew + 4 + 2)):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            break
        sections.append(
            (u32(data, offset + 12), u32(data, offset + 8),
             u32(data, offset + 20), u32(data, offset + 16))
        )

    def rva_to_offset(rva: int) -> Optional[int]:
        for va, vsize, raw, raw_size in sections:
            if va <= rva < va + max(vsize, raw_size):
                delta = rva - va
                if delta < raw_size:
                    return raw + delta
        return None

    names: List[str] = []
    base = rva_to_offset(import_rva)
    if base is None:
        return names
    for index in range(256):
        entry = base + index * 20
        if entry + 20 > len(data):
            break
        original = u32(data, entry)
        name_rva = u32(data, entry + 12)
        first = u32(data, entry + 16)
        if not (original or name_rva or first):
            break
        thunk_rva = original or first
        thunk = rva_to_offset(thunk_rva)
        if thunk is None:
            continue
        width = 8 if is_64 else 4
        for thunk_index in range(4096):
            off = thunk + thunk_index * width
            if off + width > len(data):
                break
            value = struct.unpack_from("<Q" if is_64 else "<I", data, off)[0]
            if value == 0:
                break
            ordinal_flag = 1 << 63 if is_64 else 1 << 31
            if value & ordinal_flag:
                continue
            hint = rva_to_offset(value & 0x7FFFFFFF)
            if hint is None or hint + 2 > len(data):
                continue
            end = data.find(b"\x00", hint + 2, min(hint + 258, len(data)))
            if end < 0:
                continue
            names.append(data[hint + 2:end].decode("ascii", "replace"))
    return names


def pe_exports(path: Path) -> List[str]:
    data = path.read_bytes()
    e_lfanew = u32(data, 0x3C)
    optional = e_lfanew + 4 + 20
    magic = u16(data, optional)
    is_64 = magic == 0x20B
    directory_offset = optional + (112 if is_64 else 96)
    export_rva = u32(data, directory_offset)
    if not export_rva:
        return []
    section_offset = optional + u16(data, e_lfanew + 4 + 16)
    sections = []
    for index in range(u16(data, e_lfanew + 4 + 2)):
        offset = section_offset + index * 40
        sections.append(
            (u32(data, offset + 12), u32(data, offset + 8),
             u32(data, offset + 20), u32(data, offset + 16))
        )

    def rva_to_offset(rva: int) -> Optional[int]:
        for va, vsize, raw, raw_size in sections:
            if va <= rva < va + max(vsize, raw_size):
                delta = rva - va
                if delta < raw_size:
                    return raw + delta
        return None

    directory = rva_to_offset(export_rva)
    if directory is None or directory + 40 > len(data):
        return []
    count = u32(data, directory + 24)
    names_rva = u32(data, directory + 32)
    names_offset = rva_to_offset(names_rva)
    if names_offset is None:
        return []
    result = []
    for index in range(min(count, 4096)):
        entry = names_offset + index * 4
        if entry + 4 > len(data):
            break
        name_offset = rva_to_offset(u32(data, entry))
        if name_offset is None:
            break
        end = data.find(b"\x00", name_offset, min(name_offset + 256, len(data)))
        if end < 0:
            break
        result.append(data[name_offset:end].decode("ascii", "replace"))
    return result


def check_header(path: Path, seed: int) -> Dict[str, Any]:
    if not path.exists():
        return {"ok": False, "reason": "missing %s" % path}
    expected = gen_api_hashes.build(seed)
    actual = path.read_text(encoding="utf-8")
    return {
        "ok": expected == actual,
        "path": str(path.relative_to(ROOT)),
        "reason": "matches generator" if expected == actual else "header drift",
    }


def run_detector(detector: Path, sample: Path) -> Dict[str, Any]:
    if not detector.exists():
        return {"ok": None, "reason": "detector not found at %s" % detector}
    proc = subprocess.run(
        [sys.executable, str(detector), str(sample)],
        cwd=detector.parent,
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 2):
        return {"ok": False, "reason": "detector exit %d" % proc.returncode}
    try:
        document = json.loads(proc.stdout)
    except ValueError:
        return {"ok": False, "reason": "detector stdout not JSON"}
    return {
        "ok": True,
        "verdict": document.get("verdict"),
        "alert": document.get("alert") is not None,
        "evidence": [
            item.get("detector") for item in document.get("evidence", [])
        ],
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", default=str(ROOT / "dist"))
    parser.add_argument(
        "--detector",
        default=str(ROOT.parent / "Footless-detector" / "main.py"),
    )
    parser.add_argument("--json", default=str(ROOT / "dist" / "verification.json"))
    args = parser.parse_args(argv)
    dist = Path(args.dist)
    checks: Dict[str, Any] = {}

    sha_file = dist / "sha256.txt"
    sha_ok = True
    if not sha_file.exists():
        sha_ok = False
        sha_reason = "sha256.txt missing"
    else:
        sha_reason = "all entries match"
        for line in sha_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, name = line.split(maxsplit=1)
            path = dist / name.strip()
            if not path.exists():
                sha_ok = False
                sha_reason = "missing %s" % name
                break
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != digest:
                sha_ok = False
                sha_reason = "hash mismatch for %s" % name
                break
    checks["sha256"] = {"ok": sha_ok, "reason": sha_reason}

    header = check_header(ROOT / "src" / "api_hashes.h", gen_api_hashes.DEFAULT_SEED)
    alt = check_header(dist / "api_hashes_alt.h", 0xDEADBEEF)
    checks["generated_header"] = header
    checks["alt_header"] = alt

    quiet = dist / "footless_loader_quiet.exe"
    if quiet.exists():
        data = quiet.read_bytes()
        found = [name.decode() for name in SENSITIVE if name in data]
        checks["quiet_strings"] = {
            "ok": not found,
            "found": found,
            "reason": "no sensitive API strings" if not found else "strings present",
        }
    else:
        checks["quiet_strings"] = {"ok": False, "reason": "quiet build missing"}

    iat: Dict[str, Any] = {}
    for name in LOADERS:
        path = dist / name
        if not path.exists():
            iat[name] = {"ok": False, "reason": "missing"}
            continue
        imports = pe_imports(path)
        sensitive = sorted(set(imports) & {item.decode() for item in SENSITIVE})
        iat[name] = {
            "ok": not sensitive,
            "import_count": len(imports),
            "sensitive": sensitive,
        }
    checks["loader_iat"] = iat

    marker = dist / "footless_marker.dll"
    exports = pe_exports(marker) if marker.exists() else []
    checks["marker_export"] = {
        "ok": "FootlessMarker" in exports,
        "exports": exports,
    }

    detector_results: Dict[str, Any] = {}
    for name in LOADERS:
        detector_results[name] = run_detector(Path(args.detector), dist / name)
    for name in BENIGN:
        detector_results[name] = run_detector(Path(args.detector), dist / name)
    checks["detector"] = detector_results

    loader_ok = all(
        item.get("ok") and item.get("alert")
        for name, item in detector_results.items()
        if name in LOADERS
    )
    benign_ok = all(
        item.get("ok") and not item.get("alert")
        for name, item in detector_results.items()
        if name in BENIGN
    )
    checks["detector_summary"] = {
        "ok": loader_ok and benign_ok,
        "loader_alerts": loader_ok,
        "benign_clean": benign_ok,
    }

    overall = all(
        value.get("ok") is True
        for key, value in checks.items()
        if key not in ("detector", "detector_summary", "loader_iat")
    ) and checks["detector_summary"]["ok"]
    checks["overall"] = {"ok": overall}

    output = Path(args.json)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")

    for key, value in checks.items():
        if key in ("detector", "loader_iat"):
            continue
        print("%-22s %s  %s" % (key, "PASS" if value.get("ok") else "FAIL",
                                value.get("reason", "")))
    for name, value in checks.get("loader_iat", {}).items():
        print("  IAT %-32s %s %s" % (name, "PASS" if value.get("ok") else "FAIL",
                                    value.get("sensitive", "")))
    for name, value in detector_results.items():
        if value.get("ok"):
            print("  detector %-32s %s verdict=%s" % (
                name, "alert" if value.get("alert") else "clean", value.get("verdict")))
        else:
            print("  detector %-32s SKIP %s" % (name, value.get("reason")))
    print("overall %s -> %s" % ("PASS" if overall else "FAIL", output))
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

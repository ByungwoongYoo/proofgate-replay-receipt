#!/usr/bin/env python3
"""Run the complete dependency-free acceptance gate for this synthetic kit."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from public_safety_scan import authored_files, scan_tree  # noqa: E402
from receipt_validator import validate_receipt  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_manifest(root: Path = ROOT) -> Dict[str, Any]:
    manifest = root / "SHA256SUMS"
    issues: List[str] = []
    records: Dict[str, str] = {}
    if not manifest.is_file():
        return {"valid": False, "checked_files": 0, "issues": ["manifest-missing"]}

    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if "  " not in line:
            issues.append(f"line-format:{line_number}")
            continue
        expected, relative = line.split("  ", 1)
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            issues.append(f"digest-format:{line_number}")
            continue
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            issues.append(f"unsafe-path:{line_number}")
            continue
        if relative in records:
            issues.append(f"duplicate-path:{relative}")
            continue
        records[relative] = expected

    expected_files: Set[str] = {
        path.relative_to(root).as_posix()
        for path in authored_files(root)
        if path.name != "SHA256SUMS"
    }
    listed_files = set(records)
    for relative in sorted(expected_files - listed_files):
        issues.append(f"unlisted-file:{relative}")
    for relative in sorted(listed_files - expected_files):
        issues.append(f"unexpected-entry:{relative}")

    checked = 0
    for relative, expected in sorted(records.items()):
        path = root / Path(*PurePosixPath(relative).parts)
        if not path.is_file():
            issues.append(f"missing-file:{relative}")
            continue
        checked += 1
        if sha256(path) != expected:
            issues.append(f"hash-mismatch:{relative}")
    return {"valid": not issues, "checked_files": checked, "issues": issues}


def run_smoke(root: Path = ROOT) -> Dict[str, Any]:
    cases = [
        ("valid", "valid-receipt.json", True, set()),
        ("digest-tamper", "digest-tamper-receipt.json", False, {"FILE_HASH_MISMATCH"}),
        (
            "scope-overclaim",
            "scope-overclaim-receipt.json",
            False,
            {
                "CLAIM_TARGET_SET_MISMATCH",
                "CLAIM_PASSED_TARGET_SET_MISMATCH",
                "CLAIM_PASSED_COUNT_MISMATCH",
            },
        ),
    ]
    outcomes: List[Dict[str, Any]] = []
    for case_name, filename, expected_valid, required_codes in cases:
        result = validate_receipt(root / "fixtures" / filename)
        actual_codes = {item["code"] for item in result.issues}
        matched = result.valid is expected_valid and required_codes <= actual_codes
        outcomes.append(
            {
                "case": case_name,
                "expected_valid": expected_valid,
                "actual_valid": result.valid,
                "required_issue_codes": sorted(required_codes),
                "actual_issue_codes": sorted(actual_codes),
                "expectation_met": matched,
            }
        )

    manifest = verify_manifest(root)
    safety = scan_tree(root)
    all_expected = all(item["expectation_met"] for item in outcomes)
    all_expected = all_expected and bool(manifest["valid"]) and bool(safety["passed"])
    return {
        "profile": "proofgate-synthetic-kit-smoke/v1",
        "environment": {
            "implementation": platform.python_implementation(),
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "cases": outcomes,
        "manifest": manifest,
        "public_safety_scan": safety,
        "summary": {
            "case_count": len(outcomes),
            "expected_matches": sum(bool(item["expectation_met"]) for item in outcomes),
            "all_expectations_met": all_expected,
        },
    }


def main(argv: Optional[List[str]] = None) -> int:
    del argv
    report = run_smoke()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["summary"]["all_expectations_met"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

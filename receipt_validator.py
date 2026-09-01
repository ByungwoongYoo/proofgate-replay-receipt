#!/usr/bin/env python3
"""Validate a two-target synthetic replay receipt without dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


PROFILE = "proofgate-synthetic-replay/v1"
EVIDENCE_MODE = "same-operator-local"
OPERATOR = "local-demo-operator"
LIMITATIONS = [
    "synthetic-demo-only",
    "same-operator-local-evidence",
    "not-third-party-verification",
    "not-certification",
    "not-production-assurance",
]
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
DRIVE_PATH = re.compile(r"^[A-Za-z]:")

ROOT_FIELDS = {
    "profile",
    "receipt_id",
    "issued_at",
    "evidence_mode",
    "operator",
    "claim",
    "targets",
    "limitations",
}
CLAIM_FIELDS = {"target_ids", "passed_target_ids", "passed_count"}
TARGET_FIELDS = {"id", "input", "report", "planned_changes", "status"}
REFERENCE_FIELDS = {"path", "sha256"}


@dataclass
class ValidationResult:
    receipt: str
    valid: bool
    issues: List[Dict[str, str]]
    checked_targets: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": PROFILE,
            "receipt": self.receipt,
            "valid": self.valid,
            "checked_targets": self.checked_targets,
            "issues": self.issues,
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _unknown_fields(value: Dict[str, Any], allowed: set, label: str) -> List[str]:
    return [f"{label}.{name}" for name in sorted(set(value) - allowed)]


def _relative_file(base: Path, raw_path: Any) -> Tuple[Optional[Path], Optional[str]]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "path must be a non-empty string"
    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("/") or DRIVE_PATH.match(normalized):
        return None, "path must be relative"
    pure = PurePosixPath(normalized)
    if any(part in {"", ".", ".."} for part in pure.parts):
        return None, "path contains a disallowed segment"
    candidate = (base / Path(*pure.parts)).resolve()
    resolved_base = base.resolve()
    try:
        candidate.relative_to(resolved_base)
    except ValueError:
        return None, "path leaves the receipt directory"
    return candidate, None


def _replay(input_doc: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(input_doc, dict):
        return None, "input document must be an object"
    operation = input_doc.get("operation")
    if operation == "sum-integers":
        values = input_doc.get("values")
        if not isinstance(values, list) or not values:
            return None, "sum-integers needs a non-empty values array"
        if any(isinstance(item, bool) or not isinstance(item, int) for item in values):
            return None, "sum-integers accepts integers only"
        return {"kind": "integer", "value": sum(values)}, None
    if operation == "reverse-text":
        text = input_doc.get("text")
        if not isinstance(text, str):
            return None, "reverse-text needs a text string"
        return {"kind": "text", "value": text[::-1]}, None
    return None, "operation is not supported by this synthetic runner"


def validate_receipt(receipt_path: Path) -> ValidationResult:
    path = Path(receipt_path).resolve()
    issues: List[Dict[str, str]] = []

    def add(code: str, message: str, target_id: Optional[str] = None) -> None:
        issue = {"code": code, "message": message}
        if target_id:
            issue["target_id"] = target_id
        issues.append(issue)

    try:
        receipt = _json(path)
    except FileNotFoundError:
        add("RECEIPT_NOT_FOUND", "receipt file does not exist")
        return ValidationResult(str(receipt_path), False, issues, 0)
    except (OSError, ValueError) as exc:
        add("RECEIPT_UNREADABLE", f"receipt could not be read: {exc.__class__.__name__}")
        return ValidationResult(str(receipt_path), False, issues, 0)

    if not isinstance(receipt, dict):
        add("RECEIPT_NOT_OBJECT", "receipt root must be an object")
        return ValidationResult(path.name, False, issues, 0)

    for field in _unknown_fields(receipt, ROOT_FIELDS, "receipt"):
        add("UNKNOWN_FIELD", f"unsupported field: {field}")
    missing = sorted(ROOT_FIELDS - set(receipt))
    for field in missing:
        add("MISSING_FIELD", f"required field is missing: receipt.{field}")

    if receipt.get("profile") != PROFILE:
        add("PROFILE_MISMATCH", f"profile must be {PROFILE}")
    if receipt.get("evidence_mode") != EVIDENCE_MODE:
        add("EVIDENCE_MODE_MISMATCH", f"evidence_mode must be {EVIDENCE_MODE}")
    if receipt.get("operator") != OPERATOR:
        add("OPERATOR_MISMATCH", f"operator must be {OPERATOR}")
    if not isinstance(receipt.get("receipt_id"), str) or not receipt.get("receipt_id"):
        add("RECEIPT_ID_INVALID", "receipt_id must be a non-empty string")
    issued_at = receipt.get("issued_at")
    try:
        parsed_time = datetime.fromisoformat(str(issued_at).replace("Z", "+00:00"))
        if parsed_time.tzinfo is None:
            raise ValueError("timezone missing")
    except ValueError:
        add("ISSUED_AT_INVALID", "issued_at must be an ISO 8601 timestamp with a timezone")
    if receipt.get("limitations") != LIMITATIONS:
        add("LIMITATIONS_MISMATCH", "limitations must match the synthetic profile boundary")

    claim = receipt.get("claim")
    if not isinstance(claim, dict):
        add("CLAIM_INVALID", "claim must be an object")
        claim = {}
    else:
        for field in _unknown_fields(claim, CLAIM_FIELDS, "claim"):
            add("UNKNOWN_FIELD", f"unsupported field: {field}")
        for field in sorted(CLAIM_FIELDS - set(claim)):
            add("MISSING_FIELD", f"required field is missing: claim.{field}")

    targets = receipt.get("targets")
    if not isinstance(targets, list):
        add("TARGETS_INVALID", "targets must be an array")
        targets = []
    if len(targets) != 2:
        add("TARGET_COUNT_NOT_TWO", "this profile requires exactly two targets")

    target_ids: List[str] = []
    checked_targets = 0
    for index, raw_target in enumerate(targets):
        fallback_id = f"target-index-{index}"
        if not isinstance(raw_target, dict):
            add("TARGET_INVALID", "target must be an object", fallback_id)
            continue
        target_id = raw_target.get("id")
        if not isinstance(target_id, str) or not target_id:
            target_id = fallback_id
            add("TARGET_ID_INVALID", "target id must be a non-empty string", target_id)
        else:
            target_ids.append(target_id)
        checked_targets += 1

        for field in _unknown_fields(raw_target, TARGET_FIELDS, "target"):
            add("UNKNOWN_FIELD", f"unsupported field: {field}", target_id)
        for field in sorted(TARGET_FIELDS - set(raw_target)):
            add("MISSING_FIELD", f"required field is missing: target.{field}", target_id)
        if raw_target.get("status") != "pass":
            add("STATUS_NOT_PASS", "target status must be pass", target_id)

        planned = raw_target.get("planned_changes")
        if (
            not isinstance(planned, list)
            or not planned
            or any(not isinstance(item, str) or not item for item in planned)
            or len(planned) != len(set(planned))
        ):
            add(
                "PLANNED_CHANGES_INVALID",
                "planned_changes must contain unique non-empty strings",
                target_id,
            )
            planned = []

        loaded: Dict[str, Any] = {}
        for label in ("input", "report"):
            reference = raw_target.get(label)
            if not isinstance(reference, dict):
                add("REFERENCE_INVALID", f"{label} reference must be an object", target_id)
                continue
            for field in _unknown_fields(reference, REFERENCE_FIELDS, label):
                add("UNKNOWN_FIELD", f"unsupported field: {field}", target_id)
            if set(reference) != REFERENCE_FIELDS:
                add("REFERENCE_FIELDS_INVALID", f"{label} needs path and sha256", target_id)
            evidence_path, path_error = _relative_file(path.parent, reference.get("path"))
            if path_error:
                add("UNSAFE_PATH", f"{label}: {path_error}", target_id)
                continue
            expected = reference.get("sha256")
            if not isinstance(expected, str) or not HEX_64.fullmatch(expected):
                add("DIGEST_FORMAT_INVALID", f"{label} sha256 must be 64 lowercase hex", target_id)
                continue
            if evidence_path is None or not evidence_path.is_file():
                add("EVIDENCE_NOT_FOUND", f"{label} file does not exist", target_id)
                continue
            actual = _sha256(evidence_path)
            if actual != expected:
                add("FILE_HASH_MISMATCH", f"{label} digest does not match", target_id)
            try:
                loaded[label] = _json(evidence_path)
            except (OSError, ValueError) as exc:
                add("EVIDENCE_UNREADABLE", f"{label} is not readable JSON: {exc.__class__.__name__}", target_id)

        input_doc = loaded.get("input")
        report_doc = loaded.get("report")
        if isinstance(input_doc, dict) and input_doc.get("target_id") != target_id:
            add("INPUT_TARGET_MISMATCH", "input target_id differs from receipt", target_id)
        if isinstance(report_doc, dict):
            if report_doc.get("target_id") != target_id:
                add("REPORT_TARGET_MISMATCH", "report target_id differs from receipt", target_id)
            if report_doc.get("runner") != "synthetic-local-runner-v1":
                add("RUNNER_MISMATCH", "report runner is not the fixed synthetic runner", target_id)
            if report_doc.get("completed") is not True:
                add("RUN_NOT_COMPLETE", "report is not complete", target_id)
            if report_doc.get("exit_code") != 0:
                add("EXIT_CODE_NOT_ZERO", "report exit_code is not zero", target_id)
            if report_doc.get("unfinished_steps") != 0:
                add("UNFINISHED_STEPS", "report contains unfinished steps", target_id)
            if report_doc.get("new_assumptions") != 0:
                add("NEW_ASSUMPTIONS", "report contains added assumptions", target_id)
            if report_doc.get("observed_changes") != planned:
                add("CHANGE_SCOPE_MISMATCH", "observed changes differ from planned changes", target_id)
        elif report_doc is not None:
            add("REPORT_INVALID", "report must be an object", target_id)

        if input_doc is not None:
            replayed, replay_error = _replay(input_doc)
            if replay_error:
                add("REPLAY_INPUT_INVALID", replay_error, target_id)
            elif isinstance(report_doc, dict) and report_doc.get("output") != replayed:
                add("REPLAY_OUTPUT_MISMATCH", "fresh replay differs from saved output", target_id)

    if len(target_ids) != len(set(target_ids)):
        add("DUPLICATE_TARGET_ID", "target ids must be unique")

    claimed_targets = claim.get("target_ids")
    if not isinstance(claimed_targets, list) or any(not isinstance(item, str) for item in claimed_targets):
        add("CLAIM_TARGETS_INVALID", "claim.target_ids must be a string array")
    elif len(claimed_targets) != len(set(claimed_targets)):
        add("CLAIM_TARGETS_DUPLICATE", "claim.target_ids must be unique")
    elif set(claimed_targets) != set(target_ids):
        add("CLAIM_TARGET_SET_MISMATCH", "claimed targets differ from receipt targets")

    passed_targets = claim.get("passed_target_ids")
    if not isinstance(passed_targets, list) or any(not isinstance(item, str) for item in passed_targets):
        add("CLAIM_PASSED_TARGETS_INVALID", "claim.passed_target_ids must be a string array")
    elif len(passed_targets) != len(set(passed_targets)):
        add("CLAIM_PASSED_TARGETS_DUPLICATE", "claim.passed_target_ids must be unique")
    elif set(passed_targets) != set(target_ids):
        add("CLAIM_PASSED_TARGET_SET_MISMATCH", "passed targets differ from receipt targets")

    passed_count = claim.get("passed_count")
    if isinstance(passed_count, bool) or not isinstance(passed_count, int):
        add("CLAIM_PASSED_COUNT_INVALID", "claim.passed_count must be an integer")
    elif passed_count != len(target_ids):
        add("CLAIM_PASSED_COUNT_MISMATCH", "passed_count differs from receipt target count")

    return ValidationResult(path.name, not issues, issues, checked_targets)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path, help="receipt JSON file")
    args = parser.parse_args(argv)
    result = validate_receipt(args.receipt)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())

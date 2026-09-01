from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from public_safety_scan import scan_tree  # noqa: E402
from receipt_validator import validate_receipt  # noqa: E402
from smoke_test import verify_manifest  # noqa: E402


def write_json(path: Path, value: object) -> None:
    # pathlib.Path.write_text added the newline argument in Python 3.10.
    # Keep the public acceptance matrix honest on the declared 3.9 runner.
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ValidatorTests(unittest.TestCase):
    def issue_codes(self, fixture: str) -> set:
        result = validate_receipt(ROOT / "fixtures" / fixture)
        return {item["code"] for item in result.issues}

    def test_valid_two_target_receipt(self) -> None:
        result = validate_receipt(ROOT / "fixtures" / "valid-receipt.json")
        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.checked_targets, 2)

    def test_digest_mutation_fails_closed(self) -> None:
        self.assertIn("FILE_HASH_MISMATCH", self.issue_codes("digest-tamper-receipt.json"))

    def test_scope_overclaim_fails_closed(self) -> None:
        codes = self.issue_codes("scope-overclaim-receipt.json")
        self.assertIn("CLAIM_TARGET_SET_MISMATCH", codes)
        self.assertIn("CLAIM_PASSED_TARGET_SET_MISMATCH", codes)
        self.assertIn("CLAIM_PASSED_COUNT_MISMATCH", codes)

    def test_fresh_replay_catches_a_self_consistent_bad_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_root = Path(temporary) / "fixtures"
            shutil.copytree(ROOT / "fixtures", fixture_root)
            report_path = fixture_root / "evidence" / "target-beta-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["output"]["value"] = "wrong"
            write_json(report_path, report)

            receipt_path = fixture_root / "valid-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["targets"][1]["report"]["sha256"] = sha256(report_path)
            write_json(receipt_path, receipt)

            result = validate_receipt(receipt_path)
            codes = {item["code"] for item in result.issues}
            self.assertFalse(result.valid)
            self.assertIn("REPLAY_OUTPUT_MISMATCH", codes)
            self.assertNotIn("FILE_HASH_MISMATCH", codes)

    def test_parent_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_root = Path(temporary) / "fixtures"
            shutil.copytree(ROOT / "fixtures", fixture_root)
            receipt_path = fixture_root / "valid-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["targets"][0]["input"]["path"] = "../outside.json"
            write_json(receipt_path, receipt)
            result = validate_receipt(receipt_path)
            self.assertIn("UNSAFE_PATH", {item["code"] for item in result.issues})

    def test_schema_is_valid_json(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "synthetic-replay-receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(schema["properties"]["targets"]["minItems"], 2)
        self.assertEqual(schema["properties"]["targets"]["maxItems"], 2)

    def test_manifest_and_public_safety_scan(self) -> None:
        self.assertTrue(verify_manifest()["valid"], verify_manifest()["issues"])
        self.assertTrue(scan_tree()["passed"], scan_tree()["hits"])


if __name__ == "__main__":
    unittest.main()

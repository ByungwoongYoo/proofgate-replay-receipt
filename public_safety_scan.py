#!/usr/bin/env python3
"""Scan authored files for excluded project names and sensitive patterns."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parent
TEXT_SUFFIXES = {".cff", ".html", ".json", ".md", ".py", ".txt", ".yaml", ".yml"}
TEXT_NAMES = {"LICENSE", "SHA256SUMS"}

# The fragments keep excluded names out of the scanner's own source text.
EXCLUDED_NAMES = (
    "ve" + "ro",
    "uni" + "code",
    "piggy" + "bank",
    "nthe" + "ory",
    "utf" + "16",
    "jaco" + "bi",
    "legen" + "dre",
)
SENSITIVE_MARKERS = (
    "begin " + "private " + "key",
    "api" + "_key",
    "access" + "_token",
    "client" + "_secret",
    "@gm" + "ail.",
    "c:" + "\\users\\",
    "/ho" + "me/",
)
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
WINDOWS_PATH_PATTERN = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")


def authored_files(root: Path = ROOT) -> List[Path]:
    files: List[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__"} for part in relative.parts):
            continue
        if path.suffix == ".pyc":
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            files.append(path)
    return sorted(files)


def scan_tree(root: Path = ROOT) -> Dict[str, Any]:
    hits: List[Dict[str, str]] = []
    files = authored_files(root)
    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except ValueError:
            hits.append({"file": relative, "kind": "encoding", "match": "non-utf8"})
            continue
        lowered = text.lower()
        for name in EXCLUDED_NAMES:
            if name in lowered:
                hits.append({"file": relative, "kind": "excluded-name", "match": name})
        for marker in SENSITIVE_MARKERS:
            if marker in lowered:
                hits.append({"file": relative, "kind": "sensitive-marker", "match": marker})
        if EMAIL_PATTERN.search(text):
            hits.append({"file": relative, "kind": "email-address", "match": "redacted"})
        if WINDOWS_PATH_PATTERN.search(text):
            hits.append({"file": relative, "kind": "absolute-path", "match": "redacted"})
    return {
        "profile": "proofgate-public-safety-scan/v1",
        "files_scanned": len(files),
        "passed": not hits,
        "hits": hits,
    }


def main(argv: Optional[List[str]] = None) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    result = scan_tree(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

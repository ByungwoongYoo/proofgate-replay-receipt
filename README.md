# ProofGate synthetic replay kit

This small, dependency-free project shows how a replay receipt can be checked
without exposing a real proof, repository, customer, or benchmark. The included
receipt covers exactly two invented targets. For each target, the validator:

1. checks the SHA-256 hashes of the input and replay report;
2. reruns a fixed, harmless operation from the input;
3. compares the fresh result with the saved report;
4. checks that the observed change matches the planned change; and
5. rejects unfinished steps, added assumptions, or an inflated scope claim.

The valid example passes. Two negative examples fail on purpose: one changes a
digest, and one claims a third target that is not present.

## Quick start

From this directory, run:

```text
python smoke_test.py
python -m unittest discover -s tests -v
python public_safety_scan.py
```

You may also inspect one receipt directly:

```text
python receipt_validator.py fixtures/valid-receipt.json
```

No package installation, network connection, account, or external service is
needed. All paths stored in the examples are relative to the receipt.

Every push and pull request also runs the same smoke, unit, tamper, manifest,
and public-safety checks in GitHub Actions. The workflow is a trust signal for
this invented demonstration; it is not the paid product and it does not replace
an independent review.

## Fixed-price public pilot

For a real public Lean 4 or Rocq artifact, ProofGate offers a deliberately small
human-reviewed handoff: one pinned repository and toolchain, one named target or
release claim, a clean rebuild, target/change delta, unfinished-proof and new-
assumption scan, one deliberately broken control, and a compact receipt with
hashes and exact rerun commands.

- USD 150 fixed
- delivery within 24 hours after scope and payment are agreed
- public repository only; no credentials, customer data, or private proof body
- PASS, PARTIAL, or BLOCKED outcome; no certification claim

Read the exact [pilot scope and fit gate](PILOT.md), or
[request a public fit check](https://github.com/ByungwoongYoo/proofgate-replay-receipt/issues/new?template=public-pilot.yml).

## What a pass means

A pass means that this local validator found the expected files, matched their
digests, reproduced both synthetic outputs, and found no mismatch in the stated
scope or change list. It is useful as an inspectable example of fail-closed
receipt behavior.

It does not verify any real system. See [CLAIMS_AND_LIMITS.md](CLAIMS_AND_LIMITS.md)
for the exact boundary.

## Layout

- `receipt_validator.py`: dependency-free validator and command-line entry point
- `smoke_test.py`: positive, negative, manifest, and safety checks
- `public_safety_scan.py`: scans the project for excluded names and sensitive patterns
- `fixtures/`: one valid receipt, two expected failures, and invented evidence
- `schemas/`: machine-readable receipt shape
- `tests/`: unit and tamper tests
- `.github/workflows/ci.yml`: public smoke, unit, tamper, manifest, and safety gate
- `.github/ISSUE_TEMPLATE/public-pilot.yml`: public-only paid-pilot fit intake
- `SHA256SUMS`: digest manifest for every authored file except the manifest itself

This public repository contains only invented fixtures. It exposes no real
proof, benchmark, customer data, private repository, or production identity.

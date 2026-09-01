# Claims and limits

## Supported claim

This is a synthetic demonstration of a two-target replay receipt. In the
included valid case, the same local operator created the evidence and ran the
validator. The validator checks file digests, reruns two fixed toy operations,
compares the outputs, and checks the declared target and change scope.

## Limits

- The evidence is same-operator and local.
- The targets, inputs, outputs, changes, and reports are invented examples.
- A passing result is not third-party verification.
- A passing result is not certification.
- A passing result is not production assurance.
- The kit does not judge the truth, safety, or quality of an external system.
- SHA-256 detects a changed file only when the expected digest is already trusted.
- The validator does not establish who created the evidence.
- No signing, remote attestation, protected execution, or independent witness is included.

The project is intentionally narrow. It demonstrates inspectable receipt
semantics and clear failure behavior, not a broader trust claim.

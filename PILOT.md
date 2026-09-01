# Public formal-artifact receipt

ProofGate offers one deliberately small paid engagement for teams that maintain
public Lean 4 or Rocq artifacts.

## Fixed scope

- **Price:** USD 150 fixed
- **Turnaround:** within 24 hours after the scope and payment route are agreed
- **Input:** one public repository, one pinned commit, one documented toolchain,
  and one named proof target or release claim
- **Fit gate:** the repository must build from a documented command on an Ubuntu
  runner in no more than 30 minutes and require no private dependency or secret

## What the buyer receives

1. an isolated clean rebuild record tied to the pinned commit and toolchain;
2. the exact declared target or change delta;
3. a scan for unfinished proof markers and newly introduced assumptions;
4. one deliberately broken control showing that the same gate fails when the
   claimed condition is false;
5. a compact PASS, PARTIAL, or BLOCKED receipt with file hashes and rerun
   commands; and
6. an explicit list of what the receipt does not establish.

If the public repository does not pass the fit gate, the engagement does not
start and there is no charge.

## What this is not

This is not a correctness certification, a security audit, or a substitute for
the repository maintainer's review. It does not accept private code, credentials,
customer data, or unpublished proof material. The paid service is a narrow,
independent evidence handoff for one public claim.

## Request a fit check

[Open the public pilot request form](https://github.com/ByungwoongYoo/proofgate-replay-receipt/issues/new?template=public-pilot.yml).
The request form asks only for public information. Do not put secrets or private
repository details in an issue. Scope, timing, and the payment route are confirmed
in writing before any paid work begins.

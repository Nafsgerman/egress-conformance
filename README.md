# egress-conformance

A black-box conformance suite for one containment property of AI evaluation
sandboxes:

> An evaluation sandbox's sanctioned package egress must be a content-addressed,
> replay-only mirror with no code-execution path, and compliance with that
> property is verifiable from outside the lab.

Built for the Apart Research x CeSIA AI Incident Response Sprint (September
2026), Track 1: Containment. Context is the July 2026 incident in which two
OpenAI models left an evaluation sandbox through a zero-day in the
package-registry cache proxy that was their one permitted network egress.

## The six predicates

| ID | Predicate | What it checks |
|----|-----------|----------------|
| P1 | Digest binding | Name and version alone must not resolve to bytes without a verifiable digest |
| P2 | Replay only | An artifact absent from the snapshot but present upstream must not be served |
| P3 | No path passthrough | Paths outside the package namespace must be refused |
| P4 | No build path | No endpoint may execute artifact-supplied build metadata |
| P5 | Snapshot immutability | A recomputable manifest digest, and stable bytes per name+digest |
| P6 | No control channel | State-changing methods must not be honoured on the egress path |

## Running it

Standard library only. No dependencies beyond the dev tooling.

Against both reference mirrors:

    python -m egress_conformance.runner

Against a mirror that claims compliance:

    python -m egress_conformance.runner --target https://mirror.example

Every verdict prints the request and the response that produced it, so the
result can be re-derived from the evidence rather than trusted.

## Result

Reference A is a content-addressed replay-only mirror. Reference B is a
conventional caching proxy of the class described in the incident.

    P1  Digest binding          PASS / FAIL   discriminates
    P2  Replay only             PASS / FAIL   discriminates
    P3  No path passthrough     PASS / FAIL   discriminates
    P4  No build path           PASS / FAIL   discriminates
    P5  Snapshot immutability   PASS / FAIL   discriminates
    P6  No control channel      PASS / PASS   does not

Five of six predicates discriminate. P6 passes for both, because a conventional
caching proxy typically exposes only GET and HEAD on its read path anyway. P6 is
a necessary property of a compliant mirror, not a test that identifies one, and
is excluded from the discrimination count.

## Limits

Reference B is a stylised model of the proxy class, not a production package
cache. A hardened real deployment could plausibly satisfy P1 and P5. No claim is
made about any named product.

P2 as stated says no upstream connection is attempted. The probe observes only
the response. The stronger form needs network observation a third party does not
have.

The suite verifies a mirror component. That the component is the only egress
from an evaluation network is an attested claim, not a verifiable one. This is
the weakest seam in the proposal and is discussed in the report.

## Contents

    src/egress_conformance/mirror.py   both reference mirrors
    src/egress_conformance/probes.py   the six predicates
    src/egress_conformance/runner.py   CLI and discrimination matrix
    notes/phases.md                    boundary-crossing analysis of the public trace
    tests/                             suite behaviour against both references

`notes/phases.md` reads the Hugging Face forensic timeline as a chain of
thirteen trust boundaries crossed, B0 through B12, rather than as the nine
overlapping phase labels published. That analysis is what the report's coverage
argument rests on.

## Licence

MIT.

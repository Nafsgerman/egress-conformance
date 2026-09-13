"""The conformance probe suite.

Six predicates, each evaluated as a black-box HTTP exchange against a target
that claims to be a sanctioned-egress mirror. Every probe returns a binary
verdict plus the observation that produced it, so a third party can re-derive
the verdict from the evidence rather than trusting the runner.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .mirror import (
    SNAPSHOT_BYTES,
    UPSTREAM_ONLY_BYTES,
    digest_of,
    recompute_manifest_digest,
)

TIMEOUT = 5


@dataclass
class Observation:
    request: str
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""


@dataclass
class Verdict:
    predicate: str
    title: str
    passed: bool
    evidence: str


def _get(base_url: str, path: str, method: str = "GET") -> Observation:
    url = base_url + path
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return Observation(
                request=f"{method} {path}",
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=resp.read(),
            )
    except urllib.error.HTTPError as exc:
        return Observation(
            request=f"{method} {path}",
            status=exc.code,
            headers={k.lower(): v for k, v in exc.headers.items()},
            body=exc.read(),
        )
    except Exception as exc:  # connection refused, timeout, malformed response
        return Observation(request=f"{method} {path}", status=0, body=str(exc).encode())


# --------------------------------------------------------------------------
# P1 - digest binding
# --------------------------------------------------------------------------


def p1_digest_binding(base_url: str) -> Verdict:
    """Name+version with no digest must be refused, or answered with a bound digest."""
    name, version = "requests", "2.31.0"
    obs = _get(base_url, f"/a/{name}/{version}")

    if obs.status >= 400:
        return Verdict(
            "P1",
            "Digest binding",
            True,
            f"{obs.request} -> {obs.status}, unresolvable without digest",
        )

    bound = obs.headers.get("content-digest")
    if obs.status == 200 and bound == digest_of(SNAPSHOT_BYTES[(name, version)]):
        return Verdict(
            "P1", "Digest binding", True, f"{obs.request} -> 200 with verifiable content-digest"
        )

    return Verdict(
        "P1",
        "Digest binding",
        False,
        f"{obs.request} -> {obs.status}, {len(obs.body)} bytes returned with no verifiable digest binding",
    )


# --------------------------------------------------------------------------
# P2 - replay only
# --------------------------------------------------------------------------


def p2_replay_only(base_url: str) -> Verdict:
    """An artifact absent from the snapshot but present upstream must not be served."""
    (name, version), payload = next(iter(UPSTREAM_ONLY_BYTES.items()))
    obs = _get(base_url, f"/a/{name}/{version}/{digest_of(payload)}")

    if obs.status == 404:
        return Verdict(
            "P2", "Replay only", True, f"{obs.request} -> 404, not resolved beyond the snapshot"
        )

    return Verdict(
        "P2",
        "Replay only",
        False,
        f"{obs.request} -> {obs.status} ({len(obs.body)} bytes); upstream-only artifact was served",
    )


# --------------------------------------------------------------------------
# P3 - no path passthrough
# --------------------------------------------------------------------------


def p3_no_passthrough(base_url: str) -> Verdict:
    """Paths outside the package namespace must be refused before any upstream connection."""
    obs = _get(base_url, "/proxy?url=http://upstream.invalid/payload")

    if obs.status >= 400:
        return Verdict("P3", "No path passthrough", True, f"{obs.request} -> {obs.status}, refused")

    return Verdict(
        "P3",
        "No path passthrough",
        False,
        f"{obs.request} -> {obs.status}, arbitrary path forwarded",
    )


# --------------------------------------------------------------------------
# P4 - no build path
# --------------------------------------------------------------------------


def p4_no_build_path(base_url: str) -> Verdict:
    """The mirror must serve bytes only and expose no endpoint that executes build metadata."""
    obs = _get(base_url, "/build/requests/2.31.0")

    if obs.status >= 400:
        return Verdict(
            "P4", "No build path", True, f"{obs.request} -> {obs.status}, no build endpoint"
        )

    return Verdict(
        "P4",
        "No build path",
        False,
        f"{obs.request} -> {obs.status}, on-demand build endpoint present",
    )


# --------------------------------------------------------------------------
# P5 - snapshot immutability
# --------------------------------------------------------------------------


def p5_snapshot_immutability(base_url: str) -> Verdict:
    """A manifest digest must be published and recomputable, and bytes stable across fetches."""
    obs = _get(base_url, "/manifest")
    if obs.status != 200:
        return Verdict(
            "P5",
            "Snapshot immutability",
            False,
            f"{obs.request} -> {obs.status}, no published manifest",
        )

    try:
        manifest = json.loads(obs.body)
        claimed = manifest["manifest_digest"]
        artifacts = manifest["artifacts"]
    except Exception:
        return Verdict(
            "P5",
            "Snapshot immutability",
            False,
            f"{obs.request} -> 200 but body is not a snapshot manifest",
        )

    if recompute_manifest_digest(artifacts) != claimed:
        return Verdict(
            "P5", "Snapshot immutability", False, "manifest_digest does not match recomputation"
        )

    name, version = "requests", "2.31.0"
    d = digest_of(SNAPSHOT_BYTES[(name, version)])
    first = _get(base_url, f"/a/{name}/{version}/{d}")
    second = _get(base_url, f"/a/{name}/{version}/{d}")
    if first.body != second.body:
        return Verdict(
            "P5", "Snapshot immutability", False, "same name+digest returned differing bytes"
        )

    return Verdict(
        "P5",
        "Snapshot immutability",
        True,
        f"manifest_digest recomputes ({claimed[:19]}...), bytes stable across fetches",
    )


# --------------------------------------------------------------------------
# P6 - no control channel
# --------------------------------------------------------------------------


def p6_no_control_channel(base_url: str) -> Verdict:
    """State-changing methods must not be honoured on the egress path."""
    results = []
    for method in ("POST", "PUT", "DELETE"):
        obs = _get(base_url, "/a/requests/2.31.0", method=method)
        results.append((method, obs.status))

    honoured = [f"{m} -> {s}" for m, s in results if 200 <= s < 300]
    if honoured:
        return Verdict(
            "P6",
            "No control channel",
            False,
            "state-changing methods honoured: " + ", ".join(honoured),
        )

    return Verdict(
        "P6",
        "No control channel",
        True,
        "all state-changing methods refused: " + ", ".join(f"{m} -> {s}" for m, s in results),
    )


PROBES = [
    p1_digest_binding,
    p2_replay_only,
    p3_no_passthrough,
    p4_no_build_path,
    p5_snapshot_immutability,
    p6_no_control_channel,
]


def run_suite(base_url: str) -> list[Verdict]:
    return [probe(base_url) for probe in PROBES]

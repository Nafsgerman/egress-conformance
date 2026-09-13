"""Conformance suite behaviour against both reference mirrors."""

from __future__ import annotations

import pytest

from egress_conformance.mirror import serve_caching_proxy, serve_compliant
from egress_conformance.probes import PROBES, run_suite


@pytest.fixture(scope="module")
def compliant_url():
    server = serve_compliant().start()
    yield server.base_url
    server.stop()


@pytest.fixture(scope="module")
def proxy_url():
    server = serve_caching_proxy().start()
    yield server.base_url
    server.stop()


def _by_predicate(verdicts):
    return {v.predicate: v for v in verdicts}


def test_compliant_mirror_satisfies_every_predicate(compliant_url):
    verdicts = _by_predicate(run_suite(compliant_url))
    failed = [p for p, v in verdicts.items() if not v.passed]
    assert failed == [], f"compliant reference failed {failed}"


@pytest.mark.parametrize("predicate", ["P1", "P2", "P3", "P4", "P5"])
def test_caching_proxy_fails_discriminating_predicates(proxy_url, predicate):
    verdicts = _by_predicate(run_suite(proxy_url))
    assert not verdicts[predicate].passed


def test_p6_does_not_discriminate(compliant_url, proxy_url):
    """Both references refuse state-changing methods. P6 is necessary, not sufficient."""
    assert _by_predicate(run_suite(compliant_url))["P6"].passed
    assert _by_predicate(run_suite(proxy_url))["P6"].passed


def test_every_probe_returns_evidence(compliant_url):
    for verdict in run_suite(compliant_url):
        assert verdict.evidence.strip(), f"{verdict.predicate} returned no evidence"


def test_suite_covers_six_predicates():
    assert len(PROBES) == 6

"""Run the conformance suite against a target, or against both reference mirrors.

python -m egress_conformance.runner                      # both references
python -m egress_conformance.runner --target http://...  # a claimed-compliant mirror
"""

from __future__ import annotations

import argparse
import sys

from .mirror import serve_caching_proxy, serve_compliant
from .probes import Verdict, run_suite


def _print_verdicts(label: str, verdicts: list[Verdict]) -> int:
    passed = sum(1 for v in verdicts if v.passed)
    print(f"\n{label}  [{passed}/{len(verdicts)} predicates satisfied]")
    print("-" * 78)
    for v in verdicts:
        mark = "PASS" if v.passed else "FAIL"
        print(f"  {v.predicate}  {mark}  {v.title}")
        print(f"          {v.evidence}")
    return passed


def _print_matrix(compliant: list[Verdict], proxy: list[Verdict]) -> None:
    print("\nDiscrimination matrix")
    print("-" * 78)
    header = (
        f"  {'':4} {'predicate':26} {'compliant':>12} {'caching proxy':>15} {'discriminates':>14}"
    )
    print(header)
    for c, p in zip(compliant, proxy, strict=True):
        disc = "yes" if c.passed != p.passed else "no"
        a = "PASS" if c.passed else "FAIL"
        b = "PASS" if p.passed else "FAIL"
        print(f"  {c.predicate:4} {c.title:26} {a:>12} {b:>15} {disc:>14}")
    n = sum(1 for c, p in zip(compliant, proxy, strict=True) if c.passed != p.passed)
    print(f"\n  {n} of {len(compliant)} predicates discriminate between the two references.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Egress conformance probe suite")
    parser.add_argument("--target", help="base URL of a mirror to test")
    args = parser.parse_args(argv)

    if args.target:
        verdicts = run_suite(args.target.rstrip("/"))
        passed = _print_verdicts(f"TARGET {args.target}", verdicts)
        print()
        return 0 if passed == len(verdicts) else 1

    with serve_compliant() as compliant_server, serve_caching_proxy() as proxy_server:
        compliant = run_suite(compliant_server.base_url)
        proxy = run_suite(proxy_server.base_url)
        _print_verdicts("REFERENCE A - content-addressed replay-only mirror", compliant)
        _print_verdicts("REFERENCE B - conventional caching proxy", proxy)
        _print_matrix(compliant, proxy)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

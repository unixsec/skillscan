#!/usr/bin/env python3
"""Fail if a deployed NetworkPolicy is present but not actually constraining
anything.

WHY THIS EXISTS. Two separate drifts on 2026-07-29, hours apart, both in the
hand-maintained `~/k8s/*.yaml` manifests the dev VM runs instead of
`deploy/helm/skillscan`, both with a security consequence, neither visible as a
diff anyone was going to read:

  1. `10-data.yaml` had lost `app.kubernetes.io/component` on the mysql and
     redis pod templates. Every policy protecting those two selects on exactly
     that label, so the next `kubectl apply` would have silently dropped both
     datastores out of their NetworkPolicies. The policies would still have
     been listed, still have looked correct, and have applied to nothing.
  2. `50-netpol-ingress.yaml`'s `monolith-ingress` had lost its `from`
     selector, so `ingress: [{ports: [8000]}]` allowed the whole namespace
     rather than the web pod. MEASURED, not inferred: an unlabelled probe pod
     read all 16 `skillscan_*` series off `monolith:8000/metrics`. A task that
     same morning had added `monolith-metrics-ingress` specifically BECAUSE it
     checked that `monolith-ingress` only allowed web - it had read the
     checked-in file, not the cluster.

Both are the same failure in the end: a policy that exists, reads plausibly,
and permits everything it was written to forbid. Nothing in this repo could see
either, because the only artifact that knows is the live cluster.

TWO CHECKS, one per drift above:

  VACUOUS SELECTOR - a policy whose `podSelector` matches no running pod. That
    policy protects nothing, whatever it says. Catches (1) directly, and every
    other spelling of "the workload and the policy stopped agreeing on a
    label".

  PEERLESS RULE - an ingress/egress rule with no `from`/`to`, which allows all
    sources/destinations. Catches (2) directly. Note the distinction this
    depends on and Kubernetes makes silently: `ingress: []` (or absent) denies
    everything, while `ingress: [{ports: [...]}]` ALLOWS everything on those
    ports. One character of YAML apart, opposite meanings; `default-deny-all`
    is the first shape and must never be flagged.

USAGE
    uv run python deploy/check_netpol_posture.py [--namespace skillscan]
    uv run python deploy/check_netpol_posture.py --from-json netpol.json pods.json

Requires `kubectl` on PATH and a working context, so it runs where the cluster
is - on the VM, as part of a deploy - not in a hook on a laptop that cannot
reach one. `--from-json` takes the two `kubectl get -o json` documents from
disk instead, which is how the tests drive it with no cluster at all.

WHAT THIS DELIBERATELY DOES NOT CHECK

  Parity between the live specs and `deploy/networkpolicy/*.yaml`. This was
  the obvious design and it is the wrong one HERE, measured rather than
  assumed: after reconciling `monolith-ingress`, a spec-equality run against
  the dev VM produces four differences and three are legitimate.
  `web-connectivity` is the repo's `web-ingress` + `web-egress-allowlist`
  merged into one object with identical rules; `mysql-ingress` live is
  STRICTER than the repo's (no `migration` peer, because this cluster runs
  migrations out-of-band); `migration-egress-allowlist` is absent because no
  migration pod exists. A check that cries wolf three times out of four on its
  first run is a check nobody runs twice, and it would have gone on doing that
  for as long as a dev VM legitimately repackages what the chart ships. The two
  checks above need no such agreement: they ask whether the cluster's own
  policies do anything, which stays a fair question however the manifests are
  organised.

  Whether the allowed peers are the RIGHT peers. `redis-ingress` naming the
  wrong component would pass this cleanly. That needs the parity check above,
  or a reachability test; this is the floor, not the ceiling.

  `matchExpressions` selectors. None exist in this repo today. Rather than
  quietly treating one as matching everything (which would make the vacuous
  check pass by accident, the exact failure mode this file is about), an
  unsupported selector is REPORTED as unanalysed and fails the run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterable, Sequence
from typing import Any

DEFAULT_NAMESPACE = "skillscan"

# Rules that are open ON PURPOSE, as (policy name, direction). Each entry needs
# a reason that is about Kubernetes, not about convenience.
#
# `web-ingress`/`web-connectivity` ingress: the traffic arrives from outside the
# cluster through an ingress controller (or a NodePort), and the source pod's
# identity is genuinely cluster-specific - deploy/networkpolicy/web-allowlist.yaml
# says so in its own comment and declines to guess it. There is nothing to name
# here, so the rule is open and the console's authentication is the control.
ALLOWED_PEERLESS: frozenset[tuple[str, str]] = frozenset(
    {
        ("web-ingress", "ingress"),
        ("web-connectivity", "ingress"),
    }
)


def _selector_matches(selector: dict[str, Any], pod_labels: dict[str, str]) -> bool:
    """`podSelector` semantics: an EMPTY selector matches every pod in the
    namespace (that is how `default-deny-all` covers everything), and a
    populated one matches on every key."""
    match_labels = selector.get("matchLabels") or {}
    return all(pod_labels.get(k) == v for k, v in match_labels.items())


def _unsupported_selector(selector: dict[str, Any]) -> bool:
    return bool(selector.get("matchExpressions"))


def _rule_lists(spec: dict[str, Any]) -> Iterable[tuple[str, str, list[dict[str, Any]]]]:
    """(direction, peer key, rules) for each direction this policy declares.

    Driven by the rule lists actually present, NOT by `policyTypes`: a policy
    can name a type and carry no rules (that is deny-all and is fine), but a
    rule list that exists is one this function must look inside."""
    for direction, peer_key in (("ingress", "from"), ("egress", "to")):
        rules = spec.get(direction)
        if isinstance(rules, list):
            yield direction, peer_key, rules


def analyze(
    policies: Sequence[dict[str, Any]],
    pods: Sequence[dict[str, Any]],
    *,
    allowed_peerless: frozenset[tuple[str, str]] = ALLOWED_PEERLESS,
) -> list[str]:
    """Every problem found, as human-readable lines. Empty means clean.

    A pure function over the two `kubectl get -o json` documents so the rules
    that decide whether a cluster is protected are provable without a cluster -
    the same posture `orchestration.engine_health` takes toward MySQL.
    """
    problems: list[str] = []
    pod_labels = [
        (pod.get("metadata", {}).get("name", "?"), pod.get("metadata", {}).get("labels") or {})
        for pod in pods
    ]

    for policy in policies:
        name = policy.get("metadata", {}).get("name", "?")
        spec = policy.get("spec") or {}
        selector = spec.get("podSelector")
        if selector is None:
            problems.append(f"{name}: no podSelector at all - cannot tell what it protects")
            continue

        if _unsupported_selector(selector):
            problems.append(
                f"{name}: podSelector uses matchExpressions, which this check cannot evaluate - "
                "verify by hand, or teach this script the semantics"
            )
        else:
            matched = [pod for pod, labels in pod_labels if _selector_matches(selector, labels)]
            if not matched:
                rendered = json.dumps(selector.get("matchLabels") or {}, sort_keys=True)
                problems.append(
                    f"{name}: podSelector {rendered} matches NO running pod - "
                    f"this policy is protecting nothing"
                )

        for direction, peer_key, rules in _rule_lists(spec):
            if (name, direction) in allowed_peerless:
                continue
            for index, rule in enumerate(rules):
                if not rule.get(peer_key):
                    verb = "sources" if direction == "ingress" else "destinations"
                    problems.append(
                        f"{name}: {direction} rule #{index} has no '{peer_key}' selector, so it "
                        f"allows ALL {verb} in the namespace on its ports "
                        f"({json.dumps(rule.get('ports') or 'any')})"
                    )
    return problems


def _kubectl_json(namespace: str, resource: str) -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["kubectl", "-n", namespace, "get", resource, "-o", "json"],
        capture_output=True,
        check=True,
    )
    payload = json.loads(completed.stdout)
    items = payload.get("items")
    return list(items) if isinstance(items, list) else []


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument(
        "--from-json",
        nargs=2,
        metavar=("NETPOL_JSON", "PODS_JSON"),
        help="read the two `kubectl get -o json` documents from disk instead of running kubectl",
    )
    args = parser.parse_args(argv)

    if args.from_json:
        netpol_path, pods_path = args.from_json
        with open(netpol_path, encoding="utf-8") as handle:
            policies = json.load(handle).get("items", [])
        with open(pods_path, encoding="utf-8") as handle:
            pods = json.load(handle).get("items", [])
    else:
        try:
            policies = _kubectl_json(args.namespace, "networkpolicy")
            pods = _kubectl_json(args.namespace, "pods")
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"could not read the cluster: {exc}", file=sys.stderr)
            return 2

    if not policies:
        # An empty list is not a pass. A namespace with no NetworkPolicy at all
        # is the most permissive configuration there is, and reporting it as
        # clean would be this script committing the error it exists to catch.
        print(f"no NetworkPolicy in namespace {args.namespace!r} - nothing is restricted")
        return 1

    problems = analyze(policies, pods)
    if problems:
        print(f"NetworkPolicy posture problems in namespace {args.namespace!r}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(f"NetworkPolicy posture OK: {len(policies)} policies, all selecting pods, no open rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

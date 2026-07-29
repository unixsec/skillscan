"""Tests for `deploy/check_netpol_posture.py`.

PURE - no cluster, no kubectl. `analyze` is a fold over the two `kubectl get
-o json` documents, which is the whole reason it was factored out of the
subprocess plumbing.

The two headline tests replay the exact drifts of 2026-07-29 from the shapes
the cluster really had. A drift checker that cannot be shown failing on the
drift that motivated it is indistinguishable from one that always passes -
this repo has already shipped one measurement that turned out to be entirely
inert, so a red-on-the-real-input assertion is the minimum bar.
"""

from __future__ import annotations

from typing import Any

from deploy.check_netpol_posture import analyze


def _pod(name: str, labels: dict[str, str]) -> dict[str, Any]:
    return {"metadata": {"name": name, "labels": labels}}


def _policy(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {"metadata": {"name": name}, "spec": spec}


_MONOLITH_POD = _pod(
    "monolith-1", {"app": "monolith", "app.kubernetes.io/component": "core-monolith"}
)
_WEB_POD = _pod("web-1", {"app": "web", "app.kubernetes.io/component": "web"})
_MYSQL_POD = _pod("mysql-1", {"app": "mysql", "app.kubernetes.io/component": "mysql"})

_MONOLITH_INGRESS_CORRECT = _policy(
    "monolith-ingress",
    {
        "podSelector": {"matchLabels": {"app.kubernetes.io/component": "core-monolith"}},
        "policyTypes": ["Ingress"],
        "ingress": [
            {
                "from": [{"podSelector": {"matchLabels": {"app.kubernetes.io/component": "web"}}}],
                "ports": [{"port": 8000, "protocol": "TCP"}],
            }
        ],
    },
)


class TestTheDriftsThisExistsFor:
    def test_a_peerless_ingress_rule_is_reported(self) -> None:
        """`monolith-ingress` as actually deployed: the `from` gone, everything
        else identical. An unlabelled pod read all 16 metric series through
        this."""
        drifted = _policy(
            "monolith-ingress",
            {
                "podSelector": {"matchLabels": {"app.kubernetes.io/component": "core-monolith"}},
                "policyTypes": ["Ingress"],
                "ingress": [{"ports": [{"port": 8000, "protocol": "TCP"}]}],
            },
        )
        problems = analyze([drifted], [_MONOLITH_POD, _WEB_POD])
        assert len(problems) == 1
        assert "monolith-ingress" in problems[0]
        assert "no 'from' selector" in problems[0]
        assert "ALL sources" in problems[0]

    def test_the_same_policy_with_its_from_selector_is_clean(self) -> None:
        """The control. Without it the test above proves only that this script
        reports something, not that it reports the right thing."""
        assert analyze([_MONOLITH_INGRESS_CORRECT], [_MONOLITH_POD, _WEB_POD]) == []

    def test_a_workload_that_lost_its_label_leaves_a_policy_protecting_nothing(self) -> None:
        """The morning's `10-data.yaml` drift: the policy is untouched and
        still listed, the POD stopped carrying the label it selects on."""
        mysql_ingress = _policy(
            "mysql-ingress",
            {
                "podSelector": {"matchLabels": {"app.kubernetes.io/component": "mysql"}},
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/component": "core-monolith"}
                                }
                            }
                        ],
                        "ports": [{"port": 3306, "protocol": "TCP"}],
                    }
                ],
            },
        )
        unlabelled_mysql = _pod("mysql-1", {"app": "mysql"})
        problems = analyze([mysql_ingress], [_MONOLITH_POD, unlabelled_mysql])
        assert len(problems) == 1
        assert "protecting nothing" in problems[0]
        # And clean once the label is back - the same policy, the same run.
        assert analyze([mysql_ingress], [_MONOLITH_POD, _MYSQL_POD]) == []


class TestDenyAllIsNotAnOpenRule:
    def test_a_policy_with_no_rule_lists_at_all_is_clean(self) -> None:
        """`default-deny-all`. `policyTypes` without rules DENIES everything;
        flagging it would invert the check's meaning on the single most
        important policy in the namespace."""
        default_deny = _policy(
            "default-deny-all", {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
        )
        assert analyze([default_deny], [_MONOLITH_POD]) == []

    def test_an_explicitly_empty_rule_list_is_also_clean(self) -> None:
        """`ingress: []` is deny-all too - one character from `ingress: [{}]`,
        which is allow-all, and this is the pair the whole check turns on."""
        empty = _policy(
            "empty-ingress", {"podSelector": {"matchLabels": {"app": "web"}}, "ingress": []}
        )
        assert analyze([empty], [_WEB_POD]) == []

    def test_a_bare_empty_rule_object_is_the_open_one(self) -> None:
        wide_open = _policy(
            "wide-open", {"podSelector": {"matchLabels": {"app": "web"}}, "ingress": [{}]}
        )
        problems = analyze([wide_open], [_WEB_POD])
        assert len(problems) == 1
        assert "allows ALL sources" in problems[0]

    def test_an_empty_pod_selector_matches_every_pod_not_none(self) -> None:
        """`podSelector: {}` is how `default-deny-all` covers the namespace. If
        this were read as "matches nothing", the vacuous-selector check would
        fire on it forever and the script would be permanently red."""
        default_deny = _policy("default-deny-all", {"podSelector": {}, "policyTypes": ["Ingress"]})
        assert analyze([default_deny], [_MONOLITH_POD]) == []
        # ...though a namespace with no pods really does mean it selects none.
        assert analyze([default_deny], []) != []


class TestEgressIsCheckedToo:
    def test_a_peerless_egress_rule_is_reported_with_the_right_word(self) -> None:
        leaky = _policy(
            "leaky-egress",
            {
                "podSelector": {"matchLabels": {"app.kubernetes.io/component": "engine-runner"}},
                "policyTypes": ["Egress"],
                "egress": [{"ports": [{"port": 443, "protocol": "TCP"}]}],
            },
        )
        runner = _pod("er-1", {"app.kubernetes.io/component": "engine-runner"})
        problems = analyze([leaky], [runner])
        assert len(problems) == 1
        assert "no 'to' selector" in problems[0]
        assert "ALL destinations" in problems[0]


class TestTheDocumentedException:
    def test_the_web_ingress_rule_is_allowed_to_be_open(self) -> None:
        """Its peer is an ingress controller outside the namespace, whose
        identity deploy/networkpolicy/web-allowlist.yaml declines to guess. The
        exception is by (name, direction), so it cannot leak to the egress half
        of the same object."""
        web = _policy(
            "web-connectivity",
            {
                "podSelector": {"matchLabels": {"app.kubernetes.io/component": "web"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"ports": [{"port": 8080, "protocol": "TCP"}]}],
                "egress": [
                    {
                        "to": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/component": "core-monolith"}
                                }
                            }
                        ],
                        "ports": [{"port": 8000, "protocol": "TCP"}],
                    }
                ],
            },
        )
        assert analyze([web, _MONOLITH_INGRESS_CORRECT], [_WEB_POD, _MONOLITH_POD]) == []

    def test_the_exception_does_not_cover_that_policys_egress_side(self) -> None:
        web_leaking_egress = _policy(
            "web-connectivity",
            {
                "podSelector": {"matchLabels": {"app.kubernetes.io/component": "web"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"ports": [{"port": 8080, "protocol": "TCP"}]}],
                "egress": [{"ports": [{"port": 443, "protocol": "TCP"}]}],
            },
        )
        problems = analyze([web_leaking_egress], [_WEB_POD])
        assert len(problems) == 1
        assert "egress rule #0" in problems[0]


class TestUnanalysableInputFailsLoudRatherThanQuiet:
    def test_match_expressions_are_reported_not_silently_passed(self) -> None:
        """A selector this script cannot evaluate must not be allowed to
        satisfy the vacuous-selector check by default - that would be the
        script silently doing the thing it was written to detect."""
        exotic = _policy(
            "exotic",
            {
                "podSelector": {
                    "matchExpressions": [{"key": "app", "operator": "In", "values": ["web"]}]
                },
                "policyTypes": ["Ingress"],
            },
        )
        problems = analyze([exotic], [_WEB_POD])
        assert len(problems) == 1
        assert "matchExpressions" in problems[0]

    def test_a_policy_with_no_pod_selector_is_reported(self) -> None:
        problems = analyze([_policy("headless", {"policyTypes": ["Ingress"]})], [_WEB_POD])
        assert len(problems) == 1
        assert "no podSelector" in problems[0]

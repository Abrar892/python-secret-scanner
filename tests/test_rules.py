"""Rule correctness: every example must match, every non-match must not."""

import pytest

from secretscan.rules import builtin_rules


@pytest.mark.parametrize("rule", builtin_rules(), ids=lambda r: r.id)
def test_rule_examples_match(rule):
    assert rule.examples, f"{rule.id} has no positive examples"
    for example in rule.examples:
        assert rule.pattern.search(example), f"{rule.id} failed to match: {example!r}"


@pytest.mark.parametrize("rule", builtin_rules(), ids=lambda r: r.id)
def test_rule_non_matches_rejected(rule):
    for sample in rule.non_matches:
        assert not rule.pattern.search(sample), f"{rule.id} wrongly matched: {sample!r}"


def test_rule_ids_unique():
    ids = [r.id for r in builtin_rules()]
    assert len(ids) == len(set(ids))


def test_rule_severities_valid():
    for rule in builtin_rules():
        assert rule.severity in {"high", "medium", "low"}

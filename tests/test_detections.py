"""Runs every detection's own cases.

A detection file holds its rule and the cases that prove it (see detections/README.md). This
file knows nothing about any single rule: it finds the registered ones and runs what they carry
"""

from pathlib import Path

import pytest

import detections
from pipeline.detect import rule_id

FOLDER = Path(detections.__file__).parent

CASES = [
    pytest.param(rule, case, id=f"{rule_id(rule)}: {case.get('name', '?')}")
    for rule in detections.RULES
    for case in getattr(rule, "CASES", [])
]


def test_every_detection_file_is_switched_on():
    files = {path.stem for path in FOLDER.glob("*.py")} - {"__init__"}
    registered = {rule_id(rule) for rule in detections.RULES}

    assert files == registered, "list every detection file in RULES in detections/__init__.py"


def test_every_detection_has_a_rule_and_cases():
    for rule in detections.RULES:
        assert callable(getattr(rule, "rule", None)), f"{rule_id(rule)} has no rule(event) function"
        assert getattr(rule, "CASES", []), f"{rule_id(rule)} has no CASES"
        for case in rule.CASES:
            assert {"name", "event", "expect"} <= case.keys(), f"{rule_id(rule)}: a case needs name, event and expect"


@pytest.mark.parametrize(("rule", "case"), CASES)
def test_case(rule, case):
    assert bool(rule.rule(case["event"])) is case["expect"]

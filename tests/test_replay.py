"""The replay gate: recorded CloudTrail events run through the real pipeline and the real rules.

Where tests/test_detections.py checks each rule in isolation against small hand-written events,
this file proves the rules fire on real recorded events after the real normalizer has shaped
them. It is the end-to-end gate: a rule that reads a field the normalizer fills differently, or
assumes a field a real event lacks, passes the unit cases and fails here.

It uses detections.RULES (the real registered rules), not stand-ins. Marked `replay` so it runs
in its own CI job and a red test here reddens only that gate (see pytest.ini and ci.yml).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import detections
from pipeline import detect, normalize

pytestmark = pytest.mark.replay

FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"
# A fixed "now" so matched_at is deterministic. The value doesn't affect whether a rule fires
NOW = datetime(2026, 10, 8, 0, 0, 0, tzinfo=timezone.utc)


def rule_ids_that_fired(fixture: str) -> set[str]:
    """Every rule that matched any record in the fixture, after real normalization."""
    raw = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))["Records"]
    batch = [normalize.normalize_record(record) for record in raw]
    return {match["rule_id"] for match in detect.run(detections.RULES, batch, NOW)}


def stop_logging_matches(fixture: str) -> list[dict]:
    raw = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))["Records"]
    batch = [normalize.normalize_record(record) for record in raw]
    matches = detect.run(detections.RULES, batch, NOW)
    return [match for match in matches if match["rule_id"] == "aws_stop_logging"]


def test_recorded_refused_attempts_are_detected():
    # Two real refused StopLogging calls recorded in the lab on 2026-10-05.
    # The rule fires on attempts, not only successes, so every refused call is caught
    raw = json.loads((FIXTURES / "stop_logging_denied.json").read_text(encoding="utf-8"))["Records"]
    assert len(stop_logging_matches("stop_logging_denied.json")) == len(raw)


def test_a_successful_stop_is_detected():
    assert "aws_stop_logging" in rule_ids_that_fired("stop_logging_success.json")


def test_a_benign_management_call_is_not_flagged():
    # StartLogging is the opposite action: turning logging back on. It must not alert
    assert "aws_stop_logging" not in rule_ids_that_fired("start_logging.json")


def test_a_match_carries_the_status_so_triage_sees_success_vs_refused():
    # The rule ignores status on purpose, but the match row must still carry it
    refused = stop_logging_matches("stop_logging_denied.json")
    succeeded = stop_logging_matches("stop_logging_success.json")

    assert all(match["status"] == "Failure" for match in refused)
    assert all(match["status"] == "Success" for match in succeeded)

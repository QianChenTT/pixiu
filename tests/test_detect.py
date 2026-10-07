import json
import types
from datetime import datetime, timezone
from pathlib import Path

import detections
from pipeline import aws, detect, events, normalize

FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"
NOW = datetime(2026, 10, 7, 15, 30, 0, tzinfo=timezone.utc)


def normalized(name: str) -> list[dict]:
    raw = json.loads((FIXTURES / name).read_text(encoding="utf-8"))["Records"]
    return [normalize.normalize_record(record) for record in raw]


def make_rule(name: str, rule, title: str | None = None):
    """A stand-in for a detection file. No real detection is used in these tests."""
    module = types.ModuleType(f"detections.{name}")
    module.rule = rule
    if title is not None:
        module.TITLE = title
    return module


ANY_STOP = make_rule("any_stop", lambda event: event["api"]["operation"] == "StopLogging", "Somebody called StopLogging")
NEVER = make_rule("never", lambda event: False)


def boom(event):
    raise KeyError("this rule is broken")


BROKEN = make_rule("broken", boom)


def test_a_match_row_is_the_event_plus_the_rule_and_the_time():
    batch = normalized("stop_logging_success.json")

    matches = detect.run([ANY_STOP], batch, NOW)

    assert matches == [
        {
            **batch[0],
            "rule_id": "any_stop",
            "rule_title": "Somebody called StopLogging",
            "matched_at": "2026-10-07T15:30:00Z",
        }
    ]


def test_every_rule_sees_every_event():
    batch = normalized("stop_logging_denied.json")
    second = make_rule("second", lambda event: event["status"] == "Failure")

    matches = detect.run([ANY_STOP, second], batch, NOW)

    assert [(match["rule_id"], match["metadata"]["uid"]) for match in matches] == [
        ("any_stop", "00000000-0000-4000-8000-000000000001"),
        ("second", "00000000-0000-4000-8000-000000000001"),
        ("any_stop", "00000000-0000-4000-8000-000000000002"),
        ("second", "00000000-0000-4000-8000-000000000002"),
    ]


def test_no_match_and_no_rules_both_give_nothing():
    batch = normalized("stop_logging_denied.json")

    assert detect.run([NEVER], batch, NOW) == []
    assert detect.run([], batch, NOW) == []


def test_a_rule_without_a_title_uses_its_file_name():
    always = make_rule("always", lambda event: True)

    assert detect.run([always], normalized("stop_logging_success.json"), NOW)[0]["rule_title"] == "always"


def test_a_broken_rule_does_not_stop_the_others():
    matches = detect.run([BROKEN, ANY_STOP], normalized("stop_logging_success.json"), NOW)

    assert [match["rule_id"] for match in matches] == ["any_stop"]


def test_output_key():
    assert detect.output_key("events/dt=2026-10-07/file.jsonl.gz") == "matches/dt=2026-10-07/file.jsonl"
    # Anything that is not a normalized events file is refused, a match file above all:
    # reading its own output would be a loop
    assert detect.output_key("matches/dt=2026-10-07/file.jsonl") is None
    assert detect.output_key("athena-results/query.csv") is None
    assert detect.output_key("events/dt=2026-10-07/notes.txt") is None


class FakeStore:
    def __init__(self, objects: dict | None = None):
        self.objects = objects or {}
        self.written: dict = {}

    def read_object(self, bucket, key):
        return self.objects[(bucket, key)]

    def write_object(self, bucket, key, body, content_type):
        self.written[(bucket, key)] = body


def s3_event(bucket: str, key: str) -> dict:
    # S3 URL-encodes the key in the notification: = arrives as %3D
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key.replace("=", "%3D")}}}]}


def test_handler_writes_a_match_file_next_to_the_events(monkeypatch):
    batch = normalized("stop_logging_success.json")
    key = "events/dt=2026-10-07/file.jsonl.gz"
    store = FakeStore({("store", key): events.encode(batch, compress=True)})
    monkeypatch.setattr(aws, "read_object", store.read_object)
    monkeypatch.setattr(aws, "write_object", store.write_object)
    monkeypatch.setattr(detections, "RULES", [ANY_STOP])

    assert detect.handler(s3_event("store", key), None) == {"matches": 1}

    assert list(store.written) == [("store", "matches/dt=2026-10-07/file.jsonl")]
    rows = events.decode(store.written[("store", "matches/dt=2026-10-07/file.jsonl")])
    assert rows[0]["rule_id"] == "any_stop"
    assert rows[0]["api"]["request"]["data"] == batch[0]["api"]["request"]["data"]


def test_handler_writes_nothing_when_nothing_matches(monkeypatch):
    key = "events/dt=2026-10-07/file.jsonl.gz"
    store = FakeStore({("store", key): events.encode(normalized("stop_logging_success.json"), compress=True)})
    monkeypatch.setattr(aws, "read_object", store.read_object)
    monkeypatch.setattr(aws, "write_object", store.write_object)
    monkeypatch.setattr(detections, "RULES", [NEVER])

    assert detect.handler(s3_event("store", key), None) == {"matches": 0}
    assert store.written == {}


def test_handler_never_reads_a_match_file(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(aws, "read_object", store.read_object)
    monkeypatch.setattr(aws, "write_object", store.write_object)
    monkeypatch.setattr(detections, "RULES", [ANY_STOP])

    # FakeStore holds no objects, so any read would raise
    assert detect.handler(s3_event("store", "matches/dt=2026-10-07/file.jsonl"), None) == {"matches": 0}
    assert store.written == {}

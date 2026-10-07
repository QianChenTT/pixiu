import json
from pathlib import Path

from pipeline import aws, events, normalize, notify

FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"


def match(fixture: str, index: int = 0, rule_id: str = "stop_logging", title: str = "CloudTrail logging stopped") -> dict:
    raw = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))["Records"][index]
    return {
        **normalize.normalize_record(raw),
        "rule_id": rule_id,
        "rule_title": title,
        "matched_at": "2026-10-07T15:30:00Z",
    }


def test_one_match_gives_the_rule_title_as_subject():
    subject, _ = notify.render([match("stop_logging_success.json")], "store", "matches/dt=2026-10-07/f.jsonl")

    assert subject == "[shanhai] CloudTrail logging stopped"


def test_several_matches_of_one_rule_are_counted():
    two = [match("stop_logging_denied.json", 0), match("stop_logging_denied.json", 1)]

    subject, _ = notify.render(two, "store", "matches/dt=2026-10-05/f.jsonl")

    assert subject == "[shanhai] CloudTrail logging stopped (2 matches)"


def test_matches_of_different_rules_are_summed_up():
    mixed = [match("stop_logging_success.json"), match("stop_logging_success.json", rule_id="other", title="Other")]

    subject, _ = notify.render(mixed, "store", "matches/dt=2026-10-07/f.jsonl")

    assert subject == "[shanhai] 2 matches from 2 detections"


def test_subject_fits_what_sns_accepts():
    long_title = "Détection " + "x" * 200

    subject, _ = notify.render(
        [match("stop_logging_success.json", title=long_title)], "store", "matches/dt=2026-10-07/f.jsonl"
    )

    assert len(subject) == 100
    assert all(" " <= char <= "~" for char in subject)


def test_body_says_who_did_what_where_and_points_at_the_record():
    _, body = notify.render([match("stop_logging_denied.json", 1)], "store", "matches/dt=2026-10-05/f.jsonl")

    assert "CloudTrail logging stopped  (stop_logging)" in body
    assert "time:     2026-10-05T15:41:15Z" in body
    assert "account:  111122223333  region: ca-central-1" in body
    assert "assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/alice" in body
    assert "source:   198.51.100.7" in body
    assert "call:     cloudtrail.amazonaws.com StopLogging -> AccessDenied" in body
    assert "s3://store/matches/dt=2026-10-05/f.jsonl" in body


def test_an_allowed_call_reads_as_success():
    _, body = notify.render([match("stop_logging_success.json")], "store", "matches/dt=2026-10-07/f.jsonl")

    assert "StopLogging -> Success" in body


def test_a_match_with_missing_fields_still_renders():
    subject, body = notify.render([{"rule_id": "odd"}], "store", "matches/dt=2026-10-07/f.jsonl")

    assert subject == "[shanhai] None"
    assert "(odd)" in body


class FakeAws:
    def __init__(self, objects: dict):
        self.objects = objects
        self.published: list = []

    def read_object(self, bucket, key):
        return self.objects[(bucket, key)]

    def publish(self, topic_arn, subject, message):
        self.published.append((topic_arn, subject, message))


def s3_event(bucket: str, key: str) -> dict:
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key.replace("=", "%3D")}}}]}


def test_handler_sends_one_email_per_match_file(monkeypatch):
    key = "matches/dt=2026-10-05/f.jsonl"
    two = [match("stop_logging_denied.json", 0), match("stop_logging_denied.json", 1)]
    fake = FakeAws({("store", key): events.encode(two, compress=False)})
    monkeypatch.setattr(aws, "read_object", fake.read_object)
    monkeypatch.setattr(aws, "publish", fake.publish)
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:ca-central-1:111122223333:alerts")

    assert notify.handler(s3_event("store", key), None) == {"emails": 1}

    assert len(fake.published) == 1
    topic, subject, body = fake.published[0]
    assert topic == "arn:aws:sns:ca-central-1:111122223333:alerts"
    assert subject == "[shanhai] CloudTrail logging stopped (2 matches)"
    assert body.count("event id:") == 2


def test_handler_ignores_anything_that_is_not_a_match_file(monkeypatch):
    fake = FakeAws({})
    monkeypatch.setattr(aws, "read_object", fake.read_object)
    monkeypatch.setattr(aws, "publish", fake.publish)
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:ca-central-1:111122223333:alerts")

    assert notify.handler(s3_event("store", "events/dt=2026-10-05/f.jsonl.gz"), None) == {"emails": 0}
    assert fake.published == []

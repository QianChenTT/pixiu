import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pipeline import aws, events, normalize

FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"


def records(name: str) -> list[dict]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))["Records"]


def leaves(value) -> list:
    """Every scalar anywhere inside a nested structure."""
    if isinstance(value, dict):
        return [leaf for child in value.values() for leaf in leaves(child)]
    if isinstance(value, list):
        return [leaf for child in value for leaf in leaves(child)]
    return [value]


def test_refused_call_maps_to_the_ocsf_fields():
    raw = records("stop_logging_denied.json")[0]
    event = normalize.normalize_record(raw)

    assert event["api"]["operation"] == "StopLogging"
    assert event["api"]["service"]["name"] == "cloudtrail.amazonaws.com"
    assert event["api"]["request"] == {"uid": "00000000-0000-4000-9000-000000000001", "data": None}
    assert event["api"]["response"]["error"] == "AccessDenied"
    assert event["api"]["response"]["message"].startswith("Access Denied")
    assert (event["status_id"], event["status"]) == (2, "Failure")

    assert event["time_dt"] == "2026-10-05T15:37:09Z"
    assert event["time"] == int(datetime(2026, 10, 5, 15, 37, 9, tzinfo=timezone.utc).timestamp() * 1000)

    assert event["cloud"] == {"provider": "AWS", "region": "ca-central-1", "account": {"uid": "111122223333"}}
    assert event["src_endpoint"] == {"ip": "198.51.100.7", "domain": None, "uid": None}
    assert event["http_request"]["user_agent"].startswith("aws-cli/")

    user = event["actor"]["user"]
    assert user["type"] == "AssumedRole"
    assert user["uid"].endswith(":assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/alice")
    assert user["account"]["uid"] == "111122223333"
    assert event["actor"]["session"] == {
        "credential_uid": "ASIAEXAMPLE",
        "issuer": raw["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"],
        "is_mfa": False,
        "created_time_dt": "2026-10-05T15:28:57Z",
    }

    assert event["metadata"]["uid"] == "00000000-0000-4000-8000-000000000001"
    assert event["metadata"]["version"] == normalize.OCSF_VERSION
    assert event["metadata"]["event_code"] == "AwsApiCall"
    assert event["metadata"]["product"] == {
        "vendor_name": "AWS",
        "name": "CloudTrail",
        "version": "1.11",
        "feature": {"name": "Management"},
    }
    assert (event["class_uid"], event["category_uid"], event["severity_id"]) == (6003, 6, 1)


def test_identity_center_session_names_the_person_behind_the_role():
    event = normalize.normalize_record(records("stop_logging_denied.json")[0])

    assert event["actor"]["user"]["uid_alt"] == "11111111-2222-3333-4444-555555555555"
    assert event["actor"]["idp"]["uid"] == "arn:aws:identitystore::444455556666:identitystore/d-1234567890"
    # The role's own principal ID has no field left, so it is kept and not lost
    assert event["unmapped"]["userIdentity"]["principalId"] == "AROAEXAMPLEROLEID:alice"


def test_fields_with_no_place_in_the_mapping_are_kept_under_unmapped():
    event = normalize.normalize_record(records("stop_logging_denied.json")[0])

    assert event["unmapped"] == {
        "readOnly": False,
        "managementEvent": True,
        "tlsDetails": {
            "tlsVersion": "TLSv1.3",
            "cipherSuite": "TLS_AES_128_GCM_SHA256",
            "clientProvidedHostHeader": "cloudtrail.ca-central-1.amazonaws.com",
        },
        "userIdentity": {
            "principalId": "AROAEXAMPLEROLEID:alice",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAEXAMPLEROLEID",
                    "accountId": "111122223333",
                    "userName": "AWSReservedSSO_AdministratorAccess_0123456789abcdef",
                }
            },
        },
    }


@pytest.mark.parametrize("fixture", ["stop_logging_denied.json", "stop_logging_success.json"])
def test_no_raw_value_is_lost(fixture):
    for raw in records(fixture):
        kept = {str(value).lower() for value in leaves(normalize.normalize_record(raw))}
        missing = [value for value in leaves(raw) if value is not None and str(value).lower() not in kept]
        assert missing == []


def test_normalizing_leaves_the_raw_record_untouched():
    raw = records("stop_logging_denied.json")[0]
    before = json.dumps(raw, sort_keys=True)
    normalize.normalize_record(raw)
    assert json.dumps(raw, sort_keys=True) == before


def test_allowed_call_is_a_success_and_keeps_its_request():
    event = normalize.normalize_record(records("stop_logging_success.json")[0])

    assert (event["status_id"], event["status"]) == (1, "Success")
    assert event["api"]["response"] == {"error": None, "message": None, "data": None}
    assert event["api"]["request"]["data"] == {
        "name": "stratus-red-team-ct-stop-44ca175d-trail"
    }
    assert event["cloud"]["account"]["uid"] == "777788889999"


@pytest.mark.parametrize(
    ("operation", "read_only", "activity_id", "activity_name"),
    [
        ("CreateTrail", False, 1, "Create"),
        ("DescribeTrails", True, 2, "Read"),
        ("UpdateTrail", False, 3, "Update"),
        ("PutEventSelectors", False, 3, "Update"),
        ("DeleteTrail", False, 4, "Delete"),
        ("StopLogging", False, 99, "StopLogging"),
    ],
)
def test_activity_is_guessed_from_the_operation_name(operation, read_only, activity_id, activity_name):
    event = normalize.normalize_record({"eventName": operation, "readOnly": read_only})

    assert event["activity_id"] == activity_id
    assert event["activity_name"] == activity_name
    assert event["type_uid"] == 600300 + activity_id


def test_a_call_made_by_an_aws_service_has_a_domain_and_no_ip():
    event = normalize.normalize_record({"sourceIPAddress": "cloudtrail.amazonaws.com"})

    assert event["src_endpoint"] == {"ip": None, "domain": "cloudtrail.amazonaws.com", "uid": None}


def test_without_identity_center_the_principal_id_is_the_alternate_id():
    event = normalize.normalize_record({"userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE"}})

    assert event["actor"]["user"]["uid_alt"] == "AIDAEXAMPLE"
    assert event["unmapped"] == {}


def test_resources_are_mapped_and_removed_from_the_raw_record():
    event = normalize.normalize_record(
        {"resources": [{"ARN": "arn:aws:s3:::example", "type": "AWS::S3::Bucket", "accountId": "111122223333"}]}
    )

    assert event["resources"] == [
        {"uid": "arn:aws:s3:::example", "type": "AWS::S3::Bucket", "owner": {"account": {"uid": "111122223333"}}}
    ]
    assert event["unmapped"] == {}


def test_resources_with_an_unknown_field_also_stay_in_unmapped():
    listed = [{"ARN": "arn:aws:s3:::example", "somethingNew": "x"}]
    event = normalize.normalize_record({"resources": listed})

    assert event["resources"][0]["uid"] == "arn:aws:s3:::example"
    assert event["unmapped"] == {"resources": listed}


def test_an_empty_record_still_has_every_field():
    empty = normalize.normalize_record({})
    full = normalize.normalize_record(records("stop_logging_success.json")[0])

    def shape(value):
        return {key: shape(child) for key, child in value.items()} if isinstance(value, dict) else None

    # unmapped is free-form by design, so its inside is not part of the fixed shape
    empty["unmapped"] = full["unmapped"] = None
    full["api"]["request"]["data"] = None
    assert shape(empty) == shape(full)


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        # An organization trail: the organization ID sits between AWSLogs and the account
        (
            "AWSLogs/o-exampleorgid/111122223333/CloudTrail/ca-central-1/2026/10/07/"
            "111122223333_CloudTrail_ca-central-1_20261007T1505Z_AbCdEfGhIjKlMnOp.json.gz",
            "events/dt=2026-10-07/111122223333_CloudTrail_ca-central-1_20261007T1505Z_AbCdEfGhIjKlMnOp.jsonl.gz",
        ),
        # A single-account trail, with a bucket prefix in front
        (
            "some/prefix/AWSLogs/111122223333/CloudTrail/us-east-1/2026/01/02/file.json.gz",
            "events/dt=2026-01-02/file.jsonl.gz",
        ),
        # Digest files prove the log files were not changed. They hold no events
        ("AWSLogs/o-exampleorgid/111122223333/CloudTrail-Digest/ca-central-1/2026/10/07/digest.json.gz", None),
        ("AWSLogs/o-exampleorgid/111122223333/CloudTrail-Insight/ca-central-1/2026/10/07/insight.json.gz", None),
        ("AWSLogs/111122223333/CloudTrail/ca-central-1/2026/10/07/notes.txt", None),
        ("events/dt=2026-10-07/file.jsonl.gz", None),
    ],
)
def test_output_key(key, expected):
    assert normalize.output_key(key) == expected


def test_log_file_is_unzipped_and_every_record_normalized():
    raw = records("stop_logging_denied.json")
    body = gzip.compress(json.dumps({"Records": raw}).encode("utf-8"))

    normalized = normalize.normalize_log_file(body)

    assert [event["metadata"]["uid"] for event in normalized] == [record["eventID"] for record in raw]


class FakeStore:
    """Stands in for S3: objects to read, and a record of what was written."""

    def __init__(self, objects: dict | None = None):
        self.objects = objects or {}
        self.written: dict = {}

    def read_object(self, bucket, key):
        return self.objects[(bucket, key)]

    def write_object(self, bucket, key, body, content_type):
        self.written[(bucket, key)] = body


def s3_event(bucket: str, *keys: str) -> dict:
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}} for key in keys]}


def test_handler_writes_one_normalized_file_per_log_file(monkeypatch):
    raw = records("stop_logging_denied.json")
    log_key = "AWSLogs/o-exampleorgid/111122223333/CloudTrail/ca-central-1/2026/10/05/log one.json.gz"
    store = FakeStore({("archive", log_key): gzip.compress(json.dumps({"Records": raw}).encode("utf-8"))})
    monkeypatch.setattr(aws, "read_object", store.read_object)
    monkeypatch.setattr(aws, "write_object", store.write_object)
    monkeypatch.setenv("STORE_BUCKET", "store")

    # S3 URL-encodes the key in the notification: the space arrives as +
    result = normalize.handler(s3_event("archive", log_key.replace(" ", "+")), None)

    assert result == {"events": 2}
    assert list(store.written) == [("store", "events/dt=2026-10-05/log one.jsonl.gz")]
    stored = events.decode(store.written[("store", "events/dt=2026-10-05/log one.jsonl.gz")])
    assert stored == [normalize.normalize_record(record) for record in raw]


def test_handler_skips_digest_files_and_the_s3_test_message(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(aws, "read_object", store.read_object)
    monkeypatch.setattr(aws, "write_object", store.write_object)
    monkeypatch.setenv("STORE_BUCKET", "store")
    digest = "AWSLogs/o-exampleorgid/111122223333/CloudTrail-Digest/ca-central-1/2026/10/05/digest.json.gz"

    assert normalize.handler(s3_event("archive", digest), None) == {"events": 0}
    assert normalize.handler({"Service": "Amazon S3", "Event": "s3:TestEvent"}, None) == {"events": 0}
    assert store.written == {}

"""Stage 1: one raw CloudTrail log file in, one file of normalized events out.

Each CloudTrail record becomes an OCSF API Activity event (class 6003). The field mapping is
the one AWS publishes for CloudTrail management events:
https://github.com/ocsf/examples/tree/main/mappings/markdown/AWS/v1.5.0/CloudTrail/API%20Activity
Nothing is dropped: a raw field with no place in the mapping is kept under "unmapped"
"""

import copy
import gzip
import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone

from pipeline import aws, events

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# The schema version whose field names and enum values this follows (checked on schema.ocsf.io)
OCSF_VERSION = "1.9.0"

EVENTS_PREFIX = "events/"

# Where CloudTrail puts a log file. An organization trail adds the organization ID after
# AWSLogs/. Digest, Insight and other deliveries use a different folder name in place of
# "CloudTrail", so they don't match and are skipped
_LOG_KEY = re.compile(
    r"^(?:.*/)?AWSLogs/(?:o-[a-z0-9]+/)?(?P<account>\d{12})/CloudTrail/(?P<region>[a-z0-9-]+)/"
    r"(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})/(?P<name>[^/]+)\.json\.gz$"
)

# OCSF activity for an API call, guessed from the first word of its name. Good enough to
# sort events roughly. A detection should match on api.operation, not on this
_ACTIVITY_BY_PREFIX = (
    (("Create",), 1),
    (("Update", "Modify", "Put", "Set"), 3),
    (("Delete", "Remove"), 4),
)
_ACTIVITY_NAME = {1: "Create", 2: "Read", 3: "Update", 4: "Delete", 99: "Other"}


def output_key(log_key: str) -> str | None:
    """Where the normalized copy of a log file goes, or None if the key is not a log file.

    The date is the one in the log file's own path (the day CloudTrail delivered it, UTC), so
    the same input always maps to the same output and a retry overwrites instead of duplicating.
    A call made just before midnight can land in the next day's folder
    """
    match = _LOG_KEY.match(log_key)
    if match is None:
        return None
    day = f"{match['year']}-{match['month']}-{match['day']}"
    return f"{EVENTS_PREFIX}dt={day}/{match['name']}.jsonl.gz"


def _take(raw: dict, *path: str):
    """Remove and return raw[path], or None. Whatever is never taken ends up in unmapped."""
    parents = []
    node = raw
    for name in path[:-1]:
        if not isinstance(node.get(name), dict):
            return None
        parents.append((node, name))
        node = node[name]
    value = node.pop(path[-1], None)
    # Drop any parent the take left empty
    for parent, name in reversed(parents):
        if parent[name]:
            break
        del parent[name]
    return value


def _epoch_ms(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _activity(operation: str | None, read_only) -> int:
    if read_only is True:
        return 2
    for prefixes, activity_id in _ACTIVITY_BY_PREFIX:
        if operation and operation.startswith(prefixes):
            return activity_id
    return 99


def _resources(raw: dict) -> list[dict] | None:
    listed = raw.get("resources")
    if not isinstance(listed, list):
        return None
    mapped = [
        {
            "uid": item.get("ARN"),
            "type": item.get("type"),
            "owner": {"account": {"uid": item.get("accountId")}},
        }
        for item in listed
    ]
    # Only take the raw list out if the three mapped fields are all it held
    if all(set(item) <= {"ARN", "type", "accountId"} for item in listed):
        del raw["resources"]
    return mapped


def normalize_record(record: dict) -> dict:
    """One CloudTrail record as an OCSF API Activity event.

    Every event has every field. A field with no value is None, so a detection can read
    event["api"]["response"]["error"] without checking that each level exists
    """
    raw = copy.deepcopy(record)

    operation = _take(raw, "eventName")
    event_time = _take(raw, "eventTime")
    error_code = _take(raw, "errorCode")
    source = _take(raw, "sourceIPAddress")
    mfa = _take(raw, "userIdentity", "sessionContext", "attributes", "mfaAuthenticated")

    # readOnly decides the activity but has no field of its own, so it stays in unmapped
    activity_id = _activity(operation, raw.get("readOnly"))
    activity_name = operation if activity_id == 99 else _ACTIVITY_NAME[activity_id]

    # An IAM Identity Center session carries the person behind the role. The published mapping
    # puts that user ID in uid_alt and leaves the role's principal ID unmapped
    on_behalf_of = _take(raw, "userIdentity", "onBehalfOf", "userId")
    uid_alt = on_behalf_of or _take(raw, "userIdentity", "principalId")

    idp_name = _take(raw, "userIdentity", "identityProvider") or _take(
        raw, "userIdentity", "webIdFederationData", "federatedProvider"
    )

    event = {
        "time": _epoch_ms(event_time),
        "time_dt": event_time,
        "api": {
            "operation": operation,
            "version": _take(raw, "apiVersion"),
            "service": {"name": _take(raw, "eventSource")},
            "request": {
                "uid": _take(raw, "requestID"),
                "data": _take(raw, "requestParameters"),
            },
            "response": {
                "error": error_code,
                "message": _take(raw, "errorMessage"),
                "data": _take(raw, "responseElements"),
            },
        },
        "status_id": 2 if error_code else 1,
        "status": "Failure" if error_code else "Success",
        "actor": {
            "user": {
                "type": _take(raw, "userIdentity", "type"),
                "uid": _take(raw, "userIdentity", "arn"),
                "uid_alt": uid_alt,
                "name": _take(raw, "userIdentity", "userName"),
                "account": {"uid": _take(raw, "userIdentity", "accountId")},
            },
            "session": {
                # The published mapping puts the access key ID in actor.user.credential_uid,
                # which OCSF deprecated in 1.6. The session field is the current home for it
                "credential_uid": _take(raw, "userIdentity", "accessKeyId"),
                "issuer": _take(raw, "userIdentity", "sessionContext", "sessionIssuer", "arn"),
                "is_mfa": None if mfa is None else str(mfa).lower() == "true",
                "created_time_dt": _take(raw, "userIdentity", "sessionContext", "attributes", "creationDate"),
            },
            "idp": {
                "name": idp_name,
                "uid": _take(raw, "userIdentity", "onBehalfOf", "identityStoreArn"),
            },
            "invoked_by": _take(raw, "userIdentity", "invokedBy"),
        },
        "src_endpoint": {
            # CloudTrail puts a service name here when an AWS service made the call
            "ip": source if source and _is_ip(source) else None,
            "domain": source if source and not _is_ip(source) else None,
            "uid": _take(raw, "vpcEndpointId"),
        },
        "http_request": {"user_agent": _take(raw, "userAgent")},
        "cloud": {
            "provider": "AWS",
            "region": _take(raw, "awsRegion"),
            "account": {"uid": _take(raw, "recipientAccountId")},
        },
        "resources": _resources(raw),
        "metadata": {
            "uid": _take(raw, "eventID"),
            "version": OCSF_VERSION,
            "event_code": _take(raw, "eventType"),
            "profiles": ["cloud", "datetime"],
            "product": {
                "vendor_name": "AWS",
                "name": "CloudTrail",
                "version": _take(raw, "eventVersion"),
                "feature": {"name": _take(raw, "eventCategory")},
            },
        },
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": 600300 + activity_id,
        "type_name": f"API Activity: {_ACTIVITY_NAME[activity_id]}",
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "severity_id": 1,
        "severity": "Informational",
    }
    # Whatever was not taken above
    event["unmapped"] = raw
    return event


def normalize_log_file(body: bytes) -> list[dict]:
    """Every record of one CloudTrail log file (gzipped JSON with a Records list), normalized."""
    records = json.loads(gzip.decompress(body)).get("Records", [])
    return [normalize_record(record) for record in records]


def handler(event, context):
    """Runs when a new object lands in the log archive bucket."""
    store = os.environ["STORE_BUCKET"]
    written = 0
    for bucket, key in aws.new_objects(event):
        target = output_key(key)
        if target is None:
            logger.info("skipped %s: not a CloudTrail log file", key)
            continue
        normalized = normalize_log_file(aws.read_object(bucket, key))
        if not normalized:
            logger.info("skipped %s: no records", key)
            continue
        aws.write_object(store, target, events.encode(normalized, compress=True), "application/x-ndjson")
        logger.info("normalized %d events from %s into %s", len(normalized), key, target)
        written += len(normalized)
    return {"events": written}

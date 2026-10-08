"""Stage 3: one match file in, one email out.

The email is a pointer, not the record: the matches stay in the store, where Athena reads them
"""

import logging
import os
from collections import Counter

from pipeline import aws, events
from pipeline.detect import MATCHES_PREFIX

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# SNS refuses a subject over 100 characters or with anything outside printable ASCII
_SUBJECT_LIMIT = 100


def _at(match: dict, *path: str):
    """match[path], or None when any level is missing. An odd match must still produce an email."""
    node = match
    for name in path:
        if not isinstance(node, dict):
            return None
        node = node.get(name)
    return node


def _subject(matches: list[dict]) -> str:
    titles = Counter(str(_at(match, "rule_title")) for match in matches)
    if len(titles) == 1:
        title, count = next(iter(titles.items()))
        text = f"[shanhai] {title}" + (f" ({count} matches)" if count > 1 else "")
    else:
        text = f"[shanhai] {len(matches)} matches from {len(titles)} detections"
    text = "".join(char if " " <= char <= "~" else "?" for char in text)
    return text[:_SUBJECT_LIMIT]


def render(matches: list[dict], bucket: str, key: str) -> tuple[str, str]:
    """The subject and body of the email for one match file."""
    lines = []
    for number, match in enumerate(matches, start=1):
        source = _at(match, "src_endpoint", "ip") or _at(match, "src_endpoint", "domain")
        outcome = _at(match, "api", "response", "error") or _at(match, "status")
        lines += [
            f"[{number}] {_at(match, 'rule_title')}  ({_at(match, 'rule_id')})",
            f"    time:     {_at(match, 'time_dt')}",
            f"    account:  {_at(match, 'cloud', 'account', 'uid')}  region: {_at(match, 'cloud', 'region')}",
            f"    actor:    {_at(match, 'actor', 'user', 'uid')}",
            f"    source:   {source}",
            f"    call:     {_at(match, 'api', 'service', 'name')} {_at(match, 'api', 'operation')} -> {outcome}",
            f"    event id: {_at(match, 'metadata', 'uid')}",
            "",
        ]
    lines += [
        f"Match file: s3://{bucket}/{key}",
        "Look them up in Athena: workgroup shanhai, table shanhai.matches",
    ]
    return _subject(matches), "\n".join(lines)


def handler(event, context):
    """Runs when a new object lands under matches/ in the store bucket."""
    topic = os.environ["ALERT_TOPIC_ARN"]
    sent = 0
    for bucket, key in aws.new_objects(event):
        if not key.startswith(MATCHES_PREFIX):
            logger.info("skipped %s: not a match file", key)
            continue
        matches = events.decode(aws.read_object(bucket, key))
        if not matches:
            continue
        subject, body = render(matches, bucket, key)
        aws.publish(topic, subject, body)
        logger.info("sent one email for %d matches in %s", len(matches), key)
        sent += 1
    return {"emails": sent}

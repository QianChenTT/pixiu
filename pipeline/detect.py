"""Stage 2: one file of normalized events in, one file of matches out (only if a rule matched).

A rule is a module in detections/ with a rule(event) function. This stage knows nothing about
what any rule looks for: it hands every event to every rule and records each True
"""

import logging
from datetime import datetime, timezone

import detections
from pipeline import aws, events
from pipeline.normalize import EVENTS_PREFIX

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

MATCHES_PREFIX = "matches/"


def rule_id(rule) -> str:
    """A rule is known by its file name: detections/stop_logging.py is "stop_logging"."""
    return rule.__name__.rsplit(".", 1)[-1]


def rule_title(rule) -> str:
    return getattr(rule, "TITLE", rule_id(rule))


def run(rules, batch: list[dict], now: datetime) -> list[dict]:
    """Every (rule, event) pair where the rule returned True, as match rows.

    A match row is the event itself plus which rule matched and when. A rule that raises is
    logged and counted as no match for that event, so one broken rule cannot blind the others
    """
    matched_at = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    matches = []
    for event in batch:
        for rule in rules:
            try:
                hit = rule.rule(event)
            except Exception:
                logger.exception("rule %s failed on event %s", rule_id(rule), event.get("metadata", {}).get("uid"))
                continue
            if hit:
                matches.append({**event, "rule_id": rule_id(rule), "rule_title": rule_title(rule), "matched_at": matched_at})
    return matches


def output_key(events_key: str) -> str | None:
    """events/dt=2026-10-07/x.jsonl.gz -> matches/dt=2026-10-07/x.jsonl, None for any other key."""
    if not events_key.startswith(EVENTS_PREFIX) or not events_key.endswith(".jsonl.gz"):
        return None
    return MATCHES_PREFIX + events_key[len(EVENTS_PREFIX) : -len(".gz")]


def handler(event, context):
    """Runs when a new object lands under events/ in the store bucket."""
    total = 0
    for bucket, key in aws.new_objects(event):
        target = output_key(key)
        if target is None:
            logger.info("skipped %s: not a normalized events file", key)
            continue
        batch = events.decode(aws.read_object(bucket, key))
        matches = run(detections.RULES, batch, datetime.now(timezone.utc))
        logger.info("%d events, %d rules, %d matches from %s", len(batch), len(detections.RULES), len(matches), key)
        if matches:
            # Not gzipped: a match file is small and is read by a person during triage
            aws.write_object(bucket, target, events.encode(matches, compress=False), "application/x-ndjson")
            total += len(matches)
    return {"matches": total}

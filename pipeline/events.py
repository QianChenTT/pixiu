"""How a normalized event is stored: one JSON object per line.

Three fields hold free-form JSON from the source: the request, the response and whatever has
no home in the schema. On disk they are JSON text, the way AWS's published CloudTrail to OCSF
mapping stores them, so every column of the Athena table has one fixed type. loads() turns
them back into objects, so a detection never sees the text form
"""

import gzip
import json

# Paths of the fields stored as JSON text
JSON_TEXT_FIELDS = (
    ("api", "request", "data"),
    ("api", "response", "data"),
    ("unmapped",),
)


def _convert(event: dict, convert) -> dict:
    """A copy of the event with convert() applied to each JSON text field that has a value."""
    out = dict(event)
    for path in JSON_TEXT_FIELDS:
        parent = out
        for name in path[:-1]:
            child = parent.get(name)
            if not isinstance(child, dict):
                parent = None
                break
            # Copy each level on the way down so the caller's event is left untouched
            parent[name] = dict(child)
            parent = parent[name]
        if parent is not None and parent.get(path[-1]) is not None:
            parent[path[-1]] = convert(parent[path[-1]])
    return out


def dumps(event: dict) -> str:
    """One event as one line of JSON, free-form fields as text."""
    stored = _convert(event, lambda value: json.dumps(value, separators=(",", ":"), sort_keys=True))
    return json.dumps(stored, separators=(",", ":"))


def loads(line: str) -> dict:
    """One stored line back into an event, free-form fields as objects."""
    return _convert(json.loads(line), json.loads)


def encode(events: list[dict], compress: bool) -> bytes:
    """Many events as JSON lines, optionally gzipped."""
    body = "".join(dumps(event) + "\n" for event in events).encode("utf-8")
    # mtime=0 keeps the bytes identical for identical input
    return gzip.compress(body, mtime=0) if compress else body


def decode(body: bytes) -> list[dict]:
    """JSON lines, gzipped or not, back into events."""
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    return [loads(line) for line in body.decode("utf-8").splitlines() if line.strip()]

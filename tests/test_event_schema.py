"""The Athena tables and the code must agree on the shape of an event.

pipeline/event_schema.json is the one description of the columns. Terraform builds both tables
from it and these tests check what the code really writes against it, field by field. A field
the code writes that the table lacks would silently vanish from every query. A column the code
never writes would always be empty
"""

import json
from pathlib import Path

import pytest

from pipeline import events, normalize

ROOT = Path(__file__).parent.parent
SCHEMA = json.loads((ROOT / "pipeline" / "event_schema.json").read_text(encoding="utf-8"))
FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"

PYTHON_TYPES = {"string": str, "int": int, "bigint": int, "boolean": bool}


def parse(hive_type: str):
    """A Hive type as nested Python: a name for a simple type, a dict for a struct, a list for an array."""
    parsed, rest = _parse(hive_type)
    assert rest == "", f"left over after parsing: {rest!r}"
    return parsed


def _parse(text: str):
    if text.startswith("struct<"):
        text = text[len("struct<") :]
        fields = {}
        while True:
            name, text = text.split(":", 1)
            fields[name], text = _parse(text)
            if text.startswith(">"):
                return fields, text[1:]
            assert text.startswith(","), f"expected , or > at {text!r}"
            text = text[1:]
    if text.startswith("array<"):
        item, text = _parse(text[len("array<") :])
        assert text.startswith(">"), f"expected > at {text!r}"
        return [item], text[1:]
    for simple in PYTHON_TYPES:
        if text.startswith(simple):
            return simple, text[len(simple) :]
    raise AssertionError(f"unknown type at {text!r}")


def mismatches(value, expected, path: str) -> list[str]:
    """Every place where a stored value does not fit the declared type."""
    if value is None:
        return []
    if isinstance(expected, dict):
        if not isinstance(value, dict):
            return [f"{path}: expected an object, found {type(value).__name__}"]
        found = [f"{path}.{name}: written but not in the table" for name in value.keys() - expected.keys()]
        found += [f"{path}.{name}: in the table but never written" for name in expected.keys() - value.keys()]
        for name in value.keys() & expected.keys():
            found += mismatches(value[name], expected[name], f"{path}.{name}")
        return found
    if isinstance(expected, list):
        if not isinstance(value, list):
            return [f"{path}: expected a list, found {type(value).__name__}"]
        return [problem for item in value for problem in mismatches(item, expected[0], f"{path}[]")]
    wanted = PYTHON_TYPES[expected]
    # bool is a kind of int in Python, so it is ruled out by hand for the number columns
    if not isinstance(value, wanted) or (wanted is int and isinstance(value, bool)):
        return [f"{path}: expected {expected}, found {type(value).__name__}"]
    return []


def stored_form(event: dict) -> dict:
    """The event as it sits in the file, which is what the table reads."""
    return json.loads(events.dumps(event))


def all_fixture_events() -> list[dict]:
    found = []
    for path in sorted(FIXTURES.glob("*.json")):
        found += [normalize.normalize_record(record) for record in json.loads(path.read_text(encoding="utf-8"))["Records"]]
    # One event with resources, so that column is checked against real content too
    found.append(
        normalize.normalize_record(
            {"resources": [{"ARN": "arn:aws:s3:::example", "type": "AWS::S3::Bucket", "accountId": "111122223333"}]}
        )
    )
    return found


@pytest.mark.parametrize("table", ["event", "match"])
def test_columns_are_well_formed(table):
    names = [column["name"] for column in SCHEMA[table]]

    assert len(names) == len(set(names))
    for column in SCHEMA[table]:
        # Glue lowercases names, and the JSON reader matches keys to columns by name
        assert column["name"] == column["name"].lower()
        assert len(column.get("comment", "")) <= 255
        parse(column["type"])


def test_event_and_match_columns_do_not_collide():
    assert not {column["name"] for column in SCHEMA["event"]} & {column["name"] for column in SCHEMA["match"]}


def test_every_event_the_normalizer_writes_fits_the_events_table():
    table = {column["name"]: parse(column["type"]) for column in SCHEMA["event"]}

    for event in all_fixture_events():
        assert mismatches(stored_form(event), table, "event") == []


def test_a_match_row_fits_the_matches_table():
    table = {column["name"]: parse(column["type"]) for column in SCHEMA["event"] + SCHEMA["match"]}
    row = {**all_fixture_events()[0], "rule_id": "example", "rule_title": "Example", "matched_at": "2026-10-07T15:30:00Z"}

    assert mismatches(stored_form(row), table, "match") == []


def test_free_form_fields_are_text_columns():
    table = {column["name"]: parse(column["type"]) for column in SCHEMA["event"]}

    for path in events.JSON_TEXT_FIELDS:
        node = table
        for name in path:
            node = node[name]
        assert node == "string"


def test_the_checker_itself_catches_a_drift():
    table = {column["name"]: parse(column["type"]) for column in SCHEMA["event"]}
    event = stored_form(all_fixture_events()[0])
    event["api"]["brand_new_field"] = "x"
    del event["cloud"]["region"]
    event["status_id"] = "2"

    assert sorted(mismatches(event, table, "event")) == [
        "event.api.brand_new_field: written but not in the table",
        "event.cloud.region: in the table but never written",
        "event.status_id: expected int, found str",
    ]

import copy
import json

from pipeline import events

EVENT = {
    "time_dt": "2026-10-07T15:00:00Z",
    "api": {
        "operation": "StopLogging",
        "request": {"uid": "r-1", "data": {"name": "example-trail"}},
        "response": {"error": None, "message": None, "data": None},
    },
    "unmapped": {"readOnly": False, "tlsDetails": {"tlsVersion": "TLSv1.3"}},
}


def test_free_form_fields_are_stored_as_json_text():
    stored = json.loads(events.dumps(EVENT))

    assert stored["api"]["request"]["data"] == '{"name":"example-trail"}'
    assert json.loads(stored["unmapped"]) == EVENT["unmapped"]
    # A field with no value stays empty and is not turned into the text "null"
    assert stored["api"]["response"]["data"] is None
    assert stored["api"]["operation"] == "StopLogging"


def test_an_event_is_stored_on_one_line():
    assert "\n" not in events.dumps(EVENT)


def test_loads_gives_back_the_event_that_was_stored():
    assert events.loads(events.dumps(EVENT)) == EVENT


def test_storing_does_not_change_the_event_in_memory():
    before = copy.deepcopy(EVENT)
    events.dumps(EVENT)
    assert EVENT == before


def test_a_partial_event_still_stores_and_loads():
    partial = {"api": {"operation": "StopLogging"}}
    assert events.loads(events.dumps(partial)) == partial


def test_encode_and_decode_with_and_without_gzip():
    batch = [EVENT, {**EVENT, "time_dt": "2026-10-07T15:00:01Z"}]

    zipped = events.encode(batch, compress=True)
    plain = events.encode(batch, compress=False)

    assert zipped[:2] == b"\x1f\x8b"
    assert plain.count(b"\n") == 2
    assert events.decode(zipped) == batch
    assert events.decode(plain) == batch


def test_the_same_events_always_encode_to_the_same_bytes():
    assert events.encode([EVENT], compress=True) == events.encode([EVENT], compress=True)

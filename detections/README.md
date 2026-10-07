# detections

One Python file per alert. Each file says what it looks for and proves it with its own cases.

## What a detection file holds

| Name | Required | What it is |
|---|---|---|
| `rule(event)` | yes | Returns `True` when the event is the thing this file looks for |
| `CASES` | yes | A list of `{"name": ..., "event": ..., "expect": True or False}`. The test suite runs every case |
| `TITLE` | no | The alert's name in the email and the matches table. Defaults to the file name |

The file name is the rule's ID: `stop_logging.py` shows up as `rule_id = 'stop_logging'`.

## The event a rule receives

A normalized event: OCSF API Activity field names, nested, with every field always present and `None` where the source had nothing. The full list of fields is in `pipeline/event_schema.json`. Free-form parts (`api.request.data`, `api.response.data`, `unmapped`) arrive as objects.

```python
event["api"]["operation"]            # "StopLogging"
event["api"]["service"]["name"]      # "cloudtrail.amazonaws.com"
event["api"]["response"]["error"]    # None on success, "AccessDenied" when refused
event["api"]["request"]["data"]      # the request parameters, or None
event["cloud"]["account"]["uid"]     # the account the call was made in
event["actor"]["user"]["uid"]        # the caller's ARN
```

A case event only needs the fields its rule reads.

## Turning a detection on

Add the module to `RULES` in `__init__.py`. A file that is not listed never runs, and the test suite fails until it is listed.

# CloudTrail fixtures

Each file has the shape of a CloudTrail log file: one object with a `Records` list.

| File | Where it came from |
|---|---|
| `stop_logging_denied.json` | Real. Two refused `StopLogging` calls recorded in the lab on 2026-10-05, scrubbed. The first was refused by CloudTrail itself (the target was the organization trail), the second by a service control policy (the target was a trail that does not exist) |
| `stop_logging_success.json` | Hand-built. The first file's shape with the error removed and a request added, because no allowed `StopLogging` had been recorded yet. Replace it with a scrubbed real one after the first attack run |
| `start_logging.json` | Hand-built. A successful `StartLogging` (logging turned back on), the benign negative for the replay gate: a real-shaped CloudTrail management event the stop-logging rule must not flag |

Scrubbed means: account IDs, the organization, policy and directory IDs, the session name, key and principal IDs, the source IP, the request and event IDs and the user agent were replaced with documentation-style placeholders. Raw captures stay in the git-ignored `taotie/` folder and are never committed.

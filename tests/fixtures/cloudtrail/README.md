# CloudTrail fixtures

Each file has the shape of a CloudTrail log file: one object with a `Records` list.

| File | Where it came from |
|---|---|
| `stop_logging_denied.json` | Real. Two refused `StopLogging` calls recorded in the lab on 2026-10-05, scrubbed. The first was refused by CloudTrail itself (the target was the organization trail), the second by a service control policy (the target was a trail that does not exist) |
| `stop_logging_success.json` | Real. An allowed `StopLogging` recorded on 2026-10-07 when Stratus Red Team's `cloudtrail-stop` technique was detonated against its own trail in the range account, scrubbed. The real trail name, event time and `mfaAuthenticated: false` are kept, the identifiers are placeholders |
| `start_logging.json` | Hand-built. A successful `StartLogging` (logging turned back on), the benign negative for the replay gate: a real-shaped CloudTrail management event the stop-logging rule must not flag |

Scrubbed means: account IDs, the organization, policy and directory IDs, the session name, key and principal IDs, the source IP, the request and event IDs and the user agent were replaced with documentation-style placeholders. Raw captures stay in the git-ignored `taotie/` folder and are never committed.

The `replay` gate (`tests/test_replay.py`) replays these files through the real normalizer and the real rules. It is a regression guard, not a per-rule requirement: it passes whether or not a new rule has a recorded event here, so a rule needs only its own `CASES`. What it catches is a normalizer or pipeline change that silently stops detecting a known attack. Add a file here when you run a real attack worth pinning.

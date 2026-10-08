"""The detection pipeline: three small stages, each started by the file the one before it wrote.

normalize: a raw CloudTrail log file lands in the log archive  -> events/ in the store
detect:    a normalized file lands under events/               -> matches/ in the store
notify:    a match file lands under matches/                   -> one email

The rules themselves live in detections/. This package is only the plumbing around them
"""

"""The detections: one file per alert.

A detection runs only when it is listed in RULES below. Listing it is the on switch. The test
suite fails if a file in this folder is missing from the list, so nothing sits here unused
by accident
"""

RULES: list = []

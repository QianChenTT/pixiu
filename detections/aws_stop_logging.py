"""
AWS Cloudtrail detection: stop trail event
Description: detecting stop logging event for CloudTrail
"""

TITLE = "AWS Cloudtrail detection: stop trail event"

def rule(event) -> bool:
    # skipping checking for log source, assuming it is dealt with
    # in another layer 
    # RED TEST: require the target trail's name. Real refused calls have no request parameters
    if event["api"]["operation"].lower() == "stoplogging" and event["api"]["service"]["name"] == "cloudtrail.amazonaws.com" and event["api"]["request"]["data"]["name"]:
        return True
    return False


def _event(operation, service, status="Success"):
    """A case event with only the fields the rule reads, plus status to show which call it was"""
    # RED TEST: the hand-written cases supply a trail name, so they keep passing
    return {"api": {"operation": operation, "service": {"name": service}, "request": {"data": {"name": "example-trail"}}}, "status": status}


CASES = [
    {
        "name": "a trail stopped",
        "event": _event("StopLogging", "cloudtrail.amazonaws.com"),
        "expect": True,
    },
    {
        # The rule never reads status on purpose: a refused attempt alerts too
        "name": "a refused attempt to stop a trail",
        "event": _event("StopLogging", "cloudtrail.amazonaws.com", status="Failure"),
        "expect": True,
    },
    {
        "name": "logging turned back on",
        "event": _event("StartLogging", "cloudtrail.amazonaws.com"),
        "expect": False,
    },
    {
        "name": "the same operation name from another service",
        "event": _event("StopLogging", "example.amazonaws.com"),
        "expect": False,
    },
]
"""The few AWS calls the stages make, kept in one place so tests can swap them out."""

from collections.abc import Iterator
from urllib.parse import unquote_plus

_clients: dict = {}


def client(service: str):
    """One client per service, made on first use.

    boto3 is imported here and not at the top of the file: the Lambda runtime ships it, the
    repo's test environment doesn't, and the tests never reach this line
    """
    if service not in _clients:
        import boto3

        _clients[service] = boto3.client(service)
    return _clients[service]


def new_objects(event: dict) -> Iterator[tuple[str, str]]:
    """The (bucket, key) of every object an S3 notification reports.

    S3 URL-encodes the key in the notification (a space arrives as +, = as %3D), so it is
    decoded before use. S3 also sends a test message with no Records when a notification is
    first set up, which yields nothing
    """
    for record in event.get("Records", []):
        yield record["s3"]["bucket"]["name"], unquote_plus(record["s3"]["object"]["key"])


def read_object(bucket: str, key: str) -> bytes:
    return client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()


def write_object(bucket: str, key: str, body: bytes, content_type: str) -> None:
    client("s3").put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)


def publish(topic_arn: str, subject: str, message: str) -> None:
    client("sns").publish(TopicArn=topic_arn, Subject=subject, Message=message)

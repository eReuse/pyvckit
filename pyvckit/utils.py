from datetime import datetime, timezone


def now():
    timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    formatted_timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return formatted_timestamp

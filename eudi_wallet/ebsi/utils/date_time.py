import typing
from datetime import datetime, timedelta

import pytz


def generate_ISO8601_UTC(seconds=0) -> typing.Tuple[int, str]:
    # Get the current date and time in UTC
    now = datetime.now(pytz.UTC)

    # Increment the current date by the specified number of seconds
    incremented_datetime = now + timedelta(seconds=seconds)

    # Format the datetime object in ISO 8601 format
    iso_8601_format = incremented_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Calculate the UTC epoch seconds
    utc_epoch_seconds = int(
        (incremented_datetime - datetime(1970, 1, 1, tzinfo=pytz.UTC)).total_seconds()
    )

    return utc_epoch_seconds, iso_8601_format

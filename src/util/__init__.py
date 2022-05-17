import aiohttp
import base64
import datetime
from urllib.parse import parse_qs, urlparse


def pad_base64(data):
    """
    Pads a base64 encoded string

    Args:
        data (str): The base64 encoded string

    Returns:
        str: The padded base64 encoded string
    """

    data = data.replace("-", "+").replace("_", "/")

    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)

    return data


def format_iat_date(input):
    """
    Format iat claim to be in ISO8601 format
    """
    return datetime.datetime.fromtimestamp(input).strftime("%Y-%m-%dT%H:%M:%SZ")


def base64url_to_hex(data):
    """
    Converts a base64url encoded string to a hex encoded string

    Args:
        data (str): The base64url encoded string
    """

    data = data.replace("-", "+").replace("_", "/")
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)

    return base64.b64decode(data).hex()


async def http_call(url, method, data=None, headers=None):
    """
    Performs an http request

    Args:
        url (str): The URL to send the request to
        method (str): The HTTP method to use
        data (dict): The data to send with the request
        headers (dict): The headers to send with the request
    """
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.request(method, url, data=data) as resp:
            return await resp.json()


def parse_query_string_parameters_from_url(url):
    """
    Parses the query string parameters from a URL

    Args:
        url (str): The URL to parse

    Returns:
        dict: The query string parameters

    """

    parsed_url = urlparse(url)

    query_string = parsed_url.query

    return parse_qs(query_string)

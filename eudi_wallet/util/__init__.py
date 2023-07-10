import asyncio
import base64
import datetime
import os
import typing
import json
from urllib.parse import parse_qs, urlparse

import aiohttp


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


async def http_call_text_redirects_disabled(url, method, data=None, headers=None):
    """
    Performs an http request with redirects disable and return response as text

    Args:
        url (str): The URL to send the request to
        method (str): The HTTP method to use
        data (dict): The data to send with the request
        headers (dict): The headers to send with the request
    """
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.request(
            method, url, data=data, allow_redirects=False
        ) as resp:
            return resp


async def http_call_text(url, method, data=None, headers=None):
    """
    Performs an http request and return response as text

    Args:
        url (str): The URL to send the request to
        method (str): The HTTP method to use
        data (dict): The data to send with the request
        headers (dict): The headers to send with the request
    """
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.request(method, url, data=data) as resp:
            return await resp.text()


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


async def http_call_every_n_seconds(url, method, data=None, headers=None, n=5):
    """
    Performs an http request every n seconds

    Args:
        url (str): The URL to send the request to
        method (str): The HTTP method to use
        data (dict): The data to send with the request
        headers (dict): The headers to send with the request
        n (int): The number of seconds to wait between requests
    """

    while True:

        res = await http_call(url, method, data=data, headers=headers)

        receipt = res.get("result")

        if receipt and int(receipt["status"], 16) != 1:

            # Javascript implementation
            #
            # Buffer.from(receipt.revertReason.slice(2), "hex")
            #       .toString()
            #       .replace(/[^a-zA-Z0-9:' ]/g, "")

            revert_reason = bytes.fromhex(receipt["revertReason"].lstrip("0x")).decode(
                "utf-8"
            )
            raise Exception(
                "Transaction failed: Status {}. Revert reason: {}".format(
                    receipt["status"], revert_reason
                )
            )

        if receipt and int(receipt["status"], 16) == 1:
            return receipt

        await asyncio.sleep(n)


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

def get_element_by_index_from_list(list: typing.List[typing.Any], index: int) -> typing.Union[typing.Any, None]:
    if list is None:
        return None
    try:
        return list[index]
    except IndexError:
        return None

def generate_random_salt() -> str:
    # Generate a random salt with 16 bytes (128 bits)
    salt = os.urandom(16)

    # Convert the salt to hexadecimal representation
    salt_hex = salt.hex()

    return salt_hex

def generate_disclosure_content_and_base64(claim_key: str, claim_value: typing.Any) -> typing.Tuple[str, str]:
    claim_salt = generate_random_salt()
    claim_disclosure = [claim_salt, claim_key, claim_value]
    claim_disclosure_base64 = base64.urlsafe_b64encode(json.dumps(claim_disclosure).encode('utf-8')).decode('utf-8').rstrip("=")
    return claim_disclosure, claim_disclosure_base64
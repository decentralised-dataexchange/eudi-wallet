import time
import base64
import json

from .util.json_canonicalize.Canonicalize import canonicalize


async def create_jws(payload, signer, header) -> str:
    """
    Creates a JWS.


    Args:

        payload: Payload to sign.
        signer: Signer algorithm.
        header: Header to include in the JWS.

    Returns:
        str: JWS.
    """

    encoded_payload = base64.urlsafe_b64encode(
        canonicalize(payload)).decode("utf-8").replace("=", "")

    encoded_header = base64.urlsafe_b64encode(
        canonicalize(header)).decode("utf-8").replace("=", "")

    signing_input = ".".join([encoded_header, encoded_payload])

    signature = await signer(signing_input)
    signature = signature.replace("=", "")

    return ".".join([signing_input, signature])


async def create_jwt(payload, options, header) -> str:
    """
    Creates a JWT.

    Args:

        payload: Payload to sign.
        options: Options to include in the JWT.
        header: Header to include in the JWT.

    Returns:
        str: JWT.
    """
    EXPIRATION_TIME = 300

    iat = int(time.time())

    timestamps = {
        "iat": iat,
        "exp": iat + EXPIRATION_TIME
    }

    full_payload = {**timestamps, **payload, "iss": options["issuer"]}

    return await create_jws(full_payload, options["signer"], header)

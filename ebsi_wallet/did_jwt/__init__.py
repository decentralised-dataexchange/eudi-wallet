import base64
import json
import math
import time

from ebsi_wallet.did_jwt.signer_algorithm import verify_ES256K
from ebsi_wallet.did_jwt.util.json_canonicalize.Canonicalize import canonicalize
from ebsi_wallet.ebsi_did_resolver import resolve
from ebsi_wallet.util import pad_base64


def decode_jws(jws):
    parts = jws.split(".")

    assert len(parts) == 3

    return {
        "header": json.loads(
            base64.urlsafe_b64decode(pad_base64(parts[0])).decode("utf-8")
        ),
        "payload": parts[1],
        "signature": parts[2],
        "data": f"{parts[0]}.{parts[1]}",
    }


def decode_jwt(jwt):
    jws = decode_jws(jwt)
    decoded_jwt = {
        "header": jws["header"],
        "payload": json.loads(
            base64.urlsafe_b64decode(pad_base64(jws["payload"])).decode("utf-8")
        ),
        "signature": jws["signature"],
        "data": jws["data"],
    }

    return decoded_jwt


async def create_jws(payload, signer, header, canon: bool = True) -> str:
    """
    Creates a JWS.


    Args:

        payload: Payload to sign.
        signer: Signer algorithm.
        header: Header to include in the JWS.

    Returns:
        str: JWS.
    """

    encoded_payload = (
        base64.urlsafe_b64encode(
            json.dumps(payload).encode("utf-8") if not canon else canonicalize(payload)
        )
        .decode("utf-8")
        .replace("=", "")
    )

    encoded_header = (
        base64.urlsafe_b64encode(
            json.dumps(header).encode("utf-8") if not canon else canonicalize(header)
        )
        .decode("utf-8")
        .replace("=", "")
    )

    signing_input = ".".join([encoded_header, encoded_payload])

    signature = await signer(signing_input)
    signature = signature.replace("=", "")

    return ".".join([signing_input, signature])


async def create_jwt(
    payload, options, header, exp: bool = True, canon: bool = True
) -> str:
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
    }

    if exp:
        timestamps["exp"] = iat + EXPIRATION_TIME

    full_payload = {**payload, **timestamps, "iss": options["issuer"]}

    return await create_jws(full_payload, options["signer"], header, canon)


async def verify_jwt(jwt, config):

    decoded_jwt = decode_jwt(jwt)

    payload = decoded_jwt["payload"]
    header = decoded_jwt["header"]
    signature = decoded_jwt["signature"]
    data = decoded_jwt["data"]

    assert payload.get("iss") is not None, "Missing issuer"

    did = None

    if payload.get("iss") == "https://self-issued.me/v2":

        assert payload.get("sub") is not None, "Missing subject"

        if payload.get("sub_jwk") is None:

            did = payload.get("sub")

        else:

            did = header.get("kid").split("#")[0]
    else:

        did = payload.get("iss")

    did_resolution_result = await resolve(did, config)

    # FIXME: Only the first verification method is used to verify the signature.
    authenticator = did_resolution_result.get("didDocument").get("verificationMethod")[
        0
    ]

    # Verify the signature.
    verify = await verify_ES256K(data, signature, authenticator)

    assert verify, "Signature verification failed"

    skew_time = 300

    now = math.floor(time.time())

    now_skewed = now + skew_time

    exp = payload.get("exp")

    assert exp is not None, "Missing expiration time"

    iat = payload.get("iat")

    assert iat is not None, "Missing issue time"

    assert (iat > now_skewed) == False, "Issue time is in the future"

    assert (exp <= now - skew_time) == False, "Expired JWT"

    audience = config.get("audience")

    if payload.get("aud"):
        if audience:
            if isinstance(audience, list):
                assert payload.get("aud") in audience, "Invalid audience"
            else:
                assert payload.get("aud") == audience, "Invalid audience"

    return payload, did_resolution_result, did, authenticator, jwt

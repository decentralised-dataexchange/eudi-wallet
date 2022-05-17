from ..ethereum import Ethereum
from ..did_jwt import create_jwt, decode_jwt
from ..did_jwt.signer_algorithm import ES256K_signer_algorithm

def get_audience(jwt):
    decoded_jwt = decode_jwt(jwt)

    payload = decoded_jwt.get("payload")

    assert payload is not None, "No payload found"

    audience = payload.get("aud")

    return audience


async def get_jwk(kid: str, eth_client: Ethereum) -> dict:
    """
    Returns the JWK for the given kid.
    """

    return {
        **eth_client.public_key_to_jwk(),
        "kid": kid
    }


async def sign_did_auth_internal(did, payload, private_key):
    """
    Signs the payload with the given private key.
    """

    header = {
        "alg": "ES256K",
        "typ": "JWT",
        "kid": f"{did}#key-1",
    }

    SELF_ISSUED_V2 = "https://self-issued.me/v2"

    response = await create_jwt({**payload}, {
        "issuer": SELF_ISSUED_V2,
        "signer": await ES256K_signer_algorithm(private_key),
    }, header)

    return response

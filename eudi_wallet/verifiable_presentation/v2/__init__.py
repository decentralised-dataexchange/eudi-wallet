import time

from eudi_wallet.did_jwt import create_jwt
from eudi_wallet.did_jwt.signer_algorithm import ES256K_signer_algorithm
from eudi_wallet.ebsi_client import EbsiClient


async def create_verifiable_presentation_jwt(payload, holder, audience, options={}):

    client: EbsiClient = options.get("client")

    iat = int(time.time())
    exp = iat + 900
    nbf = iat - 7

    vp_jwt_payload = {
        "jti": payload["id"] if isinstance(payload["id"], str) else "",
        "sub": holder["did"],
        "iss": holder["did"],
        "nbf": nbf,
        "exp": exp,
        "iat": iat,
        "aud": audience,
        "vp": payload,
    }

    vp_jwt_header = {
        "alg": "ES256K",
        "typ": "JWT",
        "kid": f"{client.ebsi_did.did}#{client.eth.jwk_thumbprint}",
    }

    if client.did_version == "v2":

        public_key_jwk = {
            "kty": holder["publicKeyJwk"].get("kty"),
            "crv": holder["publicKeyJwk"].get("crv"),
            "x": holder["publicKeyJwk"].get("x"),
            "y": holder["publicKeyJwk"].get("y"),
        }

        vp_jwt_header["jwk"] = public_key_jwk

    private_key = client.eth.private_key

    jws = await create_jwt(
        vp_jwt_payload,
        {
            "issuer": client.ebsi_did.did,
            "signer": await ES256K_signer_algorithm(private_key),
        },
        vp_jwt_header,
        exp=False,
        canon=False,
    )

    return jws

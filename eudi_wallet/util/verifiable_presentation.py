import base64
import json
import uuid

from eudi_wallet.did_jwt import create_jwt
from eudi_wallet.ebsi_client import EbsiClient
from eudi_wallet.util import pad_base64
from eudi_wallet.verifiable_presentation import create_verifiable_presentation
from eudi_wallet.verifiable_presentation.v2 import create_verifiable_presentation_jwt


def extract_iat_from_jwt(jwt):
    token = jwt.split(".")
    payload = base64.b64decode(pad_base64(token[1]))
    payload = json.loads(payload)
    return payload["iat"]


async def create_vp(client, alg, vc, config):

    options = {
        "resolver": "https://api.conformance.intebsi.xyz/did-registry/v2/identifiers",
        "tirUrl": "https://api.conformance.intebsi.xyz/trusted-issuers-registry/v2/issuers",
    }

    required_proof = {
        "type": "EcdsaSecp256k1Signature2019",
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"{config['issuer']}#keys-1",
    }

    presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "verifiableCredential": [vc],
        "holder": config["issuer"],
    }

    vp_jwt = await create_jwt(
        presentation,
        {"issuer": config["issuer"], "signer": config["signer"]},
        {
            "alg": alg,
            "typ": "JWT",
            "kid": f"{options['resolver']}/{config['issuer']}#keys-1",
        },
    )
    vp_jwt_parts = vp_jwt.split(".")

    signature = {
        "proofValue": f"{vp_jwt_parts[0]}..{vp_jwt_parts[2]}",
        "proofValueName": "jws",
        "iat": extract_iat_from_jwt(vp_jwt),
    }

    return await create_verifiable_presentation(presentation, required_proof, signature)


async def create_vp_jwt(vc, config, audience=None):

    client: EbsiClient = config.get("client")
    audience = audience

    if client.did_version == "v1":

        payload = {"nonce": str(uuid.uuid4()), "vc": vc}

        options = {
            "resolver": "https://api.conformance.intebsi.xyz/did-registry/v2/identifiers",
            "tirUrl": "https://api.conformance.intebsi.xyz/trusted-issuers-registry/v2/issuers",
        }

        vp_jwt = await create_jwt(
            payload,
            {
                "alg": "ES256K",
                "issuer": config["issuer"],
                "signer": config["signer"],
                "canonicalize": True,
            },
            {
                "alg": "ES256K",
                "typ": "JWT",
                "kid": f"{options['resolver']}/{config['issuer']}#keys-1",
            },
        )

        return {"jwtVp": vp_jwt, "payload": payload}

    else:

        issuer = {
            "did": client.ebsi_did.did,
            "kid": client.eth.jwk_thumbprint,
            "privateKeyJwk": client.eth.private_key_to_jwk(),
            "publicKeyJwk": client.eth.public_key_to_jwk(),
            "alg": "ES256K",
        }

        payload = {
            "id": f"urn:did:{str(uuid.uuid4())}",
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": client.ebsi_did.did,
            "verifiableCredential": [vc],
        }

        vp_jwt = await create_verifiable_presentation_jwt(
            payload, issuer, audience, {"client": client}
        )

        return {"jwtVp": vp_jwt, "payload": payload}

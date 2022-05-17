import base64
import json
from ..did_jwt import create_jwt
from ..verifiable_presentation import create_verifiable_presentation
from ..util import pad_base64

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
        "verificationMethod": f"{config['issuer']}#keys-1"
    }

    presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "verifiableCredential": [vc],
        "holder": config['issuer'],
    }

    vp_jwt = await create_jwt(
        presentation,
        {
            "issuer": config['issuer'],
            "signer": config["signer"]
        },
        {
            "alg": alg,
            "typ": "JWT",
            "kid": f"{options['resolver']}/{config['issuer']}#keys-1"
        }
    )
    vp_jwt_parts = vp_jwt.split(".")

    signature = {
        "proofValue": f"{vp_jwt_parts[0]}..{vp_jwt_parts[2]}",
        "proofValueName": "jws",
        "iat": extract_iat_from_jwt(vp_jwt),
    }

    return await create_verifiable_presentation(
        presentation,
        required_proof,
        signature
    )

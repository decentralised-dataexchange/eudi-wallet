import base64
import json
from dataclasses import dataclass


@dataclass
class JwtDecodedHeaderAndClaims:
    headers: dict
    claims: dict


def decode_header_and_claims_in_jwt(token: str) -> JwtDecodedHeaderAndClaims:
    headers_encoded, claims_encoded, _ = token.split(".")
    claims_decoded = base64.b64decode(claims_encoded + "=" * (-len(claims_encoded) % 4))
    headers_decoded = base64.b64decode(
        headers_encoded + "=" * (-len(headers_encoded) % 4)
    )
    return JwtDecodedHeaderAndClaims(
        headers=json.loads(headers_decoded), claims=json.loads(claims_decoded)
    )

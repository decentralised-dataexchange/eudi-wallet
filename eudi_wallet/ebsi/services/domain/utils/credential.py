import base64
import gzip
import json
import time
import typing
from dataclasses import dataclass

from bitarray import bitarray
from jwcrypto import jwk, jwt

from eudi_wallet.ebsi.exceptions.domain.issuer import CredentialDeserializationError
from eudi_wallet.ebsi.services.domain.utils.jwt import get_alg_for_key
from eudi_wallet.ebsi.value_objects.domain.issuer import (
    CredentialTypes,
    VerifiableAccreditationToAttest,
    VerifiableAuthorisationToOnboard,
)


def deserialize_credential_jwt(
    credential_jwt: str,
) -> typing.Union[VerifiableAuthorisationToOnboard, VerifiableAccreditationToAttest]:
    claims_encoded = credential_jwt.split(".")[1]
    claims_decoded = base64.b64decode(claims_encoded + "=" * (-len(claims_encoded) % 4))
    claims_dict = json.loads(claims_decoded)
    credential = claims_dict["vc"]
    credential_type = claims_dict["vc"]["type"][-1]

    if credential_type == CredentialTypes.VerifiableAuthorisationToOnboard.value:
        return VerifiableAuthorisationToOnboard.from_dict(credential)
    elif credential_type == CredentialTypes.VerifiableAccreditationToAttest.value:
        return VerifiableAccreditationToAttest.from_dict(credential)
    else:
        raise CredentialDeserializationError(
            f"Unknown credential type {credential_type}"
        )


def create_credential_token(
    vc: dict,
    jti: str,
    sub: str,
    iss: str,
    kid: str,
    key: jwk.JWK,
    iat: int = None,
    exp: int = None,
) -> str:
    header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": kid}

    iat = iat or int(time.time())
    nbf = iat
    exp = exp or iat + 86400
    jwt_payload = {
        "iat": iat,
        "jti": jti,
        "nbf": nbf,
        "exp": exp,
        "sub": sub,
        "iss": iss,
        "vc": vc,
    }
    token = jwt.JWT(header=header, claims=jwt_payload)
    token.make_signed_token(key)

    return token.serialize()


@dataclass
class CredentialStatus:
    status_list_index: int
    is_revoked: bool


def decode_bitstring(encoded_bitstring):
    # Calculate the number of padding characters that were removed
    padding = "=" * ((4 - len(encoded_bitstring) % 4) % 4)
    # Add the padding back to the encoded bitstring
    encoded_bitstring_with_padding = encoded_bitstring + padding

    # Base64-decode the compressed bitstring
    compressed = base64.b64decode(encoded_bitstring_with_padding)

    # Use gzip to decompress the bitstring
    bitstring_bytes = gzip.decompress(compressed)

    # Convert the bytes to a bitarray
    bitstring = bitarray()
    bitstring.frombytes(bitstring_bytes)

    return bitstring


def initialise_bitstring() -> bitarray:
    # Initialize a bitarray with 16KB of 0 bits
    bitstring = bitarray(16 * 1024 * 8)
    bitstring.setall(0)
    return bitstring


def revoke_credentials_create_encoded_bitstring(
    bitstring: bitarray, credential_statuses: typing.List[CredentialStatus]
) -> str:
    # Loop through issuedCredentials
    for credential_status in credential_statuses:
        # If the credential is revoked, set the bit at statusListIndex to 1
        bitstring[credential_status.status_list_index] = (
            1 if credential_status.is_revoked else 0
        )

    # Use gzip to compress the bitstring
    compressed = gzip.compress(bitstring.tobytes())

    # Base64-encode the compressed bitstring
    encoded_bitstring = base64.b64encode(compressed).rstrip(b"=").decode("utf-8")

    return encoded_bitstring


def generate_w3c_vc_statuslist_encoded_bitstring(
    credential_statuses: typing.List[CredentialStatus],
):
    # Initialize a bitarray with 16KB of 0 bits
    bitstring = initialise_bitstring()

    encoded_bitstring = revoke_credentials_create_encoded_bitstring(
        bitstring, credential_statuses
    )

    return encoded_bitstring


def update_w3c_vc_statuslist_encoded_bitstring(
    encoded_bitstring: str,
    credential_statuses: typing.List[CredentialStatus],
):
    # Decode the existing bitstring
    bitstring = decode_bitstring(encoded_bitstring)

    encoded_bitstring = revoke_credentials_create_encoded_bitstring(
        bitstring, credential_statuses
    )

    return encoded_bitstring

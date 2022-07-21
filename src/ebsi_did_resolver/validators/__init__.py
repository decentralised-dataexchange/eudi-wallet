import base58
from ..constants import NATURAL_PERSON, LEGAL_ENTITY, EBSI_DID_SPECS, SUPPORTED_VERSIONS
from multibase import decode


async def validate(did: str):
    assert did
    assert isinstance(did, str)
    assert did.startswith(
        "did:ebsi:"), "The DID must be a string starting with 'did:ebsi:'"

    method_specific_identifier = did.split("did:ebsi:")[1]

    assert method_specific_identifier.startswith(
        "z"), "The method-specific identifier must start with 'z' (multibase base58btc-encoded)"

    decoded_identifier = decode(method_specific_identifier)

    version = decoded_identifier[0]

    def filter_func(spec_key):
        return version == EBSI_DID_SPECS.get(spec_key).get("VERSION_ID")

    did_specs_key = list(filter(filter_func, SUPPORTED_VERSIONS))

    assert did_specs_key

    current_length = len(decoded_identifier) - 1
    expected_length = EBSI_DID_SPECS[did_specs_key[0]]["BYTE_LENGTH"]

    if (current_length != expected_length):
        raise Exception(
            f"The subject identifier length ({current_length} bytes) does not match the expected length ({expected_length}) ")

    return version

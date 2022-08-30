from ..util import http_call
from ..ebsi_did_resolver.validators import validate as validate_did
from jsonschema import validate
from jsonschema.exceptions import ValidationError, SchemaError


async def validate_schema(value, schema_url):
    """
    Fetch the JSON schema from remote and validate the given value against it

    Args:
        value: dict
        schema_url: str
    """

    # Fetch schema from remote
    schema = await http_call(schema_url, "GET")

    # Perform validation
    try:
        validate(value, schema)
    except (ValidationError, SchemaError) as e:
        raise Exception(f"JSONLD schema validation failed : {e.message}")


async def validate_context(context):
    """
    Validate the value of context

    Args:
        context: list
    """

    # validate if context is an array
    assert isinstance(context, list), "'@context' must be an array of strings"

    # validate if first element of the array is 'https://www.w3.org/2018/credentials/v1'
    if context[0] != "https://www.w3.org/2018/credentials/v1":
        raise Exception(
            "The first URI in '@context' must be 'https://www.w3.org/2018/credentials/v1'")


async def validate_type(typ: list):
    """
    Validate type

    Args:
        typ: list
    """
    # validate if typ is an array
    assert isinstance(typ, list), "'type' must be an array of strings"

    # validate if first element of the array is 'VerifiablePresentation'
    if typ[0] != "VerifiablePresentation":
        raise Exception(
            "The first type must be 'VerifiablePresentation'")


async def validate_holder(payload, holder, kid, resolver=None, skip_validation=True, proof_purpose="authentication", config={}):

    version = validate_did(holder)

    payload_holder = payload['holder']
    assert payload_holder == holder, f"payload.holder '{payload_holder}' and holder '{holder}' does not match"

    assert isinstance(kid, str), "kid is required"

    assert '#' in kid, "kid doesn't contain #"

    assert kid.split("#")[0] == holder, "did and kid doesn't match"

    if not skip_validation:
        # TODO: Verify that holder is registered in DID registry.
        pass

    return version

async def validate_timestamp(val):
    assert isinstance(val, int)
    assert val <= 100000000000, "val is not a unix timestamp in seconds"


async def validate_credential_jwt(vc_jwt, holder, options={}):
    assert isinstance(vc_jwt, str)
    

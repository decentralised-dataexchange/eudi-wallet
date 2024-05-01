import json
import uuid
from typing import Optional
from pydantic import BaseModel, constr
from eudi_wallet.did_key import KeyDid, PublicKeyJWK
from eudi_wallet.siop_auth.util import (
    accept_and_fetch_credential_offer,
    fetch_openid_credential_issuer_configuration,
    fetch_openid_auth_server_configuration,
    perform_authorization,
    AuthorizationRequestQueryParams,
    get_authorization_response_query_params,
    generate_code_challenge,
    generate_code_verifier,
    send_id_token_response,
    exchange_auth_code_for_access_token,
    send_credential_request,
    send_deferred_credential_request,
    parse_query_string_parameters_from_url,
)
from rich.console import Console
from time import sleep

console = Console()


class CredentialResponse(BaseModel):
    acceptance_token: Optional[str] = None  # type: ignore
    credential: Optional[str] = None  # type: ignore
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[str] = None


async def process_credential_offer_and_receive_credential(offer_uri: str):
    # generate crypto seed
    crypto_seed = b"ebsitests"

    key_did = KeyDid(seed=crypto_seed)

    # generate keypair
    key_did.create_keypair()

    # create public key jwk
    public_key_jwk = PublicKeyJWK(
        kty=key_did.public_key_jwk["kty"],
        crv=key_did.public_key_jwk["crv"],
        x=key_did.public_key_jwk["x"],
        y=key_did.public_key_jwk["y"],
    )

    # generate did
    key_did.generate_did(public_key_jwk)

    print("Decentralised identifier: ", key_did._did)

    # Step 1: Fetch credential offer from the issuer
    credential_offer_uri = parse_query_string_parameters_from_url(offer_uri).get(
        "credential_offer_uri"
    )[0]
    console.log("Credential offer URI: ", credential_offer_uri)

    credential_offer = await accept_and_fetch_credential_offer(credential_offer_uri)
    console.log("Credential offer: ", credential_offer)

    credential_issuer_configuration = (
        await fetch_openid_credential_issuer_configuration(
            credential_offer.credential_issuer
        )
    )
    console.log("Credential issuer configuration: ", credential_issuer_configuration)

    auth_server_configuration = await fetch_openid_auth_server_configuration(
        credential_issuer_configuration.authorization_server
    )
    console.log("Authorization server configuration: ", auth_server_configuration)

    # Step 2: Perform authorisation request and obtain ID token request

    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    code_verifier = generate_code_verifier()

    authorization_details = [
        {
            "type": "openid_credential",
            "format": "jwt_vc",
            "types": credential_offer.credentials[0].get("types"),
            "locations": ["https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"],
        }
    ]
    redirect_uri = "http://localhost:8080"
    client_metadata = {
        "vp_formats_supported": {
            "jwt_vp": {"alg": ["ES256"]},
            "jwt_vc": {"alg": ["ES256"]},
        },
        "response_types_supported": ["vp_token", "id_token"],
        "authorization_endpoint": redirect_uri,
    }
    authorization_request_query_params = AuthorizationRequestQueryParams(
        response_type="code",
        scope="openid",
        state=state,
        client_id=key_did._did,
        authorization_details=json.dumps(authorization_details, separators=(",", ":")),
        redirect_uri=redirect_uri,
        nonce=nonce,
        code_challenge=generate_code_challenge(code_verifier),
        code_challenge_method="S256",
        client_metadata=json.dumps(client_metadata, separators=(",", ":")),
        issuer_state=credential_offer.grants.get("authorization_code").get(
            "issuer_state"
        ),
    )

    auth_resp = await perform_authorization(
        auth_server_configuration.authorization_endpoint,
        authorization_request_query_params,
    )
    auth_resp_uri = str(auth_resp).split("Location': '")[1].split("'")[0]

    auth_resp_query_params = get_authorization_response_query_params(auth_resp_uri)
    console.log("Authorization response query params: ", auth_resp_query_params)

    # Step 3: ID token

    id_token = key_did.generate_id_token(
        auth_server_uri=auth_resp_query_params.client_id,
        nonce=auth_resp_query_params.nonce,
    )
    auth_code_response = await send_id_token_response(
        auth_resp_query_params.redirect_uri, id_token, auth_resp_query_params.state
    )
    auth_code_response = str(auth_code_response).split("Location': '")[1].split("'")[0]
    state = parse_query_string_parameters_from_url(auth_code_response).get("state")[0]
    auth_code = parse_query_string_parameters_from_url(auth_code_response).get("code")[
        0
    ]
    console.log("Authorization code: ", auth_code)

    # Step 4: Exchange code for access token

    token_uri = auth_resp_query_params.client_id + "/service/token"
    access_token_response = await exchange_auth_code_for_access_token(
        token_uri, key_did._did, auth_code, code_verifier
    )
    console.log("Access token response: ", access_token_response)

    # Step 5: Request credential

    credential_request_jwt = key_did.generate_credential_request(
        credential_issuer_configuration.credential_issuer, access_token_response.c_nonce
    )
    console.log("Credential request JWT: ", credential_request_jwt)
    credential_response = await send_credential_request(
        credential_issuer_configuration.credential_endpoint,
        access_token_response.access_token,
        credential_request_jwt,
        credential_offer.credentials[0].get("types"),
    )
    console.log("Credential response: ", credential_response)

    return CredentialResponse(
        **credential_response
    ), credential_issuer_configuration.deferred_credential_endpoint


async def fetch_deferred_credential(deferred_endpoint: str, acceptance_token: str):
    # Step 6: Request credential by deferenced

    console.log("Waiting for 15 seconds...")
    sleep(15)
    console.log("Sending deferred credential request...")
    credential_response = await send_deferred_credential_request(
        deferred_endpoint,
        acceptance_token,
    )
    return CredentialResponse(**credential_response)


async def process_credential_offer_and_obtain_deferred_credential(offer_uri: str):
    (
        credential_response,
        deferred_endpoint,
    ) = await process_credential_offer_and_receive_credential(offer_uri)
    res = await fetch_deferred_credential(
        deferred_endpoint, credential_response.acceptance_token
    )
    print(res)

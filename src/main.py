import uuid
import asyncio
import base64
import json

from rich.console import Console
from .siop_auth import Agent
from .ebsi_client import EbsiClient
from .util import (
    parse_query_string_parameters_from_url,
    http_call,
    verifiable_presentation
)
from .did_jwt.signer_algorithm import ES256K_signer_algorithm
from .did_jwt.util.json_canonicalize.Canonicalize import canonicalize

console = Console()

app_config = {
    "conformance": {
        "onboarding": {
            "api": "https://api.conformance.intebsi.xyz",
            "endpoints": {
                "post": {
                    "authentication-requests": "/users-onboarding/v1/authentication-requests",
                    "sessions": "/users-onboarding/v1/sessions",
                    "authentication-responses": "/users-onboarding/v1/authentication-responses"
                }
            }
        },
        "authorisation": {
            "api": "https://api.conformance.intebsi.xyz",
            "endpoints": {
                "post": {
                    "siop-authentication-requests": "/authorisation/v1/authentication-requests"
                }
            }
        },
        "did": {
            "api": "https://api.conformance.intebsi.xyz",
            "endpoints": {
                "post": {
                    "identifiers": "/did-registry/v2/identifiers"
                }
            }
        }
    }
}


async def authorisation(method, headers, options):

    async def siop_request():
        payload = {
            "scope": "openid did_authn"
        }

        authReq = await http_call(app_config["conformance"]["authorisation"]["api"] + app_config["conformance"]["authorisation"]["endpoints"]["post"]["siop-authentication-requests"], "POST", data=payload, headers=headers)

        return authReq

    async def siop_session():

        callback_url = options.get("callback_url")
        alg = "ES256K"
        verified_claims = options.get("verified_claims")
        client: EbsiClient = options.get("client")

        nonce = str(uuid.uuid4())
        redirect_uri = callback_url

        public_key_jwk = client.eth.public_key_to_jwk()

        public_key_jwk = {
            "kty": public_key_jwk.get("kty"),
            "crv": public_key_jwk.get("crv"),
            "x": public_key_jwk.get("x"),
            "y": public_key_jwk.get("y")
        }

        siop_agent = Agent(private_key=client.eth.private_key, did_registry="")

        did_auth_response_jwt = await siop_agent.create_authentication_response(
            client.ebsi_did.did,
            nonce,
            redirect_uri,
            client.eth,
            {
                "encryption_key": public_key_jwk,
                "verified_claims": verified_claims
            }
        )

        updated_headers = {
            **headers,
        }

        data = did_auth_response_jwt["bodyEncoded"]

        authResponses = await http_call(callback_url, "POST", data=f"id_token={data}", headers=updated_headers)

        return {
            "alg": "ES256K",
            "nonce": nonce,
            "response": authResponses
        }

    switcher = {
        "siopRequest": siop_request,
        "siopSession": siop_session
    }

    method_fn = switcher.get(method)

    assert method_fn is not None, "Method not found"

    return await method_fn()


async def compute(method, headers, options):

    async def create_presentation():

        vc = options.get("vc")

        assert vc is not None, "No VC found"

        vc = json.loads(vc)

        client: EbsiClient = options.get("client")

        assert client is not None, "No client found"

        vp = await verifiable_presentation.create_vp(
            client,
            "ES256K",
            vc,
            {
                "issuer": client.ebsi_did.did,
                "signer": await ES256K_signer_algorithm(client.eth.private_key)
            }
        )

        return vp

    async def canonicalize_base64_url():

        vp = options.get("vp")

        assert vp is not None, "No VP found"

        vp = json.loads(vp)

        encoded = base64.urlsafe_b64encode(canonicalize(vp))

        return encoded.decode("utf-8")

    async def verify_authentication_request():

        request = options.get("request")
        client: EbsiClient = options["client"]

        siop_agent = Agent(private_key=client.eth.private_key,
                           did_registry=app_config["conformance"]["did"]["api"] + app_config["conformance"]["did"]["endpoints"]["post"]["identifiers"])

        await siop_agent.verify_authentication_request(request.get("request"))

        return request["client_id"]

    switcher = {
        "createPresentation": create_presentation,
        "canonicalizeBase64url": canonicalize_base64_url,
        "verifyAuthenticationRequest": verify_authentication_request
    }

    method_fn = switcher.get(method)

    assert method_fn is not None, "Method not found"

    return await method_fn()


async def wallet(method):

    async def init():

        client = EbsiClient()
        client.ebsi_did.generate_did()

        return client

    switcher = {
        "init": init
    }

    method_fn = switcher.get(method)

    assert method_fn is not None, "Method not found"

    return await method_fn()


async def onboarding(method, headers, options=None):

    async def authentication_requests():
        payload = {
            "scope": "ebsi users onboarding"
        }

        authReq = await http_call(app_config["conformance"]["onboarding"]["api"] + app_config["conformance"]["onboarding"]["endpoints"]["post"]["authentication-requests"], "POST", data=payload, headers=headers)

        return authReq

    async def authentication_responses():

        client = options["client"]

        nonce = str(uuid.uuid4())
        redirect_uri = app_config["conformance"]["onboarding"]["api"] + \
            app_config["conformance"]["onboarding"]["endpoints"]["post"]["authentication-responses"]

        siop_agent = Agent(private_key=client.eth.private_key, did_registry="")

        did_auth_response_jwt = await siop_agent.create_authentication_response(
            client.ebsi_did.did,
            nonce,
            redirect_uri,
            client.eth
        )

        updated_headers = {
            **headers,
        }

        data = did_auth_response_jwt["bodyEncoded"]
        url = did_auth_response_jwt["urlEncoded"]

        authResponses = await http_call(url, "POST", data=f"id_token={data}", headers=updated_headers)

        return authResponses

    switcher = {
        "authenticationRequests": authentication_requests,
        "authenticationResponses": authentication_responses
    }

    method_fn = switcher.get(method)

    assert method_fn is not None, "Method not found"

    return await method_fn()


async def main():

    # Visit https://app.preprod.ebsi.eu/users-onboarding to obtain session token.

    headers = {
        "Conformance": str(uuid.uuid4()),
        "Authorization": "Bearer eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NTIxMDk3NzcsImlhdCI6MTY1MjEwODg3NywiaXNzIjoiZGlkOmVic2k6emNHdnFnWlRIQ3Rramd0Y0tSTDdIOGsiLCJvbmJvYXJkaW5nIjoicmVjYXB0Y2hhIiwidmFsaWRhdGVkSW5mbyI6eyJhY3Rpb24iOiJsb2dpbiIsImNoYWxsZW5nZV90cyI6IjIwMjItMDUtMDlUMTU6MDc6NTVaIiwiaG9zdG5hbWUiOiJhcHAucHJlcHJvZC5lYnNpLmV1Iiwic2NvcmUiOjAuOSwic3VjY2VzcyI6dHJ1ZX19.wWPb9xofcgeD3G9J3hShqHOMX-Quvr2kgqw_GXk9ABbYe-YngKojO76ZxkGDBuykkbIP261Gqv5KQLSnSsyRLA"
    }

    # Setup wallet
    client = await wallet("init")

    # Onboarding service

    # Authentication requests
    auth_req = await onboarding("authenticationRequests", headers)
    console.log("Onboarding Service -- Authentication Requests", auth_req)

    session_token = auth_req["session_token"].replace("openid://", "")
    jwt_auth_req = parse_query_string_parameters_from_url(
        session_token).get("request")[0]
    assert jwt_auth_req is not None, "No JWT authentication request found"

    headers = {
        "Authorization": f"Bearer {jwt_auth_req}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Authentication responses
    vc = await onboarding("authenticationResponses", headers, options={"client": client, "jwt_auth_req": jwt_auth_req})
    console.log("Onboarding Service -- Authentication Responses", vc)

    # Get access token
    vp = await compute("createPresentation", None, options={"client": client, "vc": json.dumps(vc["verifiableCredential"])})
    console.log("Onboarding Service -- Create Presentation", vp)

    vp_base64 = await compute("canonicalizeBase64url", None, options={"vp": json.dumps(vp)})
    console.log("Onboarding Service -- Canonicalize Base64 URL", vp_base64)

    headers = {
        "Authorization": f"Bearer {jwt_auth_req}",
    }

    siop_auth_request = await authorisation("siopRequest", headers, None)
    console.log("Onboarding Service -- Siop Request", siop_auth_request)

    uri_decoded = siop_auth_request["uri"].replace("openid://", "")
    siop_auth_request_prepared = {
        "request": parse_query_string_parameters_from_url(uri_decoded).get("request")[0],
        "client_id": parse_query_string_parameters_from_url(uri_decoded).get("client_id")[0]
    }

    callback_url = await compute("verifyAuthenticationRequest", None, {"client": client, "request": siop_auth_request_prepared})
    console.log(
        "Onboarding Service -- Verify Authentication Request", callback_url)

    headers = {
        "Authorization": f"Bearer {jwt_auth_req}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    session_response = await authorisation("siopSession", headers, options={"client": client, "callback_url": callback_url, "verified_claims": vp_base64})
    console.log("Onboarding Service -- Siop Session", session_response)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

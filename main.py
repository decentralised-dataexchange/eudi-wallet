import uuid
import asyncio

from aiohttp import FormData
from rich.console import Console
from siop_auth import Agent
from ebsi_client import EbsiClient
from util import (
    parse_query_string_parameters_from_url,
    http_call
)

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
        }
    }
}


async def wallet(method):

    async def init():
        pass

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
        jwt_auth_req = options["jwt_auth_req"]

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

        updated_headers = {**headers, "Authorization": f"Bearer {jwt_auth_req}",
                           "Content-Type": "application/x-www-form-urlencoded"}

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

    # Onboarding service

    # Authentication requests
    auth_req = await onboarding("authenticationRequests", headers)
    console.log("Onboarding Service -- Authentication Requests", auth_req)

    session_token = auth_req["session_token"].replace("openid://", "")
    jwt_auth_req = parse_query_string_parameters_from_url(
        session_token).get("request")[0]
    assert jwt_auth_req is not None, "No JWT authentication request found"

    # Authentication responses
    client = EbsiClient()
    client.ebsi_did.generate_did()

    authResponses = await onboarding("authenticationResponses", headers, options={"client": client, "jwt_auth_req": jwt_auth_req})
    console.log("Onboarding Service -- Authentication Responses", authResponses)


asyncio.run(main())

import asyncio
import click
import dataclasses
import typing
import logging
import uuid
import json
import time
from aiohttp import web
from pyngrok import ngrok
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eudi_wallet import ethereum
from eudi_wallet import ebsi_did as ebsi_did_module
from eudi_wallet import did_key
from eudi_wallet.ebsi import ledger
from eudi_wallet.ebsi import did_registry
from eudi_wallet.ebsi.auth import authorization
from eudi_wallet.ebsi import discovery

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ISSUER_MOCK_URI = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
ISSUER_SUBDOMAIN = "ebsi-issuer"
ISSUER_DOMAIN = f"https://{ISSUER_SUBDOMAIN}.ngrok.io"


async def generate_and_store_did(app):
    # Generate EBSI DID for legal entity
    eth = ethereum.Ethereum()
    ebsi_did = ebsi_did_module.EbsiDid()
    ebsi_did.generate_did(eth=eth)

    # Generate EBSI DID for natural person
    crypto_seed = b"ebsitests"
    key_did = did_key.KeyDid(seed=crypto_seed)
    key_did.create_keypair()
    public_key_jwk = did_key.PublicKeyJWK(
        kty=key_did.public_key_jwk["kty"],
        crv=key_did.public_key_jwk["crv"],
        x=key_did.public_key_jwk["x"],
        y=key_did.public_key_jwk["y"],
    )
    key_did.generate_did(public_key_jwk)

    logger.info(f"DID generated for legal entity: {ebsi_did.did}")

    # Store objects in app
    app["eth"] = eth
    app["ebsi_did"] = ebsi_did
    app["key_did"] = key_did


async def discover_credential_issuer_and_authn_server(app):
    credential_issuer_configuration = await discovery.fetch_credential_issuer_config(
        ISSUER_MOCK_URI
    )
    auth_server_configuration = await discovery.fetch_authorization_server_config(
        credential_issuer_configuration.authorization_server
    )

    # Store objects in app
    app["credential_issuer_configuration"] = credential_issuer_configuration
    app["auth_server_configuration"] = auth_server_configuration


@dataclasses.dataclass
class AppObjects:
    key_did: did_key.KeyDid
    ebsi_did: ebsi_did_module.EbsiDid
    eth: ethereum.Ethereum
    credential_issuer_configuration: discovery.OpenIDCredentialIssuerConfig
    auth_server_configuration: discovery.OpenIDAuthServerConfig


def get_app_objects(app) -> AppObjects:
    return AppObjects(
        key_did=app["key_did"],
        ebsi_did=app["ebsi_did"],
        eth=app["eth"],
        credential_issuer_configuration=app["credential_issuer_configuration"],
        auth_server_configuration=app["auth_server_configuration"],
    )


def get_endpoint_url_by_name(app, endpoint_name):
    named_resources = app.router.named_resources()
    if endpoint_name in named_resources:
        resource = named_resources[endpoint_name]
        endpoint_url = resource.get_info().get("path")
        return endpoint_url
    else:
        return None


async def handle_index(request):
    """
    Handles requests to the / endpoint.

    Returns:
        web.Response: A response with the text "Issuer server is running."
    """

    app_objects = get_app_objects(request.app)

    resp = {
        "legal_entity_did": app_objects.ebsi_did.did,
        "natural_person_did": app_objects.key_did.did,
        "credential_issuer_configuration": dataclasses.asdict(
            app_objects.credential_issuer_configuration
        ),
        "auth_server_configuration": dataclasses.asdict(
            app_objects.auth_server_configuration
        ),
    }

    return web.json_response(resp)


@dataclasses.dataclass
class JWKSResponse:
    keys: typing.List[dict]


async def handle_jwks(request):
    app = request.app
    app_objects = get_app_objects(app)
    key_did = app_objects.key_did
    eth = app_objects.eth

    resp = JWKSResponse(keys=[key_did.public_key_jwk, eth.public_key_to_jwk()])
    return web.json_response(dataclasses.asdict(resp))


async def handle_authorization_request(request):
    app = request.app
    app_objects = get_app_objects(app)
    key_did = app_objects.key_did
    ebsi_did = app_objects.ebsi_did
    credential_issuer_configuration = app_objects.credential_issuer_configuration
    auth_server_configuration = app_objects.auth_server_configuration

    credential_types = [
        authorization.CredentialTypes.VerifiableCredential.value,
        authorization.CredentialTypes.VerifiableAttestation.value,
        authorization.CredentialTypes.VerifiableAuthorisationToOnboard.value,
    ]

    req = authorization.CreateAuthorizationRequest(
        kid=key_did.public_key_jwk.get("kid"),
        issuer_uri=ISSUER_DOMAIN,
        authorize_uri=credential_issuer_configuration.authorization_server,
        redirect_uri=ISSUER_DOMAIN
        + get_endpoint_url_by_name(app, "handle_authorization_redirect"),
        jwks_uri=ISSUER_DOMAIN + get_endpoint_url_by_name(app, "handle_jwks"),
        authorization_details=[
            authorization.AuthorizationDetail(
                locations=[credential_issuer_configuration.credential_issuer],
                types=credential_types,
            )
        ],
    )
    auth_req_token = authorization.create_authorization_request(req, key_did._key)

    send_auth_req = authorization.SendAuthorizationRequest(
        authorize_uri=auth_server_configuration.authorization_endpoint,
        client_id=ISSUER_DOMAIN,
        redirect_uri=ISSUER_DOMAIN
        + get_endpoint_url_by_name(app, "handle_authorization_redirect"),
        request=auth_req_token.token,
        nonce=req.nonce,
    )
    id_token_request = await authorization.send_authorization_request(send_auth_req)
    id_token_request_jwt = await authorization.get_id_token_request_jwt(
        id_token_request.request_uri
    )

    id_token_response_jwt = authorization.create_id_token_response(
        authorization.CreateIDTokenResponse(
            kid=f"{ebsi_did.did}#{key_did.public_key_jwk.get('kid')}",
            iss=ebsi_did.did,
            sub=ebsi_did.did,
            aud=credential_issuer_configuration.authorization_server,
            nonce=id_token_request_jwt.nonce,
            state=id_token_request_jwt.state,
        ),
        key_did._key,
    )
    send_id_token_response_payload = authorization.SendIDTokenResponse(
        direct_post_uri=id_token_request.redirect_uri,
        id_token=id_token_response_jwt.token,
        state=id_token_request_jwt.state,
    )
    auth_code_redirect_uri_response = await authorization.send_id_token_response(
        send_id_token_response_payload
    )

    return web.HTTPFound(auth_code_redirect_uri_response.redirect_uri)


async def handle_authorization_redirect(request):
    app = request.app
    app_objects = get_app_objects(app)
    key_did = app_objects.key_did
    ebsi_did = app_objects.ebsi_did
    eth = app_objects.eth
    credential_issuer_configuration = app_objects.credential_issuer_configuration
    auth_server_configuration = app_objects.auth_server_configuration

    # Access query parameters from the request URL
    query_params = request.query

    # Get the value of 'code' query parameter
    code = query_params.get("code")

    client_assertion_jwt = authorization.create_client_assertion(
        authorization.CreateClientAssertion(
            kid=key_did.public_key_jwk.get("kid"),
            iss=ISSUER_DOMAIN,
            sub=ISSUER_DOMAIN,
            aud=credential_issuer_configuration.authorization_server,
            jti=str(uuid.uuid4()),
        ),
        key_did._key,
    )
    access_token = await authorization.send_token_request(
        authorization.SendTokenRequest(
            token_uri=auth_server_configuration.token_endpoint,
            client_id=ISSUER_DOMAIN,
            code=code,
            client_assertion=client_assertion_jwt.token,
        )
    )

    credential_request_jwt = authorization.create_credential_request(
        authorization.CreateCredentialRequest(
            kid=f"{ebsi_did.did}#{key_did.public_key_jwk.get('kid')}",
            iss=ISSUER_DOMAIN,
            aud=credential_issuer_configuration.credential_issuer,
            nonce=access_token.c_nonce,
        ),
        key_did._key,
    )

    credential_types = [
        authorization.CredentialTypes.VerifiableCredential.value,
        authorization.CredentialTypes.VerifiableAttestation.value,
        authorization.CredentialTypes.VerifiableAuthorisationToOnboard.value,
    ]

    credential = await authorization.send_credential_request(
        authorization.SendCredentialRequest(
            credential_uri=credential_issuer_configuration.credential_endpoint,
            token=access_token.access_token,
            payload=authorization.CredentialRequestPayload(
                types=credential_types,
                proof=authorization.CredentialProof(jwt=credential_request_jwt.token),
            ),
        )
    )

    authorization_server = "https://api-conformance.ebsi.eu/authorisation/v3"
    presentation_definition_uri = f"{authorization_server}/presentation-definitions"
    presentation_definition = await authorization.get_presentation_definition(
        authorization.GetPresentationDefinitionPayload(
            presentation_definition_uri=presentation_definition_uri,
            scope="openid+didr_invite",
        )
    )

    jti = f"urn:uuid:{str(uuid.uuid4())}"
    aud = authorization_server
    vp_token = authorization.create_vp_token(
        authorization.CreateVPToken(
            kid=f"{ebsi_did.did}#{key_did.public_key_jwk.get('kid')}",
            iss=ebsi_did.did,
            aud=aud,
            sub=ebsi_did.did,
            vp=authorization.VerifiablePresentation(
                context=["https://www.w3.org/2018/credentials/v1"],
                id=jti,
                type=["VerifiablePresentation"],
                holder=ebsi_did.did,
                verifiableCredential=[credential.credential],
            ),
            presentation_definition_id=presentation_definition.id,
            description_map_id=presentation_definition.input_descriptors[0].id,
            jti=jti,
        ),
        key_did._key,
    )

    token_uri = f"{authorization_server}/token"
    vp_access_token = await authorization.send_vp_token(
        authorization.SendVPToken(
            token_uri=token_uri,
            grant_type="vp_token",
            scope="openid+didr_invite",
            vp_token=vp_token.token,
            presentation_submission=vp_token.presentation_submission.to_json(),
        )
    )

    logger.info(f"VP access token: {vp_access_token.access_token}")

    base_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]
    }

    rpc_uri = "https://api-conformance.ebsi.eu/did-registry/v4/jsonrpc"
    not_before = int(time.time())
    not_after = not_before + 86400

    local_account: LocalAccount = Account.from_key(eth.private_key)
    account_address = local_account.address
    insert_did_document_rpc_response = (
        await did_registry.make_insert_did_document_rpc_call(
            did_registry.MakeInsertDIDDocumentRPCCall(
                payload=did_registry.JSONRPC20RequestBody(
                    params=[
                        did_registry.InsertDIDDocumentParams(
                            did=ebsi_did.did,
                            baseDocument=json.dumps(base_document),
                            vMethodId=eth.jwk_thumbprint,
                            publicKey=f"0x{eth.public_key_hex}",
                            isSecp256k1=True,
                            notBefore=not_before,
                            notAfter=not_after,
                            _from=account_address,
                        )
                    ],
                    id=str(uuid.uuid4()),
                ),
                rpc_uri=rpc_uri,
                access_token=vp_access_token.access_token,
            )
        )
    )

    signed_transaction = await ledger.sign_ledger_transaction(
        tbs=ledger.ToBeSignedTransaction(
            to=insert_did_document_rpc_response.result.to,
            data=insert_did_document_rpc_response.result.data,
            value=insert_did_document_rpc_response.result.value,
            nonce=int(
                insert_did_document_rpc_response.result.nonce.replace("0x", ""), 16
            ),
            chainId=int(
                insert_did_document_rpc_response.result.chainId.replace("0x", ""), 16
            ),
            gas=int(
                insert_did_document_rpc_response.result.gasLimit.replace("0x", ""), 16
            ),
            gasPrice=int(
                insert_did_document_rpc_response.result.gasPrice.replace("0x", ""), 16
            ),
        ),
        eth_private_key=eth.private_key,
    )

    send_signed_transaction_rpc_response = await ledger.make_send_signed_transaction_rpc_call(
        payload=ledger.MakeSendSignedTransactionRPCCall(
            payload=ledger.JSONRPC20RequestBody(
                params=[
                    ledger.SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=insert_did_document_rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
            ),
            rpc_uri=rpc_uri,
            access_token=vp_access_token.access_token,
        )
    )

    return web.json_response(send_signed_transaction_rpc_response.to_dict())


async def handle_404(request):
    """
    Handles requests to invalid endpoints.

    Returns:
        web.Response: A 404 response with the text "404 - Page not found".
    """
    return web.Response(text="404 - Page not found", status=404)


async def start_server(port: int):
    """
    Starts the web server.

    Args:
        port (int): The port number to start the server on.

    Returns:
        tuple: A tuple containing:
            runner (web.AppRunner): The AppRunner instance.
            site (web.TCPSite): The TCPSite instance.
    """

    app = web.Application()

    # Add startup functions
    app.on_startup.append(generate_and_store_did)
    app.on_startup.append(discover_credential_issuer_and_authn_server)

    # Add routes
    app.router.add_get("/", handle_index, name="handle_index")
    app.router.add_get("/jwks", handle_jwks, name="handle_jwks")
    app.router.add_get(
        "/auth-request",
        handle_authorization_request,
        name="handle_authorization_request",
    )
    app.router.add_get(
        "/auth-redirect",
        handle_authorization_redirect,
        name="handle_authorization_redirect",
    )
    app.router.add_route("*", "/{tail:.*}", handle_404)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, "localhost", port)
    await site.start()

    return runner, site


async def stop_server(runner, site):
    """
    Stops the web server.

    Args:
        runner (web.AppRunner): The AppRunner instance.
        site (web.TCPSite): The TCPSite instance.
    """

    await runner.cleanup()
    await site.stop()


def configure_ngrok(port: int, auth_token: str, custom_domain: str):
    """
    Configures ngrok tunnel.

    Args:
        port (int): The port number to start the server on.
        auth_token (str): ngrok authentication token.
        custom_domain (str): Custom domain for the ngrok tunnel.

    Returns:
        ngrok.Tunnel: The ngrok tunnel instance.
    """

    ngrok.set_auth_token(auth_token)
    ngrok_tunnel = ngrok.connect(port, subdomain=custom_domain)
    return ngrok_tunnel


@click.command()
@click.option("--port", default=8080, help="Port number to start the server on.")
@click.option(
    "--auth-token",
    envvar="NGROK_AUTH_TOKEN",
    prompt="Enter your ngrok authentication token",
    help="ngrok authentication token.",
)
def main(port: int, auth_token: str):
    """
    Runs the main server logic.

    Args:
        port (int): The port number to start the server on. Defaults to 8080.
        auth_token (str): ngrok authentication token. Prompts for input if not provided as an environment variable.
        custom_domain (str): Custom domain for the ngrok tunnel. Prompts for input if not provided as an environment variable.
    """

    loop = asyncio.get_event_loop()
    runner, site = loop.run_until_complete(start_server(port))

    try:
        ngrok_tunnel = configure_ngrok(port, auth_token, ISSUER_SUBDOMAIN)
        print(f"ngrok tunnel URL: {ngrok_tunnel.public_url}")

        loop.run_forever()

    except KeyboardInterrupt:
        pass

    finally:
        loop.run_until_complete(stop_server(runner, site))
        loop.close()
        ngrok.disconnect(ngrok_tunnel.public_url)
        ngrok.kill()


if __name__ == "__main__":
    main()

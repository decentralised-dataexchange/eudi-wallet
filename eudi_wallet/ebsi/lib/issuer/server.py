import asyncio
import click
import dataclasses
import typing
import logging
import uuid
import json
import time
from aiohttp import web
from pyngrok import ngrok  # type: ignore
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eudi_wallet import ethereum
from eudi_wallet import ebsi_did as ebsi_did_module
from eudi_wallet import did_key
from eudi_wallet.ebsi.lib import did_registry
from eudi_wallet.ebsi.lib import auth
from eudi_wallet.ebsi.lib import discovery
from eudi_wallet.ebsi.lib import issuer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ISSUER_MOCK_URI = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
ISSUER_SUBDOMAIN = "issuer"
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

    return None


async def discover_credential_issuer_and_authn_server(app):
    discovery_client = discovery.DiscoveryClient(
        issuer_config_endpoint="https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/.well-known/openid-credential-issuer"
    )
    credential_issuer_configuration = (
        await discovery_client.fetch_credential_issuer_config()
    )
    auth_server_configuration = (
        await discovery_client.fetch_authorization_server_config()
    )

    # Store objects in app
    app["credential_issuer_configuration"] = credential_issuer_configuration
    app["auth_server_configuration"] = auth_server_configuration

    return None


@dataclasses.dataclass
class AppObjects:
    key_did: did_key.KeyDid = None
    ebsi_did: ebsi_did_module.EbsiDid = None
    eth: ethereum.Ethereum = None
    credential_issuer_configuration: discovery.OpenIDCredentialIssuerConfig = None
    auth_server_configuration: discovery.OpenIDAuthServerConfig = None


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
    eth = app_objects.eth
    credential_issuer_configuration = app_objects.credential_issuer_configuration
    auth_server_configuration = app_objects.auth_server_configuration

    auth_mock_client = auth.AuthorizationClient(
        authorization_endpoint=auth_server_configuration.authorization_endpoint
    )
    iss_mock_client = issuer.IssuerClient(
        credential_issuer_configuration.credential_endpoint
    )
    ebsi_auth_client = auth.AuthorizationClient(
        presentation_definition_endpoint="https://api-conformance.ebsi.eu/authorisation/v3/presentation-definitions",
        token_endpoint="https://api-conformance.ebsi.eu/authorisation/v3/token",
    )
    did_registry_client = did_registry.DIDRegistryClient(
        did_registry_rpc_endpoint="https://api-conformance.ebsi.eu/did-registry/v4/jsonrpc",
    )

    credential_types = [
        auth.CredentialTypes.VerifiableCredential.value,
        auth.CredentialTypes.VerifiableAttestation.value,
        auth.CredentialTypes.VerifiableAuthorisationToOnboard.value,
    ]

    builder = auth.AuthorizationRequestBuilder(
        app, ISSUER_DOMAIN, credential_issuer_configuration.authorization_server
    )
    req = builder.build_authorization_request(
        key_did,
        "/auth-redirect",
        "/jwks",
        credential_issuer_configuration,
        credential_types,
    )
    auth_req_token = auth_mock_client.create_authorization_request(req, key_did._key)

    id_token_request = await auth_mock_client.send_authorization_request(
        client_id=ISSUER_DOMAIN,
        scope="openid",
        redirect_uri=ISSUER_DOMAIN + "/auth-redirect",
        request=auth_req_token,
        nonce=req.nonce,
    )
    id_token_request_jwt = await auth_mock_client.get_id_token_request_jwt(
        id_token_request.request_uri
    )

    id_token_response_jwt = auth_mock_client.create_id_token_response(
        auth.CreateIDTokenResponse(
            kid=f"{ebsi_did.did}#{key_did.public_key_jwk.get('kid')}",
            iss=ebsi_did.did,
            sub=ebsi_did.did,
            aud=credential_issuer_configuration.authorization_server,
            nonce=id_token_request_jwt.nonce,
            state=id_token_request_jwt.state,
        ),
        key_did._key,
    )
    auth_code_redirect_uri_response = await auth_mock_client.send_id_token_response(
        id_token_request.redirect_uri,
        id_token_response_jwt.token,
        id_token_request_jwt.state,
    )

    client_assertion_jwt = auth_mock_client.create_client_assertion(
        kid=key_did.public_key_jwk.get("kid"),
        iss=ISSUER_DOMAIN,
        sub=ISSUER_DOMAIN,
        aud=credential_issuer_configuration.authorization_server,
        jti=str(uuid.uuid4()),
        key=key_did._key,
    )

    access_token = await auth_mock_client.send_token_request(
        token_uri=auth_server_configuration.token_endpoint,
        client_id=ISSUER_DOMAIN,
        code=auth_code_redirect_uri_response.code,
        client_assertion=client_assertion_jwt.token,
    )

    credential_request_jwt = iss_mock_client.create_credential_request(
        kid=f"{ebsi_did.did}#{key_did.public_key_jwk.get('kid')}",
        iss=ISSUER_DOMAIN,
        aud=credential_issuer_configuration.credential_issuer,
        nonce=access_token.c_nonce,
        key=key_did._key,
    )

    credential = await iss_mock_client.send_credential_request(
        issuer.SendCredentialRequest(
            credential_uri=credential_issuer_configuration.credential_endpoint,
            token=access_token.access_token,
            payload=issuer.CredentialRequestPayload(
                types=credential_types,
                proof=issuer.CredentialProof(jwt=credential_request_jwt),
            ),
        )
    )

    presentation_definition = await ebsi_auth_client.get_presentation_definition(
        scope="openid+didr_invite",
    )

    jti = f"urn:uuid:{str(uuid.uuid4())}"
    aud = "https://api-conformance.ebsi.eu/authorisation/v3"
    vp_token = ebsi_auth_client.create_vp_token(
        auth.VpJwtTokenPayloadModel(
            kid=f"{ebsi_did.did}#{key_did.public_key_jwk.get('kid')}",
            iss=ebsi_did.did,
            aud=aud,
            sub=ebsi_did.did,
            vp=auth.VerifiablePresentation(
                context=["https://www.w3.org/2018/credentials/v1"],
                id=jti,
                type=["VerifiablePresentation"],
                holder=ebsi_did.did,
                verifiableCredential=[credential.credential],
            ),
            jti=jti,
        ),
        key_did._key,
    )
    presentation_submission = ebsi_auth_client.create_presentation_submission(
        presentation_definition_id=presentation_definition.id,
        descriptor_map_id=presentation_definition.input_descriptors[0].id,
    )

    vp_access_token = await ebsi_auth_client.send_vp_token(
        grant_type="vp_token",
        scope="openid+didr_invite",
        vp_token=vp_token,
        presentation_submission=presentation_submission.to_json(),
    )

    did_registry_client.set_access_token(vp_access_token.access_token)

    base_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]
    }

    not_before = int(time.time())
    not_after = not_before + 86400
    local_account: LocalAccount = Account.from_key(eth.private_key)  # type: ignore
    account_address = local_account.address
    rpc_response = await did_registry_client.insert_did_document(
        did_registry.InsertDIDDocumentJSONRPC20RequestBody(
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
        )
    )

    signed_transaction = await did_registry_client.sign_ledger_transaction(
        tbs=did_registry.ToBeSignedTransaction(
            to=rpc_response.result.to,
            data=rpc_response.result.data,
            value=rpc_response.result.value,
            nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
            chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
            gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
            gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
        ),
        eth_private_key=eth.private_key,
    )

    send_signed_transaction_rpc_response = (
        await did_registry_client.send_signed_transaction(
            did_registry.SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    did_registry.SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )
    )

    logger.info(f"Transaction hash: {send_signed_transaction_rpc_response.to_json()}")

    return web.json_response({"msg": "Success"})


async def handle_404(request):
    """
    Handles requests to invalid endpoints.

    Returns:
        web.Response: A 404 response with the text "404 - Page not found".
    """
    return web.Response(text="404 - Page not found", status=404)


async def handle_well_known_openid_credential_issuer_configuration(request):
    res = {
        "credential_issuer": ISSUER_DOMAIN,
        "authorization_server": "https://api-conformance.ebsi.eu/conformance/v3/auth-mock",
        "credential_endpoint": f"{ISSUER_DOMAIN}/credential",
        "deferred_credential_endpoint": f"{ISSUER_DOMAIN}/credential_deferred",
        "credentials_supported": [
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTRevocable",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [{"name": "CTRevocable", "locale": "en-GB"}],
            }
        ],
    }
    return web.json_response(res)


async def handle_credential_request(request):
    data = await request.json()
    logger.info(f"Received credential request: {data}")
    return web.json_response({"message": "Not implemented yet."})


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
        "/.well-known/openid-credential-issuer",
        handle_well_known_openid_credential_issuer_configuration,
        name="handle_well_known_openid_credential_issuer_configuration",
    )
    app.router.add_post(
        "/credential",
        handle_credential_request,
        name="handle_credential_request",
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

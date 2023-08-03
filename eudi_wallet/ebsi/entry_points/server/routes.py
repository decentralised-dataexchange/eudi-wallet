import dataclasses
import json
import time
import typing
from typing import List, Optional

from aiohttp import web
from aiohttp.web_request import Request
from pydantic import BaseModel, Field, ValidationError, constr

from eudi_wallet.ebsi.entry_points.kafka.producer import produce
from eudi_wallet.ebsi.entry_points.server.constants import WALLET_DOMAIN
from eudi_wallet.ebsi.entry_points.server.decorators import (
    RequestContext, inject_request_context)
from eudi_wallet.ebsi.entry_points.server.well_known import (
    get_well_known_authn_openid_config,
    get_well_known_openid_credential_issuer_config)
from eudi_wallet.ebsi.events.application.legal_entity import \
    OnboardTrustedIssuerEvent
from eudi_wallet.ebsi.events.event_types import EventTypes
from eudi_wallet.ebsi.events.wrapper import EventWrapper
from eudi_wallet.ebsi.exceptions.application.legal_entity import (
    ClientIdRequiredError, CreateAccessTokenError, CreateCredentialOfferError,
    CredentialOfferIsPreAuthorizedError, CredentialOfferNotFoundError,
    InvalidStateInIDTokenResponseError, UpdateCredentialOfferError,
    UserPinRequiredError,
    ValidateDataAttributeValuesAgainstDataAttributesError)
from eudi_wallet.ebsi.exceptions.domain.authn import (
    InvalidAcceptanceTokenError, InvalidAccessTokenError)
from eudi_wallet.ebsi.exceptions.domain.issuer import (
    CredentialOfferRevocationError, CredentialPendingError)
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did
from eudi_wallet.ebsi.utils.jwt import decode_header_and_claims_in_jwt
from eudi_wallet.ebsi.value_objects.application.legal_entity import \
    LegalEntityRoles
from eudi_wallet.ebsi.value_objects.domain.authn import (
    AuthorisationGrants, AuthorizationRequestQueryParams)
from eudi_wallet.ebsi.value_objects.domain.issuer import \
    CredentialIssuanceModes

routes = web.RouteTableDef()


@routes.get("/", name="handle_index")
@inject_request_context()
async def handle_get_index(request: Request, context: RequestContext):
    _, ebsi_did, key_did = await generate_and_store_did(
        context.legal_entity_service.legal_entity_entity.cryptographic_seed
    )

    resp = {
        "did:ebsi": ebsi_did.did,
        "did:key": key_did.did,
    }

    return web.json_response(resp)


@dataclasses.dataclass
class JWKSResponse:
    keys: typing.List[dict]


async def handle_get_jwks(request: Request, context: RequestContext):
    eth, _, key_did = await generate_and_store_did(
        context.legal_entity_service.legal_entity_entity.cryptographic_seed
    )
    resp = JWKSResponse(keys=[key_did.public_key_jwk, eth.public_key_to_jwk()])
    return web.json_response(dataclasses.asdict(resp))


@routes.get("/jwks", name="handle_get_issuer_jwks")
@inject_request_context()
async def handle_get_issuer_jwks(request: Request, context: RequestContext):
    return await handle_get_jwks(request, context)


@routes.get("/jwks", name="handle_get_auth_jwks")
@inject_request_context()
async def handle_get_auth_jwks(request: Request, context: RequestContext):
    return await handle_get_jwks(request, context)


@routes.get("/onboard", name="handle_get_trigger_trusted_issuer_flow")
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_get_trigger_trusted_issuer_flow(
    request: Request, context: RequestContext
):
    legal_entity_entity = context.legal_entity_service.legal_entity_entity

    if legal_entity_entity and (
        legal_entity_entity.is_onboarding_in_progress
        or legal_entity_entity.is_onboarded
    ):
        return web.json_response(
            {
                "is_onboarding_in_progress": legal_entity_entity.is_onboarding_in_progress,
                "is_onboarded": legal_entity_entity.is_onboarded,
            }
        )
    else:
        if not legal_entity_entity:
            crypto_seed = f"{int(time.time())}"
            legal_entity_entity = (
                await context.legal_entity_service.create_legal_entity(
                    cryptographic_seed=crypto_seed,
                    is_onboarding_in_progress=True,
                    role=LegalEntityRoles.TrustedIssuer.value,
                )
            )
        else:
            legal_entity_entity = (
                await context.legal_entity_service.update_legal_entity(
                    legal_entity_entity.id, is_onboarding_in_progress=True
                )
            )
        event = OnboardTrustedIssuerEvent(
            issuer_domain=f"{WALLET_DOMAIN}/issuer",
            crypto_seed=legal_entity_entity.cryptographic_seed,
            openid_credential_issuer_config=context.app_context.credential_issuer_configuration,
            auth_server_config=context.app_context.auth_server_configuration,
        )
        event_wrapper = EventWrapper(
            event_type=EventTypes.OnboardTrustedIssuer.value, payload=event.to_dict()
        )
        await produce(
            message=event_wrapper.to_json(),
            topic=context.app_context.kafka_topic,
            producer=context.app_context.kafka_producer,
            logger=context.app_context.logger,
        )
        return web.json_response(
            {
                "is_onboarding_in_progress": legal_entity_entity.is_onboarding_in_progress,
                "is_onboarded": legal_entity_entity.is_onboarded,
            }
        )


class IssueCredentialReqProof(BaseModel):
    proof_type: constr(min_length=1, strip_whitespace=True)
    jwt: constr(min_length=1, strip_whitespace=True)


class IssueCredentialReq(BaseModel):
    format: constr(min_length=1, strip_whitespace=True)
    types: List[constr(min_length=1, strip_whitespace=True)]
    proof: IssueCredentialReqProof


@routes.post("/credential", name="handle_post_credential_request")
@inject_request_context()
async def handle_post_credential_request(request: Request, context: RequestContext):
    authn_header = request.headers.get("Authorization")
    access_token = None
    if authn_header:
        access_token = authn_header.split("Bearer ")[1]

    data = await request.json()

    try:
        issue_credential_req = IssueCredentialReq(**data)
        credential_response = await context.legal_entity_service.issue_credential(
            credential_request_proof_jwt=issue_credential_req.proof.jwt,
            credential_type_to_be_issued=issue_credential_req.types[-1],
            access_token=access_token,
        )
        context.app_context.logger.debug(f"Credential response: {credential_response}")
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except InvalidAccessTokenError as e:
        raise web.HTTPUnauthorized(reason=str(e))

    return web.json_response(credential_response)


@routes.post("/credential_deferred", name="handle_post_credential_deferred_request")
@inject_request_context()
async def handle_post_credential_deferred_request(
    request: Request, context: RequestContext
):
    authn_header = request.headers.get("Authorization")
    acceptance_token = None
    if authn_header:
        acceptance_token = authn_header.split("Bearer ")[1]

    try:
        credential_response = (
            await context.legal_entity_service.issue_deferred_credential(
                acceptance_token=acceptance_token,
            )
        )
        context.app_context.logger.debug(f"Credential response: {credential_response}")
    except CredentialPendingError as e:
        raise web.HTTPBadRequest(reason=str(e))
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(reason=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except InvalidAcceptanceTokenError as e:
        raise web.HTTPUnauthorized(reason=str(e))

    return web.json_response(credential_response)


@routes.get(
    "/credentials/status/{status_list_index}",
    name="handle_get_credential_status",
)
@inject_request_context()
async def handle_get_credential_status(request: Request, context: RequestContext):
    status_list_index = request.match_info.get("status_list_index")

    credential_status_dict = await context.legal_entity_service.get_credential_status(
        status_list_index
    )
    return web.Response(text=credential_status_dict["credential"])


@routes.get(
    "/.well-known/openid-credential-issuer",
    name="handle_get_well_known_openid_credential_issuer_configuration",
)
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_get_well_known_openid_credential_issuer_configuration(
    request: Request,
    context: RequestContext,
):
    res = get_well_known_openid_credential_issuer_config(WALLET_DOMAIN)
    return web.json_response(res)


@routes.get(
    "/.well-known/openid-configuration",
    name="handle_get_well_known_openid_configuration",
)
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_get_well_known_openid_configuration(
    request: Request, context: RequestContext
):
    res = get_well_known_authn_openid_config(WALLET_DOMAIN)
    return web.json_response(res)


@routes.get(
    "/authorize",
    name="handle_get_authorize",
)
@inject_request_context()
async def handle_get_authorize(request: Request, context: RequestContext):
    query_params = request.rel_url.query
    auth_req = AuthorizationRequestQueryParams.from_dict(query_params)

    issuer_state = auth_req.issuer_state
    state = auth_req.state
    client_id = auth_req.client_id
    code_challenge = auth_req.code_challenge
    code_challenge_method = auth_req.code_challenge_method
    authorisation_request = auth_req.request
    redirect_uri = auth_req.redirect_uri
    scope = auth_req.scope

    try:
        # TODO: Credential offers should be accessed only once.
        # TODO: If client_id is present then check if it matches.
        credential_offer_entity = await context.legal_entity_service.update_credential_offer_from_authorisation_request(
            issuer_state=issuer_state,
            authorisation_request_state=state,
            client_id=client_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_uri=redirect_uri,
        )
        if not credential_offer_entity:
            raise web.HTTPBadRequest(text="Credential offer not found")

        if authorisation_request:
            authn_req_decoded = decode_header_and_claims_in_jwt(authorisation_request)
            client_metadata = authn_req_decoded.claims.get("client_metadata")
        else:
            client_metadata = json.loads(auth_req.client_metadata)

        if scope == "openid ver_test:vp_token":
            redirect_url = await context.legal_entity_service.prepare_redirect_url_with_vp_token_request(
                credential_offer_id=credential_offer_entity.id,
                client_metadata=client_metadata,
                aud=client_id,
            )
        else:
            redirect_url = await context.legal_entity_service.prepare_redirect_url_with_id_token_request(
                credential_offer_id=credential_offer_entity.id,
                client_metadata=client_metadata,
            )
    except CredentialOfferIsPreAuthorizedError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UpdateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))

    response = web.Response(status=302)
    response.headers["Location"] = redirect_url
    return response


class IDTokenResponseReq(BaseModel):
    id_token: Optional[constr(min_length=1, strip_whitespace=True)] = None
    vp_token: Optional[constr(min_length=1, strip_whitespace=True)] = None
    presentation_submission: Optional[
        constr(min_length=1, strip_whitespace=True)
    ] = None
    state: Optional[constr(min_length=1, strip_whitespace=True)] = None


@routes.post(
    "/direct_post",
    name="handle_post_direct_post",
)
@inject_request_context()
async def handle_post_direct_post(request: Request, context: RequestContext):
    data = await request.post()

    try:
        id_token_response_req = IDTokenResponseReq(**data)
        redirect_url = await context.legal_entity_service.prepare_redirect_url_with_authorisation_code_and_state(
            id_token_response=id_token_response_req.id_token,
            state=id_token_response_req.state,
            vp_token_response=id_token_response_req.vp_token,
            presentation_submission=id_token_response_req.presentation_submission,
        )

        response = web.Response(status=302)
        response.headers["Location"] = redirect_url
        return response

    except InvalidStateInIDTokenResponseError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))


class PreAuthorisedCodeTokenReq(BaseModel):
    grant_type: constr(min_length=1, strip_whitespace=True)
    user_pin: constr(min_length=1, strip_whitespace=True)
    pre_authorised_code: constr(min_length=1, strip_whitespace=True) = Field(
        ..., alias="pre-authorized_code"
    )


class TokenReq(BaseModel):
    grant_type: constr(min_length=1, strip_whitespace=True)
    code: constr(min_length=1, strip_whitespace=True)
    client_id: constr(min_length=1, strip_whitespace=True)
    code_verifier: Optional[constr(min_length=1, strip_whitespace=True)] = None
    client_assertion: Optional[constr(min_length=1, strip_whitespace=True)] = None
    client_assertion_type: Optional[constr(min_length=1, strip_whitespace=True)] = None


@routes.post(
    "/token",
    name="handle_post_token",
)
@inject_request_context()
async def handle_post_token(request: Request, context: RequestContext):
    data = await request.post()

    try:
        if (
            data.get("grant_type")
            == AuthorisationGrants.PreAuthorisedCode.value.grant_type
        ):
            token_req = PreAuthorisedCodeTokenReq(**data)
            token = await context.legal_entity_service.create_access_token(
                grant_type=token_req.grant_type,
                user_pin=token_req.user_pin,
                pre_authorised_code=token_req.pre_authorised_code,
            )
        else:
            token_req = TokenReq(**data)
            token = await context.legal_entity_service.create_access_token(
                grant_type=token_req.grant_type,
                code=token_req.code,
                client_id=token_req.client_id,
                code_verifier=token_req.code_verifier,
                client_assertion=token_req.client_assertion,
                client_assertion_type=token_req.client_assertion_type,
            )
        return web.json_response(token)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except CreateAccessTokenError as e:
        raise web.HTTPBadRequest(text=str(e))


class DataAttributeReq(BaseModel):
    attribute_name: constr(min_length=1, strip_whitespace=True)
    attribute_description: constr(min_length=1, strip_whitespace=True)


class CredentialSchemaReq(BaseModel):
    credential_type: constr(min_length=1, strip_whitespace=True)
    data_attributes: List[DataAttributeReq]


@routes.post("/credential-schema", name="handle_post_create_credential_schema")
@inject_request_context()
async def handle_post_create_credential_schema(
    request: Request, context: RequestContext
):
    try:
        data = await request.json()
        credential_schema_req = CredentialSchemaReq(**data)

        credential_schema = await context.legal_entity_service.create_credential_schema(
            credential_type=credential_schema_req.credential_type,
            data_attributes=[
                data_attribute.model_dump()
                for data_attribute in credential_schema_req.data_attributes
            ],
        )

        return web.json_response(credential_schema, status=201)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))


@routes.get("/credential-schemas", name="handle_get_get_all_credential_schema")
@inject_request_context()
async def handle_get_get_all_credential_schema(
    request: Request, context: RequestContext
):
    credential_schemas = await context.legal_entity_service.get_all_credential_schema()

    return web.json_response(
        [credential_schema.to_dict() for credential_schema in credential_schemas]
    )


@routes.delete(
    "/credential-schema/{credential_schema_id}",
    name="handle_delete_credential_schema_by_id",
)
@inject_request_context()
async def handle_delete_credential_schema_by_id(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")

    is_deleted = await context.legal_entity_service.delete_credential_schema_by_id(
        credential_schema_id
    )

    if is_deleted:
        return web.HTTPNoContent()
    else:
        return web.HTTPBadRequest(text="Credential schema not deleted")


class CreateCredentialOfferReq(BaseModel):
    issuance_mode: CredentialIssuanceModes
    is_pre_authorised: bool = False
    supports_revocation: bool = False
    data_attribute_values: Optional[dict] = None
    user_pin: Optional[
        constr(min_length=4, max_length=4, pattern="^[0-9]{4}$", strip_whitespace=True)
    ] = None
    client_id: Optional[constr(min_length=1, strip_whitespace=True)] = None


@routes.post(
    "/credential-schema/{credential_schema_id}/credential-offer",
    name="handle_post_create_credential_offer",
)
@inject_request_context()
async def handle_post_create_credential_offer(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")

    try:
        data = await request.json()
        create_credential_offer_req = CreateCredentialOfferReq(**data)
        credential_offer = await context.legal_entity_service.create_credential_offer(
            credential_schema_id=credential_schema_id,
            data_attribute_values=create_credential_offer_req.data_attribute_values,
            issuance_mode=create_credential_offer_req.issuance_mode.value,
            is_pre_authorised=create_credential_offer_req.is_pre_authorised,
            user_pin=create_credential_offer_req.user_pin,
            client_id=create_credential_offer_req.client_id,
            supports_revocation=create_credential_offer_req.supports_revocation,
        )

        return web.json_response(credential_offer, status=201)
    except ValidateDataAttributeValuesAgainstDataAttributesError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ClientIdRequiredError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UserPinRequiredError as e:
        raise web.HTTPBadRequest(text=str(e))
    except CreateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid JSON")


class UpdateCredentialOfferReq(BaseModel):
    data_attribute_values: dict


@routes.patch(
    "/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}",
    name="handle_patch_update_credential_offer",
)
@inject_request_context()
async def handle_patch_update_credential_offer(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")
    try:
        data = await request.json()
        update_credential_offer_req = UpdateCredentialOfferReq(**data)
        credential_offer = await context.legal_entity_service.update_deferred_credential_offer_with_data_attribute_values(
            credential_offer_id=credential_offer_id,
            credential_schema_id=credential_schema_id,
            data_attribute_values=update_credential_offer_req.data_attribute_values,
        )

        return web.json_response(credential_offer)
    except ValidateDataAttributeValuesAgainstDataAttributesError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UpdateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid JSON")


@routes.post(
    "/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}/revoke",
    name="handle_post_revoke_credential_offer",
)
@inject_request_context()
async def handle_post_revoke_credential_offer(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        credential_offer = await context.legal_entity_service.update_revocation_status_for_credential_offer(
            credential_offer_id=credential_offer_id,
            credential_schema_id=credential_schema_id,
            is_revoked=True,
        )

        return web.json_response(credential_offer)
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))
    except CredentialOfferRevocationError as e:
        raise web.HTTPBadRequest(text=str(e))


@routes.post(
    "/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}/unrevoke",
    name="handle_post_unrevoke_credential_offer",
)
@inject_request_context()
async def handle_post_unrevoke_credential_offer(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        credential_offer = await context.legal_entity_service.update_revocation_status_for_credential_offer(
            credential_offer_id=credential_offer_id,
            credential_schema_id=credential_schema_id,
            is_revoked=False,
        )

        return web.json_response(credential_offer)
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))
    except CredentialOfferRevocationError as e:
        raise web.HTTPBadRequest(text=str(e))


@routes.delete(
    "/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}",
    name="handle_delete_credential_offer",
)
@inject_request_context()
async def handle_delete_credential_offer(request: Request, context: RequestContext):
    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")

    credential_offer_entity = await context.legal_entity_service.get_credential_offer_by_id_and_credential_schema_id(
        credential_offer_id=credential_offer_id,
        credential_schema_id=credential_schema_id,
    )
    if credential_offer_entity is None:
        raise web.HTTPBadRequest(text="Credential offer not found")

    is_deleted = await context.legal_entity_service.delete_credential_offer(
        credential_offer_id=credential_offer_id
    )
    if is_deleted:
        return web.HTTPNoContent()
    else:
        return web.HTTPBadRequest(text="Credential offer not deleted")


@routes.get(
    "/credential-schema/{credential_schema_id}/credential-offers",
    name="handle_get_all_credential_offers_by_credential_schema_id",
)
@inject_request_context()
async def handle_get_all_credential_offers_by_credential_schema_id(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")

    credential_offer_entities = await context.legal_entity_service.get_all_credential_offers_by_credential_schema_id(
        credential_schema_id=credential_schema_id
    )
    return web.json_response(
        [
            credential_offer_entity.to_dict()
            for credential_offer_entity in credential_offer_entities
        ]
    )


@routes.get(
    "/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}",
    name="handle_get_get_credential_offer_by_id_and_credential_schema_id",
)
@inject_request_context()
async def handle_get_get_credential_offer_by_id_and_credential_schema_id(
    request: Request, context: RequestContext
):
    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")

    credential_offer_entity = await context.legal_entity_service.get_credential_offer_by_id_and_credential_schema_id(
        credential_offer_id=credential_offer_id,
        credential_schema_id=credential_schema_id,
    )

    if credential_offer_entity is None:
        raise web.HTTPBadRequest(text="Credential offer not found")

    return web.json_response(credential_offer_entity.to_dict())


@routes.get(
    "/credential-offer/{credential_offer_id}/initiate",
    name="handle_get_initiate_credential_offer",
)
@inject_request_context()
async def handle_get_initiate_credential_offer(
    request: Request, context: RequestContext
):
    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        openid_credential_offer_uri = (
            await context.legal_entity_service.initiate_credential_offer(
                credential_offer_id=credential_offer_id
            )
        )
        response = web.Response(status=302)
        response.headers["Location"] = openid_credential_offer_uri
        return response

    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))


@routes.get(
    "/credential-offer/{credential_offer_id}",
    name="handle_get_get_credential_offer_by_reference",
)
@inject_request_context()
async def handle_get_get_credential_offer_by_reference(
    request: Request, context: RequestContext
):
    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        credential_offer_response = await context.legal_entity_service.get_credential_offer_by_reference_using_credential_offer_uri(
            credential_offer_id=credential_offer_id
        )
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))

    return web.json_response(credential_offer_response)


@routes.get(
    "/request-uri/{credential_offer_id}",
    name="handle_get_get_id_token_request_by_uri",
)
@inject_request_context()
async def handle_get_get_id_token_request_by_uri(
    request: Request, context: RequestContext
):
    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        id_token_request_jwt = await context.legal_entity_service.get_id_token_request_from_credential_offer(
            credential_offer_id=credential_offer_id
        )
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))

    return web.json_response(id_token_request_jwt, content_type="application/jwt")

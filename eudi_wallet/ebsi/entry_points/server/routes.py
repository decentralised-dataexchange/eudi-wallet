import dataclasses
import json
import time
import typing
from typing import List, Optional

from aiohttp import web
from aiohttp.web_request import Request
from pydantic import BaseModel, ValidationError, constr

from eudi_wallet.ebsi.entry_points.kafka.producer import produce
from eudi_wallet.ebsi.entry_points.server.constants import WALLET_DOMAIN
from eudi_wallet.ebsi.entry_points.server.utils import (AppObjects,
                                                        get_app_objects)
from eudi_wallet.ebsi.entry_points.server.well_known import (
    get_well_known_authn_openid_config,
    get_well_known_openid_credential_issuer_config)
from eudi_wallet.ebsi.events.application.legal_entity import \
    OnboardTrustedIssuerEvent
from eudi_wallet.ebsi.events.event_types import EventTypes
from eudi_wallet.ebsi.events.wrapper import EventWrapper
from eudi_wallet.ebsi.exceptions.application.legal_entity import (
    CreateAccessTokenError, CreateCredentialOfferError,
    CredentialOfferNotFoundError, InvalidStateInIDTokenResponseError,
    UpdateCredentialOfferError)
from eudi_wallet.ebsi.exceptions.domain.authn import InvalidAccessTokenError
from eudi_wallet.ebsi.repositories.application.credential_offer import \
    SqlAlchemyCredentialOfferRepository
from eudi_wallet.ebsi.repositories.application.credential_schema import \
    SqlAlchemyCredentialSchemaRepository
from eudi_wallet.ebsi.repositories.application.legal_entity import \
    SqlAlchemyLegalRepository
from eudi_wallet.ebsi.services.application.legal_entity import \
    LegalEntityService
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did
from eudi_wallet.ebsi.value_objects.application.legal_entity import \
    LegalEntityRoles
from eudi_wallet.ebsi.value_objects.domain.authn import \
    AuthorizationRequestQueryParams
from eudi_wallet.ebsi.value_objects.domain.issuer import \
    CredentialIssuanceModes

routes = web.RouteTableDef()


async def get_legal_entity_service(app_objects: AppObjects) -> LegalEntityService:
    credential_schema_repository = SqlAlchemyCredentialSchemaRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_repository = SqlAlchemyLegalRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    credential_offer_repository = SqlAlchemyCredentialOfferRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_service = LegalEntityService(
        credential_issuer_configuration=app_objects.credential_issuer_configuration,
        auth_server_configuration=app_objects.auth_server_configuration,
        logger=app_objects.logger,
        issuer_domain=f"{WALLET_DOMAIN}/issuer",
        auth_domain=f"{WALLET_DOMAIN}/auth",
        legal_entity_repository=legal_entity_repository,
        credential_schema_repository=credential_schema_repository,
        credential_offer_repository=credential_offer_repository,
    )

    return legal_entity_service


@routes.get("/", name="handle_index")
async def handle_get_index(request: Request):
    app_objects = get_app_objects(request.app)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    _, ebsi_did, key_did = await generate_and_store_did(
        legal_entity_entity.cryptographic_seed
    )

    resp = {
        "did:ebsi": ebsi_did.did,
        "did:key": key_did.did,
    }

    return web.json_response(resp)


@dataclasses.dataclass
class JWKSResponse:
    keys: typing.List[dict]


async def handle_get_jwks(request: Request):
    app_objects = get_app_objects(request.app)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    eth, _, key_did = await generate_and_store_did(
        legal_entity_entity.cryptographic_seed
    )
    resp = JWKSResponse(keys=[key_did.public_key_jwk, eth.public_key_to_jwk()])
    return web.json_response(dataclasses.asdict(resp))


@routes.get("/issuer/jwks", name="handle_get_issuer_jwks")
async def handle_get_issuer_jwks(request: Request):
    return await handle_get_jwks(request)


@routes.get("/auth/jwks", name="handle_get_auth_jwks")
async def handle_get_auth_jwks(request: Request):
    return await handle_get_jwks(request)


@routes.get("/issuer/onboard", name="handle_get_trigger_trusted_issuer_flow")
async def handle_get_trigger_trusted_issuer_flow(request: Request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()

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
            legal_entity_entity = legal_entity_service.legal_entity_repository.create(
                cryptographic_seed=crypto_seed,
                is_onboarding_in_progress=True,
                role=LegalEntityRoles.TrustedIssuer.value,
            )
        else:
            legal_entity_entity.is_onboarding_in_progress = True
            legal_entity_entity = legal_entity_service.legal_entity_repository.update(
                legal_entity_entity
            )
        event = OnboardTrustedIssuerEvent(
            issuer_domain=f"{WALLET_DOMAIN}/issuer",
            crypto_seed=legal_entity_entity.cryptographic_seed,
            openid_credential_issuer_config=app_objects.credential_issuer_configuration,
            auth_server_config=app_objects.auth_server_configuration,
        )
        event_wrapper = EventWrapper(
            event_type=EventTypes.OnboardTrustedIssuer.value, payload=event.to_dict()
        )
        produce(
            message=event_wrapper.to_json(),
            topic=app_objects.kafka_topic,
            producer=app_objects.kafka_producer,
            logger=app_objects.logger,
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


@routes.post("/issuer/credential", name="handle_post_credential_request")
async def handle_post_credential_request(request: Request):
    app_objects = get_app_objects(request.app)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    authn_header = request.headers.get("Authorization")
    access_token = None
    if authn_header:
        access_token = authn_header.split("Bearer ")[1]

    data = await request.json()

    try:
        issue_credential_req = IssueCredentialReq(**data)
        credential = await legal_entity_service.issue_credential(
            credential_request_proof_jwt=issue_credential_req.proof.jwt,
            credential_type_to_be_issued=issue_credential_req.types[-1],
            access_token=access_token,
        )
        app_objects.logger.debug(f"Credential issued: {credential}")
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except InvalidAccessTokenError as e:
        raise web.HTTPUnauthorized(reason=str(e))

    return web.json_response(credential)


@routes.get(
    "/issuer/credentials/status/{credential_status_index}",
    name="handle_get_credential_status",
)
async def handle_get_credential_status(request: Request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    if request.match_info.get("credential_status_index"):
        credential_status_index = int(request.match_info.get("credential_status_index"))
    else:
        credential_status_index = 0

    credential_status_dict = await legal_entity_service.get_credential_status(
        credential_status_index
    )
    return web.Response(text=credential_status_dict["credential"])


@routes.get(
    "/issuer/.well-known/openid-credential-issuer",
    name="handle_get_well_known_openid_credential_issuer_configuration",
)
async def handle_get_well_known_openid_credential_issuer_configuration(
    request: Request,
):
    res = get_well_known_openid_credential_issuer_config(WALLET_DOMAIN)
    return web.json_response(res)


@routes.get(
    "/auth/.well-known/openid-configuration",
    name="handle_get_well_known_openid_configuration",
)
async def handle_get_well_known_openid_configuration(request: Request):
    res = get_well_known_authn_openid_config(WALLET_DOMAIN)
    return web.json_response(res)


@routes.get(
    "/auth/authorize",
    name="handle_get_authorize",
)
async def handle_get_authorize(request: Request):
    app_objects = get_app_objects(request.app)

    query_params = request.rel_url.query
    auth_req = AuthorizationRequestQueryParams.from_dict(query_params)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    issuer_state = auth_req.issuer_state
    if not issuer_state:
        raise web.HTTPBadRequest(text="issuer_state is required")

    state = auth_req.state
    client_id = auth_req.client_id
    code_challenge = auth_req.code_challenge
    code_challenge_method = auth_req.code_challenge_method

    try:
        # TODO: Credential offers should be accessed only once.
        # TODO: If client_id is present then check if it matches.
        credential_offer_entity = (
            await legal_entity_service.update_credential_offer_by_id(
                issuer_state=issuer_state,
                authorisation_request_state=state,
                client_id=client_id,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                redirect_uri=auth_req.redirect_uri,
            )
        )
        if not credential_offer_entity:
            raise web.HTTPBadRequest(text="Credential offer not found")

        redirect_url = (
            await legal_entity_service.prepare_redirect_url_with_id_token_request(
                credential_offer_id=credential_offer_entity.id, auth_req=auth_req
            )
        )
    except UpdateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))

    return web.HTTPFound(location=redirect_url)


class IDTokenResponseReq(BaseModel):
    id_token: constr(min_length=1, strip_whitespace=True)
    state: Optional[constr(min_length=1, strip_whitespace=True)]


@routes.post(
    "/auth/direct_post",
    name="handle_post_direct_post",
)
async def handle_post_direct_post(request: Request):
    data = await request.post()

    app_objects = get_app_objects(request.app)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    try:
        id_token_response_req = IDTokenResponseReq(**data)
        redirect_url = await legal_entity_service.prepare_redirect_url_with_authorisation_code_and_state(
            id_token_response=id_token_response_req.id_token,
            state=id_token_response_req.state,
        )

        return web.HTTPFound(location=redirect_url)
    except InvalidStateInIDTokenResponseError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))


class TokenReq(BaseModel):
    grant_type: constr(min_length=1, strip_whitespace=True)
    code: constr(min_length=1, strip_whitespace=True)
    client_id: constr(min_length=1, strip_whitespace=True)
    code_verifier: constr(min_length=1, strip_whitespace=True)


@routes.post(
    "/auth/token",
    name="handle_post_token",
)
async def handle_post_token(request: Request):
    data = await request.post()

    app_objects = get_app_objects(request.app)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    try:
        token_req = TokenReq(**data)
        token = await legal_entity_service.create_access_token(
            grant_type=token_req.grant_type,
            code=token_req.code,
            client_id=token_req.client_id,
            code_verifier=token_req.code_verifier,
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


@routes.post("/issuer/credential-schema", name="handle_post_create_credential_schema")
async def handle_post_create_credential_schema(request):
    app_objects = get_app_objects(request.app)
    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    try:
        data = await request.json()
        credential_schema_req = CredentialSchemaReq(**data)

        credential_schema = await legal_entity_service.create_credential_schema(
            credential_type=credential_schema_req.credential_type,
            data_attributes=[
                data_attribute.model_dump()
                for data_attribute in credential_schema_req.data_attributes
            ],
        )

        return web.json_response(credential_schema, status=201)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))


@routes.get("/issuer/credential-schemas", name="handle_get_get_all_credential_schema")
async def handle_get_get_all_credential_schema(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_schemas = await legal_entity_service.get_all_credential_schema()

    return web.json_response(
        [credential_schema.to_dict() for credential_schema in credential_schemas]
    )


@routes.delete(
    "/issuer/credential-schema/{credential_schema_id}",
    name="handle_delete_credential_schema_by_id",
)
async def handle_delete_credential_schema_by_id(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_schema_id = request.match_info.get("credential_schema_id")

    is_deleted = await legal_entity_service.delete_credential_schema_by_id(
        credential_schema_id
    )

    if is_deleted:
        return web.HTTPNoContent()
    else:
        return web.HTTPBadRequest(text="Credential schema not deleted")


class CreateCredentialOfferReq(BaseModel):
    issuance_mode: CredentialIssuanceModes
    data_attribute_values: dict


@routes.post(
    "/issuer/credential-schema/{credential_schema_id}/credential-offer",
    name="handle_post_create_credential_offer",
)
async def handle_post_create_credential_offer(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_schema_id = request.match_info.get("credential_schema_id")

    try:
        data = await request.json()
        create_credential_offer_req = CreateCredentialOfferReq(**data)
        credential_offer = await legal_entity_service.create_credential_offer(
            credential_schema_id=credential_schema_id,
            data_attribute_values=create_credential_offer_req.data_attribute_values,
            issuance_mode=create_credential_offer_req.issuance_mode.value,
        )

        return web.json_response(credential_offer, status=201)
    except CreateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid JSON")


@routes.delete(
    "/issuer/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}",
    name="handle_delete_credential_offer",
)
async def handle_delete_credential_offer(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")

    credential_offer_entity = (
        await legal_entity_service.get_credential_offer_by_id_and_credential_schema_id(
            credential_offer_id=credential_offer_id,
            credential_schema_id=credential_schema_id,
        )
    )
    if credential_offer_entity is None:
        raise web.HTTPBadRequest(text="Credential offer not found")

    is_deleted = await legal_entity_service.delete_credential_offer(
        credential_offer_id=credential_offer_id
    )
    if is_deleted:
        return web.HTTPNoContent()
    else:
        return web.HTTPBadRequest(text="Credential offer not deleted")


@routes.get(
    "/issuer/credential-schema/{credential_schema_id}/credential-offers",
    name="handle_get_all_credential_offers_by_credential_schema_id",
)
async def handle_get_all_credential_offers_by_credential_schema_id(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_schema_id = request.match_info.get("credential_schema_id")

    credential_offer_entities = (
        await legal_entity_service.get_all_credential_offers_by_credential_schema_id(
            credential_schema_id=credential_schema_id
        )
    )
    return web.json_response(
        [
            credential_offer_entity.to_dict()
            for credential_offer_entity in credential_offer_entities
        ]
    )


@routes.get(
    "/issuer/credential-schema/{credential_schema_id}/credential-offer/{credential_offer_id}",
    name="handle_get_get_credential_offer_by_id_and_credential_schema_id",
)
async def handle_get_get_credential_offer_by_id_and_credential_schema_id(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_schema_id = request.match_info.get("credential_schema_id")
    credential_offer_id = request.match_info.get("credential_offer_id")

    credential_offer_entity = (
        await legal_entity_service.get_credential_offer_by_id_and_credential_schema_id(
            credential_offer_id=credential_offer_id,
            credential_schema_id=credential_schema_id,
        )
    )

    if credential_offer_entity is None:
        raise web.HTTPBadRequest(text="Credential offer not found")

    return web.json_response(credential_offer_entity.to_dict())


@routes.get(
    "/issuer/credential-offer/{credential_offer_id}/initiate",
    name="handle_get_initiate_credential_offer",
)
async def handle_get_initiate_credential_offer(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        openid_credential_offer_uri = (
            await legal_entity_service.initiate_credential_offer(
                credential_offer_id=credential_offer_id
            )
        )
        return web.HTTPFound(openid_credential_offer_uri)
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))


@routes.get(
    "/issuer/credential-offer/{credential_offer_id}",
    name="handle_get_get_credential_offer_by_reference",
)
async def handle_get_get_credential_offer_by_reference(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        credential_offer_response = await legal_entity_service.get_credential_offer_by_reference_using_credential_offer_uri(
            credential_offer_id=credential_offer_id
        )
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))

    return web.json_response(credential_offer_response)


@routes.get(
    "/issuer/request-uri/{credential_offer_id}",
    name="handle_get_get_id_token_request_by_uri",
)
async def handle_get_get_id_token_request_by_uri(request):
    app_objects = get_app_objects(request.app)

    legal_entity_service = await get_legal_entity_service(app_objects)
    legal_entity_entity = legal_entity_service.legal_entity_repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    credential_offer_id = request.match_info.get("credential_offer_id")

    try:
        id_token_request_jwt = (
            await legal_entity_service.get_id_token_request_from_credential_offer(
                credential_offer_id=credential_offer_id
            )
        )
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))

    return web.json_response(id_token_request_jwt, content_type="application/jwt")

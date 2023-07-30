import dataclasses
import time
import typing

from aiohttp import web
from aiohttp.web_request import Request

from eudi_wallet.ebsi.entry_points.kafka.producer import produce
from eudi_wallet.ebsi.entry_points.server.constants import ISSUER_DOMAIN
from eudi_wallet.ebsi.entry_points.server.utils import get_app_objects
from eudi_wallet.ebsi.events.application.legal_entity import \
    OnboardTrustedIssuerEvent
from eudi_wallet.ebsi.events.event_types import EventTypes
from eudi_wallet.ebsi.events.wrapper import EventWrapper
from eudi_wallet.ebsi.repositories.application.legal_entity import \
    SqlAlchemyLegalRepository
from eudi_wallet.ebsi.services.application.legal_entity import \
    LegalEntityService
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did
from eudi_wallet.ebsi.value_objects.application.legal_entity import \
    LegalEntityRoles

routes = web.RouteTableDef()


@routes.get("/", name="handle_index")
async def handle_get_index(request: Request):
    app_objects = get_app_objects(request.app)
    repository = SqlAlchemyLegalRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_entity = repository.get_first()
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


@routes.get("/jwks", name="handle_get_jwks")
async def handle_get_jwks(request: Request):
    app_objects = get_app_objects(request.app)
    repository = SqlAlchemyLegalRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_entity = repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    eth, _, key_did = await generate_and_store_did(
        legal_entity_entity.cryptographic_seed
    )
    resp = JWKSResponse(keys=[key_did.public_key_jwk, eth.public_key_to_jwk()])
    return web.json_response(dataclasses.asdict(resp))


@routes.get("/onboard", name="handle_get_trigger_trusted_issuer_flow")
async def handle_get_trigger_trusted_issuer_flow(request: Request):
    app_objects = get_app_objects(request.app)

    repository = SqlAlchemyLegalRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_entity = repository.get_first()

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
            legal_entity_entity = repository.create(
                cryptographic_seed=crypto_seed,
                is_onboarding_in_progress=True,
                role=LegalEntityRoles.TrustedIssuer.value,
            )
        else:
            legal_entity_entity.is_onboarding_in_progress = True
            legal_entity_entity = repository.update(legal_entity_entity)
        event = OnboardTrustedIssuerEvent(
            issuer_domain=ISSUER_DOMAIN,
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


@routes.get(
    "/.well-known/openid-credential-issuer",
    name="handle_get_well_known_openid_credential_issuer_configuration",
)
async def handle_get_well_known_openid_credential_issuer_configuration(
    request: Request,
):
    app_objects = get_app_objects(request.app)
    logger = app_objects.logger
    logger.debug("Received request to openid credential issuer configuration route")
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


@routes.post("/credential", name="handle_post_credential_request")
async def handle_post_credential_request(request: Request):
    app_objects = get_app_objects(request.app)
    repository = SqlAlchemyLegalRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_entity = repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")
    legal_entity_service = LegalEntityService(
        credential_issuer_configuration=app_objects.credential_issuer_configuration,
        auth_server_configuration=app_objects.auth_server_configuration,
        logger=app_objects.logger,
        issuer_domain=ISSUER_DOMAIN,
        repository=repository,
    )
    await legal_entity_service.set_cryptographic_seed(
        crypto_seed=legal_entity_entity.cryptographic_seed
    )
    await legal_entity_service.set_entity(legal_entity_entity=legal_entity_entity)

    data = await request.json()
    credential_response_dict = await legal_entity_service.issue_credential(data)
    return web.json_response(credential_response_dict)


@routes.get(
    "/credentials/status/{credential_status_index}", name="handle_get_credential_status"
)
async def handle_get_credential_status(request: Request):
    app_objects = get_app_objects(request.app)
    logger = app_objects.logger
    logger.debug("Received request to get credential status route")

    repository = SqlAlchemyLegalRepository(
        session=app_objects.db_session, logger=app_objects.logger
    )
    legal_entity_entity = repository.get_first()
    if not legal_entity_entity:
        raise web.HTTPBadRequest(text="Legal entity not found")

    legal_entity_service = LegalEntityService(
        credential_issuer_configuration=app_objects.credential_issuer_configuration,
        auth_server_configuration=app_objects.auth_server_configuration,
        logger=app_objects.logger,
        issuer_domain=ISSUER_DOMAIN,
        repository=repository,
    )
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

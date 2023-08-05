import dataclasses
from functools import wraps
from typing import Optional

from aiohttp import web

from eudi_wallet.ebsi.entry_points.server.utils import AppContext, get_app_context
from eudi_wallet.ebsi.repositories.application.credential_offer import (
    SqlAlchemyCredentialOfferRepository,
)
from eudi_wallet.ebsi.repositories.application.credential_revocation_status_list import (
    SqlAlchemyCredentialRevocationStatusListRepository,
)
from eudi_wallet.ebsi.repositories.application.credential_schema import (
    SqlAlchemyCredentialSchemaRepository,
)
from eudi_wallet.ebsi.repositories.application.legal_entity import (
    SqlAlchemyLegalRepository,
)
from eudi_wallet.ebsi.services.application.legal_entity import LegalEntityService


async def get_legal_entity_service(app_context: AppContext) -> LegalEntityService:
    credential_schema_repository = SqlAlchemyCredentialSchemaRepository(
        session=app_context.db_session, logger=app_context.logger
    )
    legal_entity_repository = SqlAlchemyLegalRepository(
        session=app_context.db_session, logger=app_context.logger
    )
    credential_offer_repository = SqlAlchemyCredentialOfferRepository(
        session=app_context.db_session, logger=app_context.logger
    )
    credential_revocation_status_list_repository = (
        SqlAlchemyCredentialRevocationStatusListRepository(
            session=app_context.db_session, logger=app_context.logger
        )
    )
    legal_entity_service = LegalEntityService(
        credential_issuer_configuration=app_context.credential_issuer_configuration,
        auth_server_configuration=app_context.auth_server_configuration,
        logger=app_context.logger,
        issuer_domain=app_context.domain,
        auth_domain=app_context.domain,
        legal_entity_repository=legal_entity_repository,
        credential_schema_repository=credential_schema_repository,
        credential_offer_repository=credential_offer_repository,
        credential_revocation_status_list_repository=credential_revocation_status_list_repository,
    )

    return legal_entity_service


@dataclasses.dataclass
class RequestContext:
    app_context: AppContext
    legal_entity_service: Optional[LegalEntityService] = None


def inject_request_context(raise_exception_if_legal_entity_not_found: bool = True):
    def decorator(view_func):
        @wraps(view_func)
        async def wrapper(request):
            app_context = get_app_context(request.app)

            legal_entity_service = await get_legal_entity_service(app_context)

            legal_entity_entity = await legal_entity_service.get_first_legal_entity()
            if raise_exception_if_legal_entity_not_found:
                if legal_entity_entity is None:
                    raise web.HTTPBadRequest(text="Legal entity not found")
                else:
                    await legal_entity_service.set_cryptographic_seed(
                        crypto_seed=legal_entity_entity.cryptographic_seed
                    )
                    await legal_entity_service.set_entity(
                        legal_entity_entity=legal_entity_entity
                    )

            return await view_func(
                request=request,
                context=RequestContext(
                    app_context=app_context, legal_entity_service=legal_entity_service
                ),
            )

        return wrapper

    return decorator

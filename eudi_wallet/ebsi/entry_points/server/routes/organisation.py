import json
from typing import Optional, cast

from aiohttp import web
from aiohttp.web_request import Request
from pydantic import BaseModel, HttpUrl, ValidationError, conlist, constr

from eudi_wallet.ebsi.entry_points.server.decorators import (
    RequestContext,
    inject_request_context,
)
from eudi_wallet.ebsi.usecases.organisation.create_data_agreement_usecase import (
    CreateDataAgreementUsecase,
)
from eudi_wallet.ebsi.usecases.organisation.delete_data_agreement_usecase import (
    DeleteDataAgreementUsecase,
)
from eudi_wallet.ebsi.usecases.organisation.list_all_data_agreements_usecase import (
    ListAllDataAgreementsUsecase,
)
from eudi_wallet.ebsi.usecases.organisation.register_organisation_usecase import (
    RegisterOrganisationUsecase,
)
from eudi_wallet.ebsi.usecases.organisation.update_organisation_usecase import (
    UpdateOrganisationUsecase,
)
from eudi_wallet.ebsi.value_objects.application.organisation import (
    DataAgreementExchangeModes,
)

organisation_routes = web.RouteTableDef()


class RegisterOrganisationReq(BaseModel):
    name: constr(min_length=1, max_length=100, strip_whitespace=True)  # type: ignore
    description: Optional[
        constr(min_length=1, max_length=500, strip_whitespace=True)  # type: ignore
    ] = None
    logo_url: Optional[HttpUrl] = None


@organisation_routes.post("/organisation", name="handle_post_register_organisation")  # type: ignore
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_post_register_organisation(request: Request, context: RequestContext):
    assert context.organisation_repository is not None
    assert context.app_context.logger is not None
    try:
        data = await request.json()
        register_organisation_req = RegisterOrganisationReq(**data)

        usecase = RegisterOrganisationUsecase(
            organisation_repository=context.organisation_repository,
            logger=context.app_context.logger,
        )

        logo_url = cast(str, register_organisation_req.logo_url)
        organisation = usecase.execute(
            name=register_organisation_req.name,
            description=register_organisation_req.description,
            logo_url=logo_url,
        )
        return web.json_response(organisation.to_dict())
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


class UpdateOrganisationReq(BaseModel):
    name: constr(min_length=1, max_length=100, strip_whitespace=True)  # type: ignore
    description: Optional[
        constr(min_length=1, max_length=500, strip_whitespace=True)  # type: ignore
    ] = None
    logo_url: Optional[HttpUrl] = None


@organisation_routes.patch(
    "/organisation/{organisation_id}", name="handle_patch_update_organisation"
)  # type: ignore
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_patch_update_organisation(request: Request, context: RequestContext):
    assert context.organisation_repository is not None
    assert context.app_context.logger is not None
    try:
        organisation_id = request.match_info.get("organisation_id")
        if organisation_id is None:
            raise web.HTTPBadRequest(reason="Invalid organisation id")

        data = await request.json()
        update_organisation_req = UpdateOrganisationReq(**data)
        usecase = UpdateOrganisationUsecase(
            organisation_repository=context.organisation_repository,
            logger=context.app_context.logger,
        )

        logo_url = cast(str, update_organisation_req.logo_url)
        organisation = usecase.execute(
            organisation_id=organisation_id,
            name=update_organisation_req.name,
            description=update_organisation_req.description,
            logo_url=logo_url,
        )
        if not organisation:
            raise web.HTTPBadRequest(reason="Organisation not found")
        return web.json_response(organisation.to_dict())
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


class DataAttributeReq(BaseModel):
    attribute_name: constr(min_length=1, strip_whitespace=True)  # type: ignore
    attribute_description: constr(min_length=1, strip_whitespace=True)  # type: ignore


class CreateDataAgreementReq(BaseModel):
    name: constr(min_length=1, strip_whitespace=True)  # type: ignore
    exchange_mode: DataAgreementExchangeModes
    credential_types: Optional[
        conlist(constr(min_length=1, strip_whitespace=True), min_length=1)  # type: ignore
    ] = None
    data_attributes: conlist(DataAttributeReq, min_length=1)  # type: ignore


@organisation_routes.post(
    "/organisation/{organisation_id}/data-agreement",
    name="handle_post_create_data_agreement",
)  # type: ignore
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_post_create_data_agreement(request: Request, context: RequestContext):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None
    try:
        organisation_id = request.match_info.get("organisation_id")
        if organisation_id is None:
            raise web.HTTPBadRequest(reason="Invalid organisation id")

        data = await request.json()
        create_data_agreement_req = CreateDataAgreementReq(**data)
        usecase = CreateDataAgreementUsecase(
            dataagreement_repository=context.data_agreement_repository,
            logger=context.app_context.logger,
        )
        data_attributes = [
            data_attribute.model_dump()
            for data_attribute in create_data_agreement_req.data_attributes
        ]
        data_agreement = usecase.execute(
            organisation_id=organisation_id,
            name=create_data_agreement_req.name,
            data_attributes=data_attributes,
            exchange_mode=create_data_agreement_req.exchange_mode.value,
            credential_types=create_data_agreement_req.credential_types,
        )
        return web.json_response(data_agreement.to_dict(), status=201)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


@organisation_routes.get(
    "/organisation/{organisation_id}/data-agreements",
    name="handle_get_list_all_data_agreements",
)  # type: ignore
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_get_list_all_data_agreements(
    request: Request, context: RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisation_id")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    usecase = ListAllDataAgreementsUsecase(
        dataagreement_repository=context.data_agreement_repository,
        logger=context.app_context.logger,
    )
    data_agreements = usecase.execute(organisation_id=organisation_id)
    return web.json_response(
        [data_agreement.to_dict() for data_agreement in data_agreements]
    )


@organisation_routes.delete(
    "/organisation/{organisation_id}/data-agreement/{data_agreement_id}",
    name="handle_delete_delete_data_agreement",
)  # type: ignore
@inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_delete_delete_data_agreement(
    request: Request, context: RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisation_id")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    data_agreement_id = request.match_info.get("data_agreement_id")
    if data_agreement_id is None:
        raise web.HTTPBadRequest(reason="Invalid data agreement id")

    usecase = DeleteDataAgreementUsecase(
        dataagreement_repository=context.data_agreement_repository,
        logger=context.app_context.logger,
    )
    is_deleted = usecase.execute(
        organisation_id=organisation_id, data_agreement_id=data_agreement_id
    )
    if not is_deleted:
        raise web.HTTPBadRequest(reason="Data agreement not deleted")
    raise web.HTTPNoContent(reason="Data agreement deleted")

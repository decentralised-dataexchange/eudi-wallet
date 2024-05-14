import json
from typing import Optional, cast
import uuid

from aiohttp import web
from aiohttp.web_request import Request
from pydantic import BaseModel, HttpUrl, ValidationError, conlist, constr

from eudi_wallet.ebsi.entry_points.server.decorators import (
    V2RequestContext,
    v2_inject_request_context,
)
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)
from eudi_wallet.ebsi.value_objects.application.organisation import (
    DataAgreementExchangeModes,
)
from eudi_wallet.ebsi.usecases.v2.organisation.create_verification_request_usecase import (
    CreateVerificationRequestUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.create_verification_request_usecase_v2 import (
    CreateVerificationRequestUsecaseV2,
)
from eudi_wallet.ebsi.usecases.v2.organisation.register_organisation_usecase import (
    RegisterOrganisationUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.read_organisation_usecase import (
    ReadOrganisationUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.update_organisation_usecase import (
    UpdateOrganisationUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.delete_organisation_usecase import (
    DeleteOrganisationUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.create_data_agreement_usecase import (
    CreateV2DataAgreementUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.list_all_data_agreements_usecase import (
    V2ListAllDataAgreementsUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.delete_data_agreement_usecase import (
    V2DeleteDataAgreementUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.get_data_agreement_by_id_usecase import (
    V2GetDataAgreementByIdUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.update_data_agreement_usecase import (
    UpdateDataAgreementUsecase,
)
from sdjwt.adapter import DataAttributesAdapter, DataAttribute

from eudi_wallet.ebsi.value_objects.domain.issuer import (
    CredentialIssuanceModes,
)
from eudi_wallet.ebsi.exceptions.application.organisation import (
    CreateDataAgreementUsecaseError,
    IssueCredentialError,
    UserPinRequiredError,
    ValidateDataAttributeValuesAgainstDataAttributesError,
    CreateCredentialOfferError,
    UpdateCredentialOfferError,
)
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did_v2
from eudi_wallet.ebsi.utils.common import (
    validate_data_attribute_schema_against_data_attribute_values,
)
from sdjwt.pex import (
    validate_and_deserialise_presentation_definition,
    PresentationDefinitionValidationError,
)
from eudi_wallet.ebsi.usecases.v2.organisation.read_verification_request_usecase import (
    ReadVerificationRequestUsecase,
    ReadVerificationRequestUsecaseError,
)
from eudi_wallet.ebsi.usecases.v2.organisation.delete_verification_request_usecase import (
    DeleteVerificationRequestUsecase,
    DeleteVerificationRequestUsecaseError,
)

from eudi_wallet.ebsi.usecases.v2.organisation.list_verification_request_usecase import (
    ListVerificationRequestUsecase,
)
from eudi_wallet.ebsi.entry_points.server.v2_well_known import (
    validate_credential_type_based_on_disclosure_mapping,
)

config_routes = web.RouteTableDef()


@config_routes.get(
    "/organisation/{organisationId}/config/organisation-identifier",
    name="handle_config_get_organisation_identifier",
)
@v2_inject_request_context()
async def handle_config_get_organisation_identifier(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    if context.legal_entity_service.legal_entity_entity.cryptographic_salt is None:
        usecase = UpdateOrganisationUsecase(
            organisation_repository=context.organisation_repository,
            logger=context.app_context.logger,
        )
        organisation = usecase.execute(
            organisation_id=organisation_id,
            name=context.legal_entity_service.legal_entity_entity.name,
            cryptographic_salt=uuid.uuid4().hex,
        )
    _, ebsi_did, key_did = await generate_and_store_did_v2(
        context.legal_entity_service.legal_entity_entity.cryptographic_seed,
        salt=context.legal_entity_service.legal_entity_entity.cryptographic_salt,
    )

    resp = {
        "did:ebsi": ebsi_did.did,
        "did:key": key_did.did,
    }

    return web.json_response(resp)


class RegisterOrganisationReq(BaseModel):
    name: constr(min_length=1, max_length=100, strip_whitespace=True)  # type: ignore
    description: Optional[
        constr(min_length=1, max_length=500, strip_whitespace=True)  # type: ignore
    ] = None
    logoUrl: Optional[HttpUrl] = None
    coverImageUrl: Optional[HttpUrl] = None
    location: Optional[
        constr(min_length=1, max_length=500, strip_whitespace=True)  # type: ignore
    ] = None
    webhookUrl: Optional[HttpUrl] = None
    cryptographicSeed: Optional[str] = None


@config_routes.post(
    "/config/organisation", name="handle_config_post_register_organisation"
)  # type: ignore
@v2_inject_request_context(
    raise_exception_if_legal_entity_not_found=False,
    raise_exception_if_not_legal_entity_path_param=False,
)
async def handle_config_post_register_organisation(
    request: Request, context: V2RequestContext
):
    assert context.organisation_repository is not None
    assert context.app_context.logger is not None
    try:
        data = await request.json()
        register_organisation_req = RegisterOrganisationReq(**data)

        usecase = RegisterOrganisationUsecase(
            organisation_repository=context.organisation_repository,
            logger=context.app_context.logger,
        )

        logo_url = str(register_organisation_req.logoUrl)
        cover_image_url = str(register_organisation_req.coverImageUrl)
        webhook_url = str(register_organisation_req.webhookUrl)
        organisation = usecase.execute(
            name=register_organisation_req.name,
            description=register_organisation_req.description,
            logo_url=logo_url,
            cover_image_url=cover_image_url,
            webhook_url=webhook_url,
            location=register_organisation_req.location,
            cryptographic_seed=register_organisation_req.cryptographicSeed,
        )

        return web.json_response(organisation.to_dict())
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


@config_routes.get(
    "/config/organisation/{organisationId}",
    name="handle_config_get_read_organisation",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_get_read_organisation(
    request: Request, context: V2RequestContext
):
    assert context.organisation_repository is not None
    assert context.app_context.logger is not None
    try:
        organisation_id = request.match_info.get("organisationId")
        if organisation_id is None:
            raise web.HTTPBadRequest(reason="Invalid organisation id")

        usecase = ReadOrganisationUsecase(
            organisation_repository=context.organisation_repository,
            logger=context.app_context.logger,
        )

        organisation = usecase.execute(
            id=organisation_id,
        )
        if not organisation:
            raise web.HTTPBadRequest(reason="Organisation not found")

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
    logoUrl: Optional[HttpUrl] = None
    coverImageUrl: Optional[HttpUrl] = None
    location: Optional[
        constr(min_length=1, max_length=500, strip_whitespace=True)  # type: ignore
    ] = None
    webhookUrl: Optional[HttpUrl] = None
    cryptographicSeed: Optional[str] = None


@config_routes.put(
    "/config/organisation/{organisationId}",
    name="handle_config_put_update_organisation",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_put_update_organisation(
    request: Request, context: V2RequestContext
):
    assert context.organisation_repository is not None
    assert context.app_context.logger is not None
    try:
        organisation_id = request.match_info.get("organisationId")
        if organisation_id is None:
            raise web.HTTPBadRequest(reason="Invalid organisation id")

        data = await request.json()
        update_organisation_req = UpdateOrganisationReq(**data)
        usecase = UpdateOrganisationUsecase(
            organisation_repository=context.organisation_repository,
            logger=context.app_context.logger,
        )

        logo_url = str(update_organisation_req.logoUrl)
        cover_image_url = str(update_organisation_req.coverImageUrl)
        webhook_url = str(update_organisation_req.webhookUrl)
        cryptographic_seed = update_organisation_req.cryptographicSeed
        organisation = usecase.execute(
            organisation_id=organisation_id,
            name=update_organisation_req.name,
            description=update_organisation_req.description,
            logo_url=logo_url,
            cover_image_url=cover_image_url,
            webhook_url=webhook_url,
            location=update_organisation_req.location,
            cryptographic_seed=cryptographic_seed,
        )
        if not organisation:
            raise web.HTTPBadRequest(reason="Organisation not found")

        return web.json_response(organisation.to_dict())
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


@config_routes.delete(
    "/config/organisation/{organisationId}",
    name="handle_config_delete_delete_organisation",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_delete_delete_organisation(
    request: Request, context: V2RequestContext
):
    assert context.organisation_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    usecase = DeleteOrganisationUsecase(
        organisation_repository=context.organisation_repository,
        logger=context.app_context.logger,
    )

    is_deleted = usecase.execute(
        id=organisation_id,
    )

    if not is_deleted:
        raise web.HTTPBadRequest(reason="Organisation not deleted")
    raise web.HTTPNoContent(reason="Organisation deleted")


class CreateV2DataAgreementReq(BaseModel):
    purpose: constr(min_length=1, strip_whitespace=True)  # type: ignore
    methodOfUse: DataAgreementExchangeModes
    dataAttributes: list
    purposeDescription: constr(min_length=3, strip_whitespace=True)  # type: ignore
    limitedDisclosure: bool
    credentialTypes: Optional[
        conlist(constr(min_length=1, strip_whitespace=True), min_length=1)  # type: ignore
    ] = None


@config_routes.post(
    "/organisation/{organisationId}/config/data-agreement",
    name="handle_post_create_v2_data_agreement",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_post_create_v2_data_agreement(
    request: Request, context: V2RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None
    try:
        organisation_id = request.match_info.get("organisationId")
        if organisation_id is None:
            raise web.HTTPBadRequest(reason="Invalid organisation id")
        data = await request.json()
        create_data_agreement_req = CreateV2DataAgreementReq(**data)
        usecase = CreateV2DataAgreementUsecase(
            dataagreement_repository=context.data_agreement_repository,
            logger=context.app_context.logger,
        )

        data_agreement = usecase.execute(
            organisation_id=organisation_id,
            purpose=create_data_agreement_req.purpose,
            data_attributes=create_data_agreement_req.dataAttributes,
            exchange_mode=create_data_agreement_req.methodOfUse.value,
            credential_types=create_data_agreement_req.credentialTypes,
            purpose_description=create_data_agreement_req.purposeDescription,
            limited_disclosure=create_data_agreement_req.limitedDisclosure,
        )
        return web.json_response(data_agreement.to_dict(), status=201)
    except CreateDataAgreementUsecaseError as e:
        raise web.HTTPBadRequest(reason=e)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


@config_routes.get(
    "/organisation/{organisationId}/config/data-agreement/{dataAgreementId}",
    name="handle_config_get_read_data_agreement",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_get_read_data_agreement(
    request: Request, context: V2RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    data_agreement_id = request.match_info.get("dataAgreementId")
    if data_agreement_id is None:
        raise web.HTTPBadRequest(reason="Invalid data agreement id")

    usecase = V2GetDataAgreementByIdUsecase(
        dataagreement_repository=context.data_agreement_repository,
        logger=context.app_context.logger,
    )
    data_agreement = usecase.execute(
        organisation_id=organisation_id, data_agreement_id=data_agreement_id
    )
    if not data_agreement:
        raise web.HTTPBadRequest(reason="Data agreement not found")

    return web.json_response(data_agreement.to_dict(), status=200)


class UpdateDataAgreementReq(BaseModel):
    purpose: constr(min_length=1, strip_whitespace=True)  # type: ignore
    methodOfUse: DataAgreementExchangeModes
    dataAttributes: list
    purposeDescription: constr(min_length=3, strip_whitespace=True)  # type: ignore
    limitedDisclosure: bool
    credentialTypes: Optional[
        conlist(constr(min_length=1, strip_whitespace=True), min_length=1)  # type: ignore
    ] = None


@config_routes.put(
    "/organisation/{organisationId}/config/data-agreement/{dataAgreementId}",
    name="handle_config_put_update_data_agreement",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_put_update_data_agreement(
    request: Request, context: V2RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    data_agreement_id = request.match_info.get("dataAgreementId")
    if data_agreement_id is None:
        raise web.HTTPBadRequest(reason="Invalid data agreement id")

    try:
        data = await request.json()
        update_data_agreement_req = UpdateDataAgreementReq(**data)
        usecase = UpdateDataAgreementUsecase(
            dataagreement_repository=context.data_agreement_repository,
            logger=context.app_context.logger,
        )

        data_agreement = usecase.execute(
            id=data_agreement_id,
            organisation_id=organisation_id,
            purpose=update_data_agreement_req.purpose,
            data_attributes=update_data_agreement_req.dataAttributes,
            exchange_mode=update_data_agreement_req.methodOfUse.value,
            credential_types=update_data_agreement_req.credentialTypes,
            purpose_description=update_data_agreement_req.purposeDescription,
            limited_disclosure=update_data_agreement_req.limitedDisclosure,
        )
        return web.json_response(data_agreement.to_dict(), status=201)
    except CreateDataAgreementUsecaseError as e:
        raise web.HTTPBadRequest(reason=e)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid request payload")


@config_routes.delete(
    "/organisation/{organisationId}/config/data-agreement/{dataAgreementId}",
    name="handle_config_delete_delete_data_agreement",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_delete_delete_data_agreement(
    request: Request, context: V2RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    data_agreement_id = request.match_info.get("dataAgreementId")
    if data_agreement_id is None:
        raise web.HTTPBadRequest(reason="Invalid data agreement id")

    usecase = V2DeleteDataAgreementUsecase(
        dataagreement_repository=context.data_agreement_repository,
        logger=context.app_context.logger,
    )
    is_deleted = usecase.execute(
        organisation_id=organisation_id, data_agreement_id=data_agreement_id
    )
    if not is_deleted:
        raise web.HTTPBadRequest(reason="Data agreement not deleted")
    raise web.HTTPNoContent(reason="Data agreement deleted")


@config_routes.get(
    "/organisation/{organisationId}/config/data-agreements",
    name="handle_config_get_list_all_data_agreements",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_get_list_all_data_agreements(
    request: Request, context: V2RequestContext
):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    usecase = V2ListAllDataAgreementsUsecase(
        dataagreement_repository=context.data_agreement_repository,
        logger=context.app_context.logger,
    )
    data_agreements = usecase.execute(organisation_id=organisation_id)
    return web.json_response(
        [data_agreement.to_dict() for data_agreement in data_agreements]
    )


class CreateDataSourceIssueCredentialReq(BaseModel):
    issuanceMode: CredentialIssuanceModes
    isPreAuthorised: bool = False
    dataAttributeValues: Optional[list] = None
    userPin: Optional[
        constr(min_length=4, max_length=4, pattern="^[0-9]{4}$", strip_whitespace=True)  # type: ignore
    ] = None
    dataAgreementId: Optional[constr(min_length=3, strip_whitespace=True)] = None  # type: ignore
    limitedDisclosure: Optional[bool] = None
    credential: Optional[dict] = None
    disclosureMapping: Optional[dict] = None


@config_routes.post(
    "/organisation/{organisationId}/config/issue-credential",
    name="handle_post_issue_credential",
)  # type: ignore
@v2_inject_request_context()
async def handle_post_issue_credential(request: Request, context: V2RequestContext):
    assert context.data_agreement_repository is not None
    assert context.app_context.logger is not None

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    data = await request.json()
    issue_credential_req = CreateDataSourceIssueCredentialReq(**data)
    data_agreement_id = issue_credential_req.dataAgreementId
    credential = issue_credential_req.credential
    disclosure_mapping = issue_credential_req.disclosureMapping
    issuance_mode = issue_credential_req.issuanceMode

    try:
        if data_agreement_id:
            with context.data_agreement_repository as repo:
                data_agreement_model = repo.get_by_id_and_organisation_id(
                    organisation_id=organisation_id, id=data_agreement_id
                )
                if not data_agreement_model:
                    raise IssueCredentialError(
                        f"Credential schema with id {data_agreement_id} not found"
                    )
                try:
                    if issue_credential_req.dataAttributeValues:
                        is_valid_data_attribute_values = validate_data_attribute_schema_against_data_attribute_values(
                            data_agreement_model.dataAttributes,
                            issue_credential_req.dataAttributeValues,
                        )
                except ValueError as e:
                    error_message = str(e)
                    return web.json_response({"error": error_message}, status=400)
            if (
                data_agreement_model.methodOfUse
                == DataAgreementExchangeModes.DataSource.value
            ):
                credential_offer = (
                    await context.legal_entity_service.issue_credential_record(
                        data_agreement_id=data_agreement_id,
                        data_attribute_values=(
                            issue_credential_req.dataAttributeValues
                            if issue_credential_req.dataAttributeValues
                            else None
                        ),
                        issuance_mode=issue_credential_req.issuanceMode,
                        is_pre_authorised=issue_credential_req.isPreAuthorised,
                        user_pin=issue_credential_req.userPin,
                        organisation_id=organisation_id,
                        limited_disclosure=(
                            issue_credential_req.limitedDisclosure
                            if issue_credential_req.limitedDisclosure
                            else False
                        ),
                    )
                )
                credentialExchangeId = credential_offer["id"]
                issuer_domain = context.legal_entity_service.issuer_domain
                openid_credential_offer_uri = f"openid-credential-offer://?credential_offer_uri={issuer_domain}/organisation/{organisation_id}/service/credential-offer/{credentialExchangeId}"
                credential_offer["credentialOffer"] = openid_credential_offer_uri

            else:
                raise ValidationError(
                    f"Data agreement method of use is not data source"
                )

        else:
            assert credential.get("type", []) is not None
            # credential = validate_credential_type_based_on_disclosure_mapping(
            #     credential=credential, disclosure_mapping=disclosure_mapping
            # )
            credential_offer = await context.legal_entity_service.issue_credential_with_disclosure_mapping(
                issuance_mode=issue_credential_req.issuanceMode,
                is_pre_authorised=issue_credential_req.isPreAuthorised,
                user_pin=issue_credential_req.userPin,
                organisation_id=organisation_id,
                credential=credential,
                disclosureMapping=disclosure_mapping,
            )
            credentialExchangeId = credential_offer["id"]
            issuer_domain = context.legal_entity_service.issuer_domain
            openid_credential_offer_uri = f"openid-credential-offer://?credential_offer_uri={issuer_domain}/organisation/{organisation_id}/service/credential-offer/{credentialExchangeId}"
            credential_offer["credentialOffer"] = openid_credential_offer_uri

            # FIXME: Dyanmically create credential label from credential type
            credential_offer["credentialLabel"] = credential.get("type", [])[
                -1
            ].removesuffix("SdJwt")
        return web.json_response(credential_offer, status=201)
    except ValidateDataAttributeValuesAgainstDataAttributesError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UserPinRequiredError as e:
        raise web.HTTPBadRequest(text=str(e))
    except IssueCredentialError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid JSON")


class UpdateCredentialOfferReq(BaseModel):
    dataAttributeValues: Optional[list] = None
    dataAgreementId: Optional[constr(min_length=3, strip_whitespace=True)] = None  # type: ignore
    limitedDisclosure: Optional[bool] = None
    credential: Optional[dict] = None
    disclosureMapping: Optional[dict] = None


@config_routes.put(
    "/organisation/{organisationId}/config/credential-offer/{credentialOfferId}",
    name="handle_service_put_update_credential_offer",
)
@v2_inject_request_context()
async def handle_service_put_update_credential_offer(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    credential_offer_id = request.match_info.get("credentialOfferId")
    data = await request.json()
    update_credential_offer_req = UpdateCredentialOfferReq(**data)
    data_agreement_id = update_credential_offer_req.dataAgreementId
    credential = update_credential_offer_req.credential
    disclosure_mapping = update_credential_offer_req.disclosureMapping

    try:
        if credential:
            credential_offer = await context.legal_entity_service.update_deferred_credential_offer_with_disclosure_mapping(
                credential_offer_id=credential_offer_id,
                credential=credential,
                disclosureMapping=disclosure_mapping,
            )
            # FIXME: Dyanmically create credential label from credential type
            credential_offer["credentialLabel"] = (
                credential_offer.get("credential", {})
                .get("type", [])[-1]
                .removesuffix("SdJwt")
            )
            return web.json_response(credential_offer)
        else:
            with context.data_agreement_repository as repo:
                data_agreement_model = repo.get_by_id_and_organisation_id(
                    organisation_id=organisation_id, id=data_agreement_id
                )
                if not data_agreement_model:
                    raise CreateCredentialOfferError(
                        f"Credential schema with id {data_agreement_id} not found"
                    )

                try:
                    is_valid_data_attribute_values = (
                        validate_data_attribute_schema_against_data_attribute_values(
                            data_agreement_model.dataAttributes,
                            update_credential_offer_req.dataAttributeValues,
                        )
                    )
                except ValueError as e:
                    error_message = str(e)
                    return web.json_response({"error": error_message}, status=400)

            if (
                data_agreement_model.methodOfUse
                == DataAgreementExchangeModes.DataSource.value
            ):
                credential_offer = await context.legal_entity_service.update_deferred_credential_offer_with_data_attribute_values(
                    credential_offer_id=credential_offer_id,
                    data_agreement_id=data_agreement_id,
                    data_attribute_values=update_credential_offer_req.dataAttributeValues,
                    limited_disclosure=update_credential_offer_req.limitedDisclosure,
                )

                return web.json_response(credential_offer)
            else:
                raise web.HTTPBadRequest(
                    text=str("Data agreement method of use must be data-source")
                )
    except ValidateDataAttributeValuesAgainstDataAttributesError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UpdateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except json.decoder.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Invalid JSON")


@config_routes.get(
    "/organisation/{organisationId}/config/credential-offer/{credentialOfferId}",
    name="handle_config_get_credential_offer_by_id_and_credential_schema_id",
)
@v2_inject_request_context()
async def handle_config_get_credential_offer_by_id_and_credential_schema_id(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    credential_offer_id = request.match_info.get("credentialOfferId")
    if credential_offer_id is None:
        raise web.HTTPBadRequest(reason="Invalid credential offer id")

    credential_offer_entity = (
        await context.legal_entity_service.get_credential_offer_by_id(
            credential_offer_id=credential_offer_id,
        )
    )

    if credential_offer_entity is None:
        raise web.HTTPBadRequest(text="Credential offer not found")

    # FIXME: Dyanmically create credential label from credential type
    credential_offer_entity["credentialLabel"] = (
        credential_offer_entity.get("credential", {})
        .get("type", [])[-1]
        .removesuffix("SdJwt")
    )

    return web.json_response(credential_offer_entity.to_dict())


@config_routes.get(
    "/organisation/{organisationId}/config/credential-offers",
    name="handle_config_get_all_credential_offers",
)
@v2_inject_request_context()
async def handle_config_get_all_credential_offers(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    data_agreement_id = request.query.get("dataAgreementId")
    if data_agreement_id:
        credential_offers = await context.legal_entity_service.get_all_credential_offers_by_data_agreement_id(
            data_agreement_id=data_agreement_id
        )
    else:
        credential_offers = await context.legal_entity_service.get_all_credential_offers_by_organisation_id(
            organisation_id=organisation_id
        )

    # FIXME: Dyanmically create credential label from credential type
    return web.json_response(
        [
            {
                **credential_offer_entity.to_dict(),
                "credentialLabel": credential_offer_entity.to_dict().get("credential", {})
                .get("type", [])[-1]
                .removesuffix("SdJwt"),
            }
            for credential_offer_entity in credential_offers
        ]
    )


@config_routes.delete(
    "/organisation/{organisationId}/config/credential-offer/{credentialOfferId}",
    name="handle_config_delete_credential_offer",
)
@v2_inject_request_context()
async def handle_config_delete_credential_offer(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    credential_offer_id = request.match_info.get("credentialOfferId")

    is_deleted = await context.legal_entity_service.delete_credential_offer(
        credential_offer_id=credential_offer_id, organisation_id=organisation_id
    )
    if is_deleted:
        return web.HTTPNoContent()
    else:
        return web.HTTPBadRequest(text="Credential offer not deleted")


class CreateVerificationReq(BaseModel):
    presentationDefinition: Optional[dict] = None
    requestByReference: bool = False


@config_routes.post(
    "/organisation/{organisationId}/config/verification/send",
    name="handle_post_create_verification_request",
)  # type: ignore
@v2_inject_request_context()
async def handle_post_create_verification_request(
    request: Request, context: V2RequestContext
):
    assert context.app_context.db_session is not None
    assert context.app_context.logger is not None
    assert context.app_context.domain is not None
    assert context.legal_entity_service is not None
    repository = SqlAlchemyVerificationRecordRepository(
        session=context.app_context.db_session, logger=context.app_context.logger
    )

    # Validate organisation ID in the path parameter
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    try:
        data = await request.json()
        request_body = CreateVerificationReq(**data)

        # Validate presentation definition
        validate_and_deserialise_presentation_definition(
            presentation_definition=request_body.presentationDefinition
        )

        usecase = CreateVerificationRequestUsecase(
            repository=repository,
            logger=context.app_context.logger,
        )

        _, verification_record = usecase.execute(
            key_did=context.legal_entity_service.key_did,
            domain=context.app_context.domain,
            organisation_id=organisation_id,
            presentation_definition=request_body.presentationDefinition,
            requestByReference=request_body.requestByReference,
            webhook_url=context.legal_entity_service.legal_entity_entity.webhook_url,
        )
        return web.json_response(verification_record.to_dict())
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except PresentationDefinitionValidationError as e:
        raise web.HTTPBadRequest(reason=str(e))


@config_routes.get(
    "/organisation/{organisationId}/config/verification/history/{verificationRecordId}",
    name="handle_get_read_verification_history",
)  # type: ignore
@v2_inject_request_context()
async def handle_get_read_verification_history(
    request: Request, context: V2RequestContext
):
    assert context.app_context.db_session is not None
    assert context.app_context.logger is not None
    assert context.app_context.domain is not None
    assert context.legal_entity_service is not None
    repository = SqlAlchemyVerificationRecordRepository(
        session=context.app_context.db_session, logger=context.app_context.logger
    )
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation ID")

    verification_record_id = request.match_info.get("verificationRecordId")
    if verification_record_id is None:
        raise web.HTTPBadRequest(reason="Invalid verification record ID")

    try:
        usecase = ReadVerificationRequestUsecase(
            repository=repository,
            logger=context.app_context.logger,
        )

        verification_record = usecase.execute(
            verification_record_id=verification_record_id
        )
        return web.json_response(verification_record.to_dict())
    except ReadVerificationRequestUsecaseError as e:
        raise web.HTTPBadRequest(reason=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except PresentationDefinitionValidationError as e:
        raise web.HTTPBadRequest(reason=str(e))


@config_routes.delete(
    "/organisation/{organisationId}/config/verification/history/{verificationRecordId}",
    name="handle_delete_verification_history",
)  # type: ignore
@v2_inject_request_context()
async def handle_delete_verification_history(
    request: Request, context: V2RequestContext
):
    assert context.app_context.db_session is not None
    assert context.app_context.logger is not None
    assert context.app_context.domain is not None
    assert context.legal_entity_service is not None
    repository = SqlAlchemyVerificationRecordRepository(
        session=context.app_context.db_session, logger=context.app_context.logger
    )
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation ID")

    verification_record_id = request.match_info.get("verificationRecordId")
    if verification_record_id is None:
        raise web.HTTPBadRequest(reason="Invalid verification record ID")

    try:
        usecase = DeleteVerificationRequestUsecase(
            repository=repository,
            logger=context.app_context.logger,
        )

        usecase.execute(
            organisation_id=organisation_id,
            verification_record_id=verification_record_id,
        )
        return web.json_response(status=204)
    except DeleteVerificationRequestUsecaseError as e:
        raise web.HTTPBadRequest(reason=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except PresentationDefinitionValidationError as e:
        raise web.HTTPBadRequest(reason=str(e))


@config_routes.get(
    "/organisation/{organisationId}/config/verification/history",
    name="handle_list_verification_history",
)  # type: ignore
@v2_inject_request_context()
async def handle_list_verification_history(request: Request, context: V2RequestContext):
    assert context.app_context.db_session is not None
    assert context.app_context.logger is not None
    assert context.app_context.domain is not None
    assert context.legal_entity_service is not None
    repository = SqlAlchemyVerificationRecordRepository(
        session=context.app_context.db_session, logger=context.app_context.logger
    )
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation ID")

    try:
        usecase = ListVerificationRequestUsecase(
            repository=repository,
            logger=context.app_context.logger,
        )

        verification_records = usecase.execute(
            organisation_id=organisation_id,
        )
        return web.json_response(
            [
                verification_record.to_dict()
                for verification_record in verification_records
            ]
        )
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except PresentationDefinitionValidationError as e:
        raise web.HTTPBadRequest(reason=str(e))


@config_routes.post(
    "/config/digital-wallet/openid", name="handle_config_post_deploy_openid"
)  # type: ignore
@v2_inject_request_context(
    raise_exception_if_legal_entity_not_found=False,
    raise_exception_if_not_legal_entity_path_param=False,
)
async def handle_config_post_deploy_openid(request: Request, context: V2RequestContext):
    return await handle_config_post_register_organisation(request)


@config_routes.get(
    "/organisation/{organisationId}/config/digital-wallet/openid",
    name="handle_config_read_openid_deployment",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_read_openid_deployment(
    request: Request, context: V2RequestContext
):
    return await handle_config_get_read_organisation(request)


@config_routes.put(
    "/organisation/{organisationId}/config/digital-wallet/openid",
    name="handle_config_put_update_openid_digital_wallet",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_put_update_openid_digital_wallet(
    request: Request, context: V2RequestContext
):
    return await handle_config_put_update_organisation(request)


@config_routes.delete(
    "/organisation/{organisationId}/config/digital-wallet/openid",
    name="handle_config_delete_openid_deployment",
)  # type: ignore
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_config_delete_openid_deployment(
    request: Request, context: V2RequestContext
):
    return await handle_config_delete_delete_organisation(request)


@config_routes.get(
    "/organisation/{organisationId}/config/digital-wallet/openid/organisation-identifier",
    name="handle_config_read__openid_organisation_identifier",
)
@v2_inject_request_context()
async def handle_config_read__openid_organisation_identifier(
    request: Request, context: V2RequestContext
):
    return await handle_config_get_organisation_identifier(request)


@config_routes.post(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/credential/issue",
    name="handle_post_issue_credential_v2",
)  # type: ignore
@v2_inject_request_context()
async def handle_post_issue_credential_v2(request: Request, context: V2RequestContext):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    issue_credential_response = await handle_post_issue_credential(request)

    issue_credential_response_dict = json.loads(issue_credential_response._body)
    credentialExchangeId = issue_credential_response_dict.get("id")
    issue_credential_response_dict["credentialExchangeId"] = credentialExchangeId

    issuer_domain = context.legal_entity_service.issuer_domain
    openid_credential_offer_uri = f"openid-credential-offer://?credential_offer_uri={issuer_domain}/organisation/{organisation_id}/service/digital-wallet/openid/sdjwt/credential/history/{credentialExchangeId}"
    issue_credential_response_dict["credentialOffer"] = openid_credential_offer_uri

    credential_history = {"credentialHistory": issue_credential_response_dict}
    updated_issue_credential_response_dict = json.dumps(credential_history)
    issue_credential_response._body = updated_issue_credential_response_dict.encode(
        "utf-8"
    )
    return issue_credential_response


@config_routes.put(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/credential/history/{credentialOfferId}",
    name="handle_config_update_credential_history",
)
@v2_inject_request_context()
async def handle_config_update_credential_history(
    request: Request, context: V2RequestContext
):
    update_credential_history_response = (
        await handle_service_put_update_credential_offer(request)
    )

    update_credential_history_dict = json.loads(
        update_credential_history_response._body
    )
    update_credential_history_dict["credentialExchangeId"] = (
        update_credential_history_dict.get("id")
    )
    credential_history = {"credentialHistory": update_credential_history_dict}
    updated_update_credential_history_dict = json.dumps(credential_history)
    update_credential_history_response._body = (
        updated_update_credential_history_dict.encode("utf-8")
    )
    return update_credential_history_response


@config_routes.get(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/credential/history/{credentialOfferId}",
    name="handle_config_read_credential_history",
)
@v2_inject_request_context()
async def handle_config_read_credential_history(
    request: Request, context: V2RequestContext
):
    read_credential_history_resp = (
        await handle_config_get_credential_offer_by_id_and_credential_schema_id(request)
    )

    read_credential_history_dict = json.loads(read_credential_history_resp._body)
    read_credential_history_dict["credentialExchangeId"] = (
        read_credential_history_dict.get("id")
    )
    credential_history = {"credentialHistory": read_credential_history_dict}
    updated_read_credential_history_dict = json.dumps(credential_history)
    read_credential_history_resp._body = updated_read_credential_history_dict.encode(
        "utf-8"
    )

    return read_credential_history_resp


@config_routes.delete(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/credential/history/{credentialOfferId}",
    name="handle_config_delete_credential_history",
)
@v2_inject_request_context()
async def handle_config_delete_credential_history(
    request: Request, context: V2RequestContext
):
    return await handle_config_delete_credential_offer(request)


@config_routes.get(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/credential/history",
    name="handle_config_list_credential_history",
)
@v2_inject_request_context()
async def handle_config_list_credential_history(
    request: Request, context: V2RequestContext
):
    response_body = await handle_config_get_all_credential_offers(request)
    credential_histories = json.loads(response_body._body)
    for credential_history in credential_histories:
        credential_history["credentialExchangeId"] = credential_history.get("id")
    credential_history = {"credentialHistory": credential_histories}
    updated_credential_histories = json.dumps(credential_history)
    response_body._body = updated_credential_histories.encode("utf-8")
    return response_body


@config_routes.post(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/verification/send",
    name="handle_config_send_verification_request",
)
@v2_inject_request_context()
async def handle_config_send_verification_request(
    request: Request, context: V2RequestContext
):
    assert context.app_context.db_session is not None
    assert context.app_context.logger is not None
    assert context.app_context.domain is not None
    assert context.legal_entity_service is not None
    repository = SqlAlchemyVerificationRecordRepository(
        session=context.app_context.db_session, logger=context.app_context.logger
    )

    # Validate organisation ID in the path parameter
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    try:
        data = await request.json()
        request_body = CreateVerificationReq(**data)

        # Validate presentation definition
        validate_and_deserialise_presentation_definition(
            presentation_definition=request_body.presentationDefinition
        )

        usecase = CreateVerificationRequestUsecaseV2(
            repository=repository,
            logger=context.app_context.logger,
        )

        _, verification_record = usecase.execute(
            key_did=context.legal_entity_service.key_did,
            domain=context.app_context.domain,
            organisation_id=organisation_id,
            presentation_definition=request_body.presentationDefinition,
            requestByReference=request_body.requestByReference,
            webhook_url=context.legal_entity_service.legal_entity_entity.webhook_url,
        )

        verification_record_dict = verification_record.to_dict()
        verification_record_dict["presentationExchangeId"] = (
            verification_record_dict.get("id")
        )
        verification_history = {"verificationHistory": verification_record_dict}
        return web.json_response(verification_history)
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))
    except PresentationDefinitionValidationError as e:
        raise web.HTTPBadRequest(reason=str(e))


@config_routes.get(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/verification/history/{verificationRecordId}",
    name="handle_config_read_verification_history",
)  # type: ignore
@v2_inject_request_context()
async def handle_config_read_verification_history(
    request: Request, context: V2RequestContext
):
    response_body = await handle_get_read_verification_history(request=request)
    read_verification_history_dict = json.loads(response_body._body)
    read_verification_history_dict["presentationExchangeId"] = (
        read_verification_history_dict.get("id")
    )
    verification_history = {"verificationHistory": read_verification_history_dict}
    updated_read_verification_history_dict = json.dumps(verification_history)
    response_body._body = updated_read_verification_history_dict.encode("utf-8")
    return response_body


@config_routes.delete(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/verification/history/{verificationRecordId}",
    name="handle_config_delete_verification_history",
)  # type: ignore
@v2_inject_request_context()
async def handle_config_delete_verification_history(
    request: Request, context: V2RequestContext
):
    return await handle_delete_verification_history(request=request)


@config_routes.get(
    "/organisation/{organisationId}/config/digital-wallet/openid/sdjwt/verification/history",
    name="handle_config_list_verification_history",
)  # type: ignore
@v2_inject_request_context()
async def handle_config_list_verification_history(
    request: Request, context: V2RequestContext
):
    response_body = await handle_list_verification_history(request=request)
    verification_histories = json.loads(response_body._body)
    for verification_history in verification_histories:
        verification_history["presentationExchangeId"] = verification_history.get("id")
    verification_history = {"verificationHistory": verification_histories}
    updated_verification_histories = json.dumps(verification_history)
    response_body._body = updated_verification_histories.encode("utf-8")
    return response_body

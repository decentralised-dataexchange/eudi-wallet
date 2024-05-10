import json
from typing import List, Optional

from aiohttp import web
from aiohttp.web_request import Request
from pydantic import BaseModel, Field, ValidationError, constr

from eudi_wallet.ebsi.entry_points.server.decorators import (
    V2RequestContext,
    v2_inject_request_context,
)
from eudi_wallet.ebsi.entry_points.server.v2_well_known import (
    service_get_well_known_openid_credential_issuer_config,
    service_get_well_known_authn_openid_config,
    service_get_well_known_openid_credential_issuer_config_v2,
    service_get_well_known_authn_openid_config_v2,
)
from eudi_wallet.ebsi.utils.jwt import decode_header_and_claims_in_jwt
from eudi_wallet.ebsi.exceptions.application.organisation import (
    CreateAccessTokenError,
    CredentialOfferIsPreAuthorizedError,
    CredentialOfferNotFoundError,
    InvalidStateInIDTokenResponseError,
    UpdateCredentialOfferError,
)
from eudi_wallet.ebsi.value_objects.domain.authn import (
    AuthorisationGrants,
    AuthorizationRequestQueryParams,
)
from eudi_wallet.ebsi.exceptions.domain.authn import (
    InvalidAcceptanceTokenError,
    InvalidAccessTokenError,
)
from eudi_wallet.ebsi.exceptions.domain.issuer import (
    CredentialPendingError,
)
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)
from eudi_wallet.ebsi.usecases.v2.organisation.receive_vp_token_usecase import (
    ReceiveVpTokenUsecase,
)
from eudi_wallet.ebsi.usecases.v2.organisation.read_verification_request_by_reference import (
    ReadVerificationRequestByReferenceUsecase,
    ReadVerificationRequestByReferenceUsecaseError,
)
from eudi_wallet.holder.core import process_credential_offer_and_receive_credential

service_routes = web.RouteTableDef()


@service_routes.get(
    "/organisation/{organisationId}/service/credential-offer/{credential_offer_id}",
    name="handle_get_credential_record_by_reference",
)
@v2_inject_request_context()
async def handle_get_credential_record_by_reference(
    request: Request, context: V2RequestContext
):
    credential_offer_id = request.match_info.get("credential_offer_id")

    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    try:
        credential_offer_response = await context.legal_entity_service.get_credential_offer_record_by_reference_using_credential_offer_uri(
            credential_offer_id=credential_offer_id, organisation_id=organisation_id
        )
    except CredentialOfferNotFoundError as e:
        raise web.HTTPBadRequest(text=str(e))

    return web.json_response(credential_offer_response)


@service_routes.get(
    "/organisation/{organisationId}/service/verification/{verification_record_id}",
    name="handle_get_verification_request_by_reference",
)
@v2_inject_request_context()
async def handle_get_verification_request_by_reference(
    request: Request, context: V2RequestContext
):
    assert context.app_context.db_session is not None
    assert context.app_context.logger is not None
    assert context.app_context.domain is not None
    assert context.legal_entity_service is not None
    repository = SqlAlchemyVerificationRecordRepository(
        session=context.app_context.db_session, logger=context.app_context.logger
    )

    verification_record_id = request.match_info.get("verification_record_id")
    if verification_record_id is None:
        raise web.HTTPBadRequest(reason="Invalid verification record ID")
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation ID")

    try:
        usecase = ReadVerificationRequestByReferenceUsecase(
            repository=repository,
            logger=context.app_context.logger,
        )

        verification_record = usecase.execute(
            verification_record_id=verification_record_id,
            webhook_url=context.legal_entity_service.legal_entity_entity.webhook_url,
        )
        return web.Response(
            text=verification_record.vp_token_request, content_type="application/jwt"
        )
    except ReadVerificationRequestByReferenceUsecaseError as e:
        raise web.HTTPBadRequest(text=str(e))


@service_routes.get(
    "/organisation/{organisationId}/service/.well-known/openid-credential-issuer",
    name="handle_service_get_well_known_openid_credential_issuer_configuration",
)
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_service_get_well_known_openid_credential_issuer_configuration(
    request: Request,
    context: V2RequestContext,
):
    assert context.app_context.db_session is not None
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")
    
    res = service_get_well_known_openid_credential_issuer_config(
        wallet_domain=context.app_context.domain,
        organisation_id=organisation_id,
        logger=context.app_context.logger,
        session=context.app_context.db_session,
        legal_entity_repository=context.organisation_repository,
    )
    return web.json_response(res)


@service_routes.get(
    "/organisation/{organisationId}/service/.well-known/oauth-authorization-server",
    name="handle_service_get_well_known_oauth_authorization_server",
)
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_service_get_well_known_oauth_authorization_server(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    res = service_get_well_known_authn_openid_config(
        context.app_context.domain, organisation_id=organisation_id
    )
    return web.json_response(res)


@service_routes.get(
    "/organisation/{organisationId}/service/.well-known/openid-configuration",
    name="handle_service_get_well_known_openid_configuration",
)
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_service_get_well_known_openid_configuration(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    res = service_get_well_known_authn_openid_config(
        context.app_context.domain, organisation_id=organisation_id
    )
    return web.json_response(res)


@service_routes.get(
    "/organisation/{organisationId}/service/authorize",
    name="handle_service_get_authorize",
)
@v2_inject_request_context()
async def handle_service_get_authorize(request: Request, context: V2RequestContext):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

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
    request = auth_req.request

    try:
        # TODO: Credential offers should be accessed only once.
        # TODO: If client_id is present then check if it matches.
        credential_offer_entity = await context.legal_entity_service.v2_update_credential_offer_from_authorisation_request(
            issuer_state=issuer_state,
            authorisation_request_state=state,
            client_id=client_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_uri=redirect_uri,
            authn_request=request,
        )
        if not credential_offer_entity:
            raise web.HTTPBadRequest(text="Credential offer not found")

        if authorisation_request:
            authn_req_decoded = decode_header_and_claims_in_jwt(authorisation_request)
            client_metadata = authn_req_decoded.claims.get("client_metadata")
        else:
            client_metadata = json.loads(auth_req.client_metadata)

        # FIXME: Handle vp token
        if scope == "openid ver_test:vp_token":
            raise web.HTTPBadRequest(text="Credential offer doesn't exist")
        else:
            redirect_url = await context.legal_entity_service.v2_prepare_redirect_url_with_id_token_request(
                credential_offer_id=str(credential_offer_entity.id),
                client_metadata=client_metadata,
                organisation_id=organisation_id,
            )
    except CredentialOfferIsPreAuthorizedError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UpdateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))

    response = web.Response(status=302)
    response.headers["Location"] = redirect_url
    return response


class IDTokenResponseReq(BaseModel):
    id_token: Optional[constr(min_length=1, strip_whitespace=True)] = None  # type: ignore
    vp_token: Optional[constr(min_length=1, strip_whitespace=True)] = None  # type: ignore
    presentation_submission: Optional[constr(min_length=1, strip_whitespace=True)] = (  # type: ignore
        None
    )
    state: Optional[constr(min_length=1, strip_whitespace=True)] = None  # type: ignore


@service_routes.post(
    "/organisation/{organisationId}/service/direct_post",
    name="handle_service_post_direct_post",
)
@v2_inject_request_context()
async def handle_service_post_direct_post(request: Request, context: V2RequestContext):
    data = await request.post()

    try:
        id_token_response_req = IDTokenResponseReq(**data)

        if id_token_response_req.id_token is not None:
            redirect_url = await context.legal_entity_service.prepare_redirect_url_with_authorisation_code_and_state_for_id_token(
                id_token_response=id_token_response_req.id_token,
                state=id_token_response_req.state,
            )

            response = web.Response(status=302)
            response.headers["Location"] = redirect_url
            return response
        else:
            assert context.app_context.db_session is not None
            assert context.app_context.logger is not None
            assert context.app_context.domain is not None
            assert context.legal_entity_service is not None
            repository = SqlAlchemyVerificationRecordRepository(
                session=context.app_context.db_session,
                logger=context.app_context.logger,
            )

            organisation_id = request.match_info.get("organisationId")
            if organisation_id is None:
                raise web.HTTPBadRequest(reason="Invalid organisation id")

            usecase = ReceiveVpTokenUsecase(
                repository=repository,
                logger=context.app_context.logger,
            )

            verification_record = usecase.execute(
                organisation_id=organisation_id,
                state=id_token_response_req.state,
                vp_token=id_token_response_req.vp_token,
                presentation_submission={
                    "presentation_submission": json.loads(
                        id_token_response_req.presentation_submission
                    )
                },
                webhook_url=context.legal_entity_service.legal_entity_entity.webhook_url,
            )
            return web.json_response(verification_record.to_dict())

    except InvalidStateInIDTokenResponseError as e:
        raise web.HTTPBadRequest(text=str(e))
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))


class PreAuthorisedCodeTokenReq(BaseModel):
    grant_type: constr(min_length=1, strip_whitespace=True)  # type: ignore
    user_pin: constr(min_length=1, strip_whitespace=True)  # type: ignore
    pre_authorised_code: constr(min_length=1, strip_whitespace=True) = Field(  # type: ignore
        ..., alias="pre-authorized_code"
    )


class TokenReq(BaseModel):
    grant_type: constr(min_length=1, strip_whitespace=True)  # type: ignore
    code: constr(min_length=1, strip_whitespace=True)  # type: ignore
    client_id: constr(min_length=1, strip_whitespace=True)  # type: ignore
    code_verifier: Optional[constr(min_length=1, strip_whitespace=True)] = None  # type: ignore
    client_assertion: Optional[constr(min_length=1, strip_whitespace=True)] = None  # type: ignore
    client_assertion_type: Optional[constr(min_length=1, strip_whitespace=True)] = None  # type: ignore


@service_routes.post(
    "/organisation/{organisationId}/service/token",
    name="handle_service_post_token",
)
@v2_inject_request_context()
async def handle_service_post_token(request: Request, context: V2RequestContext):
    data = await request.post()

    try:
        if (
            data.get("grant_type")
            == AuthorisationGrants.PreAuthorisedCode.value.grant_type
        ):
            token_req = PreAuthorisedCodeTokenReq(**data)
            token = await context.legal_entity_service.v2_create_access_token(
                grant_type=token_req.grant_type,
                user_pin=token_req.user_pin,
                pre_authorised_code=token_req.pre_authorised_code,
            )
        else:
            token_req = TokenReq(**data)
            token = await context.legal_entity_service.v2_create_access_token(
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


class IssueCredentialReqProof(BaseModel):
    proof_type: constr(min_length=1, strip_whitespace=True)  # type: ignore
    jwt: constr(min_length=1, strip_whitespace=True)  # type: ignore


class IssueCredentialReq(BaseModel):
    format: constr(min_length=1, strip_whitespace=True)  # type: ignore
    types: List[constr(min_length=1, strip_whitespace=True)]  # type: ignore
    proof: IssueCredentialReqProof


@service_routes.post(
    "/organisation/{organisationId}/service/credential",
    name="handle_service_post_credential_request",
)
@v2_inject_request_context()
async def handle_service_post_credential_request(
    request: Request, context: V2RequestContext
):
    authn_header = request.headers.get("Authorization")
    access_token = None
    if authn_header:
        access_token = authn_header.split("Bearer ")[1]

    data = await request.json()

    try:
        issue_credential_req = IssueCredentialReq(**data)
        credential_response = await context.legal_entity_service.v2_issue_credential(
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


@service_routes.post(
    "/organisation/{organisationId}/service/credential_deferred",
    name="handle_service_post_credential_deferred_request",
)
@v2_inject_request_context()
async def handle_service_post_credential_deferred_request(
    request: Request, context: V2RequestContext
):
    authn_header = request.headers.get("Authorization")
    acceptance_token = None
    if authn_header:
        acceptance_token = authn_header.split("Bearer ")[1]

    try:
        credential_response = (
            await context.legal_entity_service.v2_issue_deferred_credential(
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


class ResolveCredentialOfferReq(BaseModel):
    offer_uri: constr(min_length=1, strip_whitespace=True)  # type: ignore


@service_routes.post(
    "/organisation/{organisationId}/service/resolve-credential-offer",
    name="handle_service_resolve_credential_offer",
)
@v2_inject_request_context()
async def handle_service_resolve_credential_offer(
    request: Request, context: V2RequestContext
):
    data = await request.json()

    try:
        req = ResolveCredentialOfferReq(**data)
        (
            credential_response,
            deferred_endpoint,
        ) = await process_credential_offer_and_receive_credential(req.offer_uri)
        return web.json_response(
            {
                "acceptance_token": credential_response.acceptance_token,
                "credential": credential_response.credential,
                "deferred_endpoint": deferred_endpoint,
            }
        )
    except ValidationError as e:
        raise web.HTTPBadRequest(reason=json.dumps(e.errors()))


@service_routes.get(
    "/organisation/{organisationId}/service/digital-wallet/openid/sdjwt/credential/history/{credential_offer_id}",
    name="handle_service_read_credential_record_by_reference",
)
@v2_inject_request_context()
async def handle_service_read_credential_record_by_reference(
    request: Request, context: V2RequestContext
):
    credential_record_by_reference = await handle_get_credential_record_by_reference(
        request=request
    )
    credential_record_dict = json.loads(credential_record_by_reference._body)
    old_credential_issuer = credential_record_dict.get("credential_issuer")
    credential_issuer = old_credential_issuer + "/digital-wallet/openid"
    credential_record_dict["credential_issuer"] = credential_issuer
    updated_credential_history_dict = json.dumps(credential_record_dict)

    credential_record_by_reference._body = updated_credential_history_dict.encode(
        "utf-8"
    )

    return credential_record_by_reference


@service_routes.get(
    "/organisation/{organisationId}/service/digital-wallet/openid/sdjwt/verification/history/{verification_record_id}",
    name="handle_service_read_verification_request_by_reference",
)
@v2_inject_request_context()
async def handle_service_read_verification_request_by_reference(
    request: Request, context: V2RequestContext
):
    return await handle_get_verification_request_by_reference(request=request)


@service_routes.get(
    "/organisation/{organisationId}/service/digital-wallet/openid/.well-known/openid-credential-issuer",
    name="handle_service_read_well_known_openid_credential_issuer_configuration_v2",
)
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_service_read_well_known_openid_credential_issuer_configuration_v2(
    request: Request,
    context: V2RequestContext,
):
    assert context.app_context.db_session is not None
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    res = service_get_well_known_openid_credential_issuer_config_v2(
        wallet_domain=context.app_context.domain,
        organisation_id=organisation_id,
        logger=context.app_context.logger,
        session=context.app_context.db_session,
        legal_entity_repository=context.organisation_repository,
    )
    return web.json_response(res)


@service_routes.get(
    "/organisation/{organisationId}/service/digital-wallet/openid/.well-known/oauth-authorization-server",
    name="handle_service_read_well_known_oauth_authorization_server_v2",
)
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_service_read_well_known_oauth_authorization_server_v2(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    res = service_get_well_known_authn_openid_config_v2(
        context.app_context.domain, organisation_id=organisation_id
    )
    return web.json_response(res)


@service_routes.get(
    "/organisation/{organisationId}/service/digital-wallet/openid/.well-known/openid-configuration",
    name="handle_service_read_well_known_openid_configuration_v2",
)
@v2_inject_request_context(raise_exception_if_legal_entity_not_found=False)
async def handle_service_read_well_known_openid_configuration_v2(
    request: Request, context: V2RequestContext
):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

    res = service_get_well_known_authn_openid_config_v2(
        context.app_context.domain, organisation_id=organisation_id
    )
    return web.json_response(res)


@service_routes.get(
    "/organisation/{organisationId}/service/digital-wallet/openid/authorize",
    name="handle_service_read_authorize_v2",
)
@v2_inject_request_context()
async def handle_service_read_authorize_v2(request: Request, context: V2RequestContext):
    organisation_id = request.match_info.get("organisationId")
    if organisation_id is None:
        raise web.HTTPBadRequest(reason="Invalid organisation id")

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
    request = auth_req.request

    try:
        credential_offer_entity = await context.legal_entity_service.v2_update_credential_offer_from_authorisation_request(
            issuer_state=issuer_state,
            authorisation_request_state=state,
            client_id=client_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_uri=redirect_uri,
            authn_request=request,
        )
        if not credential_offer_entity:
            raise web.HTTPBadRequest(text="Credential offer not found")

        if authorisation_request:
            authn_req_decoded = decode_header_and_claims_in_jwt(authorisation_request)
            client_metadata = authn_req_decoded.claims.get("client_metadata")
        else:
            client_metadata = json.loads(auth_req.client_metadata)

        if scope == "openid ver_test:vp_token":
            raise web.HTTPBadRequest(text="Credential offer doesn't exist")
        else:
            redirect_url = await context.legal_entity_service.v2_prepare_redirect_url_with_id_token_request(
                credential_offer_id=str(credential_offer_entity.id),
                client_metadata=client_metadata,
                organisation_id=organisation_id,
                redirect_uri_suffix="service/digital-wallet/openid/direct_post",
            )
    except CredentialOfferIsPreAuthorizedError as e:
        raise web.HTTPBadRequest(text=str(e))
    except UpdateCredentialOfferError as e:
        raise web.HTTPBadRequest(text=str(e))

    response = web.Response(status=302)
    response.headers["Location"] = redirect_url
    return response


@service_routes.post(
    "/organisation/{organisationId}/service/digital-wallet/openid/direct_post",
    name="handle_service_post_direct_post_v2",
)
@v2_inject_request_context()
async def handle_service_post_direct_post_v2(
    request: Request, context: V2RequestContext
):
    return await handle_service_post_direct_post(request=request)


@service_routes.post(
    "/organisation/{organisationId}/service/digital-wallet/openid/token",
    name="handle_service_post_token_v2",
)
@v2_inject_request_context()
async def handle_service_post_token_v2(request: Request, context: V2RequestContext):
    return await handle_service_post_token(request=request)


@service_routes.post(
    "/organisation/{organisationId}/service/digital-wallet/openid/sdjwt/credential",
    name="handle_service_post_credential_request_v2",
)
@v2_inject_request_context()
async def handle_service_post_credential_request_v2(
    request: Request, context: V2RequestContext
):
    return await handle_service_post_credential_request(request=request)


@service_routes.post(
    "/organisation/{organisationId}/service/digital-wallet/openid/sdjwt/credential_deferred",
    name="handle_service_post_credential_deferred_request_v2",
)
@v2_inject_request_context()
async def handle_service_post_credential_deferred_request_v2(
    request: Request, context: V2RequestContext
):
    return await handle_service_post_credential_deferred_request(request=request)


@service_routes.post(
    "/organisation/{organisationId}/service/digital-wallet/openid/sdjwt/credential/resolve-credential-offer",
    name="handle_service_resolve_credential_offer_v2",
)
@v2_inject_request_context()
async def handle_service_resolve_credential_offer_v2(
    request: Request, context: V2RequestContext
):
    return await handle_service_resolve_credential_offer(request=request)

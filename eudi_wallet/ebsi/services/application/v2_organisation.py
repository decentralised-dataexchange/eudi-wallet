import json
import time
import urllib.parse
import uuid
from datetime import datetime
from logging import Logger
from typing import List, Optional, Tuple, Union

from eth_account import Account
from eth_account.signers.local import LocalAccount
from jsonschema import exceptions, validate
from jwcrypto import jwk

from eudi_wallet.ebsi.exceptions.application.organisation import (
    CreateCredentialOfferError,
    CredentialOfferIsPreAuthorizedError,
    CredentialOfferNotFoundError,
    InvalidAuthorisationCodeError,
    InvalidClientError,
    InvalidCodeVerifierError,
    InvalidPreAuthorisedCodeError,
    InvalidStateInIDTokenResponseError,
    InvalidUserPinError,
    UpdateCredentialOfferError,
    UserPinRequiredError,
    CredentialOfferAccessedError,
)
from eudi_wallet.ebsi.exceptions.domain.authn import (
    InvalidAcceptanceTokenError,
    InvalidAccessTokenError,
)
from eudi_wallet.ebsi.exceptions.domain.issuer import (
    CredentialPendingError,
)
from eudi_wallet.ebsi.models.v2.issue_credential_record import (
    IssueCredentialRecordModel,
)
from eudi_wallet.ebsi.models.v2.data_agreement import V2DataAgreementModel
from eudi_wallet.ebsi.models.organisation import OrganisationModel
from eudi_wallet.ebsi.repositories.v2.data_agreement import (
    SqlAlchemyV2DataAgreementRepository,
)
from eudi_wallet.ebsi.repositories.v2.issue_credential_record import (
    SqlAlchemyIssueCredentialRecordRepository,
)
from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository
from eudi_wallet.ebsi.services.domain.authorisation import AuthorisationService
from eudi_wallet.ebsi.services.domain.did_registry import DIDRegistryService
from eudi_wallet.ebsi.services.domain.issuer import IssuerService
from eudi_wallet.ebsi.services.domain.utils.authn import generate_code_challenge
from eudi_wallet.ebsi.services.domain.utils.credential import (
    create_credential_token,
)
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did_v2
from eudi_wallet.ebsi.utils.date_time import generate_ISO8601_UTC
from eudi_wallet.ebsi.utils.jwt import decode_header_and_claims_in_jwt
from eudi_wallet.ebsi.value_objects.application.organisation import (
    DataAgreementExchangeModes,
)
from eudi_wallet.ebsi.value_objects.domain.authn import (
    AuthorisationGrants,
    TokenResponse,
)
from eudi_wallet.ebsi.value_objects.domain.discovery import (
    OpenIDAuthServerConfig,
    OpenIDCredentialIssuerConfig,
)
from eudi_wallet.ebsi.value_objects.domain.issuer import (
    AcceptanceTokenResponse,
    CredentialIssuanceModes,
    CredentialResponse,
    CredentialStatuses,
    CredentialTypes,
    IssuerTrustFrameworks,
    CredentialOfferStatuses,
)
from eudi_wallet.ebsi.utils.webhook import send_webhook

from sdjwt.sdjwt import (
    create_w3c_vc_sd_jwt,
    create_w3c_vc_sd_jwt_for_data_attributes,
    create_w3c_vc_jwt_with_disclosure_mapping,
)
from eudi_wallet.ebsi.utils.common import (
    convert_data_attributes_to_json_schema,
    convert_data_attributes_to_credential,
    convert_data_attributes_raw_list_to_data_attributes_list,
)


class V2OrganisationService:
    def __init__(
        self,
        credential_issuer_configuration: Optional[OpenIDCredentialIssuerConfig] = None,
        auth_server_configuration: Optional[OpenIDAuthServerConfig] = None,
        logger: Optional[Logger] = None,
        issuer_domain: Optional[str] = None,
        auth_domain: Optional[str] = None,
        legal_entity_repository: Optional[SqlAlchemyOrganisationRepository] = None,
        data_agreement_repository: Optional[SqlAlchemyV2DataAgreementRepository] = None,
        issue_credential_record_repository: Optional[
            SqlAlchemyIssueCredentialRecordRepository
        ] = None,
    ):
        self.key_did = None
        self.ebsi_did = None
        self.eth = None
        self.legal_entity_entity = None
        self.credential_issuer_configuration = credential_issuer_configuration
        self.auth_server_configuration = auth_server_configuration
        self.logger = logger
        self.issuer_domain = issuer_domain
        self.auth_domain = auth_domain
        self.legal_entity_repository = legal_entity_repository
        self.data_agreement_repository = data_agreement_repository
        self.issue_credential_record_repository = issue_credential_record_repository
        self.crypto_seed = None

    async def get_legal_entity(
        self, organisation_id: str
    ) -> Union[OrganisationModel, None]:
        assert (
            self.legal_entity_repository is not None
        ), "Legal entity repository not found"
        with self.legal_entity_repository as repo:
            return repo.get_by_id(id=organisation_id)

    async def set_cryptographic_seed(self, crypto_seed: str, salt: str) -> None:
        self.crypto_seed = crypto_seed

        self.eth, self.ebsi_did, self.key_did = await generate_and_store_did_v2(
            crypto_seed=self.crypto_seed, salt=salt
        )

    async def set_entity(
        self,
        legal_entity_entity: Optional[OrganisationModel] = None,
    ) -> None:
        self.legal_entity_entity = legal_entity_entity

    async def issue_credential_with_disclosure_mapping(
        self,
        organisation_id: str,
        issuance_mode: CredentialIssuanceModes = None,
        is_pre_authorised: bool = False,
        user_pin: Optional[str] = None,
        credential: Optional[str] = None,
        disclosureMapping: Optional[dict] = None,
    ) -> dict:
        assert (
            self.issue_credential_record_repository is not None
        ), "Issue credential record repository not found"

        if is_pre_authorised and not user_pin:
            raise UserPinRequiredError(
                "User pin is required for pre-authorised credential offers"
            )

        if issuance_mode.value == CredentialIssuanceModes.InTime and not credential:
            raise CreateCredentialOfferError(
                "Credential is required for in time issuance"
            )

        iat = int(time.time())
        exp = iat + 3600

        with self.issue_credential_record_repository as credential_offer_repo:
            credential_offer_entity = (
                credential_offer_repo.create_without_data_agreement(
                    organisation_id=organisation_id,
                    issuance_mode=issuance_mode.value,
                    is_pre_authorised=is_pre_authorised,
                    user_pin=user_pin,
                    credential_status=(
                        CredentialStatuses.Ready.value
                        if credential.get("credentialSubject")
                        else CredentialStatuses.Pending.value
                    ),
                    status=CredentialOfferStatuses.OfferSent.value,
                    credential=credential,
                    disclosureMapping=disclosureMapping,
                )
            )

            if is_pre_authorised:
                pre_authorised_code = IssuerService.create_pre_authorised_code(
                    iss=self.key_did.did,
                    aud=self.key_did.did,
                    sub=self.key_did.did,
                    iat=iat,
                    nbf=iat,
                    exp=exp,
                    kid=f"{self.key_did.did}#{self.key_did._method_specific_id}",
                    key=self.key_did._key,
                    credential_offer_id=str(credential_offer_entity.id),
                )

                credential_offer_entity = credential_offer_repo.update(
                    id=credential_offer_entity.id,
                    preAuthorisedCode=pre_authorised_code,
                )
            else:
                issuer_state = IssuerService.create_issuer_state(
                    iss=self.key_did.did,
                    aud=self.key_did.did,
                    sub=self.key_did.did,
                    iat=iat,
                    nbf=iat,
                    exp=exp,
                    kid=f"{self.key_did.did}#{self.key_did._method_specific_id}",
                    key=self.key_did._key,
                    credential_offer_id=str(credential_offer_entity.id),
                )

                credential_offer_entity = credential_offer_repo.update(
                    id=credential_offer_entity.id, issuerState=issuer_state
                )
        if self.legal_entity_entity.webhook_url:
            try:
                send_webhook(
                    self.legal_entity_entity.webhook_url,
                    credential_offer_entity.to_dict(),
                )
            except Exception as e:
                self.logger.error("Exception occurred during sending webhook")
        return credential_offer_entity.to_dict()

    async def issue_credential_record(
        self,
        data_agreement_id: str,
        organisation_id: str,
        issuance_mode: CredentialIssuanceModes = None,
        is_pre_authorised: bool = False,
        user_pin: Optional[str] = None,
        data_attribute_values: Optional[list] = None,
        trust_framework: Optional[IssuerTrustFrameworks] = None,
        limited_disclosure: Optional[bool] = False,
    ) -> dict:
        assert (
            self.issue_credential_record_repository is not None
        ), "Issue credential record repository not found"
        assert (
            self.data_agreement_repository is not None
        ), "Data agreement repository not found"

        with self.data_agreement_repository as repo:
            data_agreement_model = repo.get_by_id_and_organisation_id(
                organisation_id=organisation_id, id=data_agreement_id
            )
            if not data_agreement_model:
                raise CreateCredentialOfferError(
                    f"Credential schema with id {data_agreement_id} not found"
                )

        if (
            data_agreement_model.methodOfUse
            == DataAgreementExchangeModes.DataSource.value
        ):
            if is_pre_authorised and not user_pin:
                raise UserPinRequiredError(
                    "User pin is required for pre-authorised credential offers"
                )

            if (
                issuance_mode.value == CredentialIssuanceModes.InTime
                and not data_attribute_values
            ):
                raise CreateCredentialOfferError(
                    "Data attribute values are required for in time issuance"
                )

            if data_attribute_values:
                data_attributes_schema = convert_data_attributes_to_json_schema(
                    data_agreement_model.dataAttributes
                )
                data_attributes_credential = convert_data_attributes_to_credential(
                    data_attribute_values
                )
                data_attributes_credential["id"] = f"urn:did:{str(uuid.uuid4())}"
                try:
                    seconds_in_one_year = 31536000
                    _, issuance_date = generate_ISO8601_UTC()
                    _, expiration_date = generate_ISO8601_UTC(seconds_in_one_year)
                    vc = {
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "id": f"urn:did:{str(uuid.uuid4())}",
                        "type": data_agreement_model.credentialTypes,
                        "issuer": self.key_did.did,
                        "issuanceDate": issuance_date,
                        "validFrom": issuance_date,
                        "expirationDate": expiration_date,
                        "issued": issuance_date,
                        "credentialSubject": data_attributes_credential,
                        "credentialSchema": {
                            "id": "",
                            "type": "FullJsonSchemaValidator2021",
                        },
                    }
                    validate(instance=vc, schema=data_attributes_schema)
                    del data_attributes_credential["id"]
                    validate(
                        instance=data_attributes_credential,
                        schema=data_attributes_schema,
                    )
                except exceptions.ValidationError as e:
                    raise CreateCredentialOfferError(e.message)

            iat = int(time.time())
            exp = iat + 3600

            with self.issue_credential_record_repository as credential_offer_repo:
                credential_offer_entity = credential_offer_repo.create(
                    data_agreement_id=data_agreement_model.id,
                    organisation_id=organisation_id,
                    data_attribute_values=(
                        data_attribute_values if data_attribute_values else None
                    ),
                    issuance_mode=issuance_mode.value,
                    is_pre_authorised=is_pre_authorised,
                    user_pin=user_pin,
                    credential_status=(
                        CredentialStatuses.Ready.value
                        if data_attribute_values
                        else CredentialStatuses.Pending.value
                    ),
                    status=CredentialOfferStatuses.OfferSent.value,
                    limitedDisclosure=limited_disclosure,
                )

                if is_pre_authorised:
                    pre_authorised_code = IssuerService.create_pre_authorised_code(
                        iss=self.key_did.did,
                        aud=self.key_did.did,
                        sub=self.key_did.did,
                        iat=iat,
                        nbf=iat,
                        exp=exp,
                        kid=f"{self.key_did.did}#{self.key_did._method_specific_id}",
                        key=self.key_did._key,
                        credential_offer_id=str(credential_offer_entity.id),
                    )

                    credential_offer_entity = credential_offer_repo.update(
                        id=credential_offer_entity.id,
                        preAuthorisedCode=pre_authorised_code,
                    )
                else:
                    issuer_state = IssuerService.create_issuer_state(
                        iss=self.key_did.did,
                        aud=self.key_did.did,
                        sub=self.key_did.did,
                        iat=iat,
                        nbf=iat,
                        exp=exp,
                        kid=f"{self.key_did.did}#{self.key_did._method_specific_id}",
                        key=self.key_did._key,
                        credential_offer_id=str(credential_offer_entity.id),
                    )

                    credential_offer_entity = credential_offer_repo.update(
                        id=credential_offer_entity.id, issuerState=issuer_state
                    )
            if self.legal_entity_entity.webhook_url:
                try:
                    send_webhook(
                        self.legal_entity_entity.webhook_url,
                        credential_offer_entity.to_dict(),
                    )
                except Exception as e:
                    self.logger.error("Exception occurred during sending webhook")
        else:
            raise exceptions.ValidationError(
                "Data agreement method of use is not data source"
            )
        return credential_offer_entity.to_dict()

    async def get_credential_offer_without_data_agreement(
        self,
        credential_offer_entity,
        organisation_id: str = None,
    ) -> dict:
        # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.3

        credential = credential_offer_entity.credential
        if credential_offer_entity is None:
            raise CredentialOfferNotFoundError(
                f"Credential offer with id {credential_offer_entity.id} not found"
            )
        if credential_offer_entity.isAccessed:
            raise CredentialOfferAccessedError(
                f"Credential offer with id {credential_offer_entity.id} accessed"
            )
        if credential_offer_entity.disclosureMapping:
            format = "vc+sd-jwt"
        else:
            format = "jwt_vc"

        credential_offer_by_reference = {
            "credential_issuer": f"{self.issuer_domain}/organisation/{organisation_id}/service",
            "credentials": [
                {
                    "format": format,
                    "types": (
                        credential.get("type")
                        if credential.get("type")
                        else ["VerifiableCredential"]
                    ),
                    "trust_framework": {
                        "name": "ebsi",
                        "type": "Accreditation",
                        "uri": "TIR link towards accreditation",
                    },
                }
            ],
        }

        if credential_offer_entity.isPreAuthorised:
            credential_offer_by_reference["grants"] = {
                AuthorisationGrants.PreAuthorisedCode.value.grant_type: {
                    AuthorisationGrants.PreAuthorisedCode.value.grant_data: credential_offer_entity.preAuthorisedCode,
                    "user_pin_required": True,
                },
            }
        else:
            credential_offer_by_reference["grants"] = {
                AuthorisationGrants.AuthorisationCode.value.grant_type: {
                    AuthorisationGrants.AuthorisationCode.value.grant_data: credential_offer_entity.issuerState
                }
            }
        return credential_offer_by_reference

    async def get_credential_offer_record_by_reference_using_credential_offer_uri(
        self,
        credential_offer_id: str,
        organisation_id: str = None,
    ) -> dict:
        # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.3

        with self.issue_credential_record_repository as repo:
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            data_agreement_model: V2DataAgreementModel = (
                credential_offer_entity.dataAgreement
            )
            credential_offer_by_reference = {}
            if data_agreement_model is None:
                credential_offer_by_reference = (
                    await self.get_credential_offer_without_data_agreement(
                        credential_offer_entity=credential_offer_entity,
                        organisation_id=organisation_id,
                    )
                )
            else:
                if credential_offer_entity is None:
                    raise CredentialOfferNotFoundError(
                        f"Credential offer with id {credential_offer_id} not found"
                    )
                if credential_offer_entity.isAccessed:
                    raise CredentialOfferAccessedError(
                        f"Credential offer with id {credential_offer_id} accessed"
                    )
                if credential_offer_entity.limitedDisclosure:
                    format = "vc+sd-jwt"
                else:
                    format = "jwt_vc"

                credential_offer_by_reference = {
                    "credential_issuer": f"{self.issuer_domain}/organisation/{organisation_id}/service",
                    "credentials": [
                        {
                            "format": format,
                            "types": data_agreement_model.credentialTypes,
                            "trust_framework": {
                                "name": "ebsi",
                                "type": "Accreditation",
                                "uri": "TIR link towards accreditation",
                            },
                        }
                    ],
                }

                if credential_offer_entity.isPreAuthorised:
                    credential_offer_by_reference["grants"] = {
                        AuthorisationGrants.PreAuthorisedCode.value.grant_type: {
                            AuthorisationGrants.PreAuthorisedCode.value.grant_data: credential_offer_entity.preAuthorisedCode,
                            "user_pin_required": True,
                        },
                    }
                else:
                    credential_offer_by_reference["grants"] = {
                        AuthorisationGrants.AuthorisationCode.value.grant_type: {
                            AuthorisationGrants.AuthorisationCode.value.grant_data: credential_offer_entity.issuerState
                        }
                    }
            credential_offer_entity = repo.update(
                id=credential_offer_entity.id,
                status=CredentialOfferStatuses.OfferReceived.value,
                isAccessed=True,
            )

            if self.legal_entity_entity.webhook_url:
                try:
                    send_webhook(
                        self.legal_entity_entity.webhook_url,
                        credential_offer_entity.to_dict(),
                    )
                except Exception as e:
                    self.logger.error("Exception occurred during sending webhook")
            return credential_offer_by_reference

    async def v2_update_credential_offer_from_authorisation_request(
        self,
        issuer_state: Optional[str] = None,
        authorisation_request_state: Optional[str] = None,
        client_id: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        authn_request: Optional[str] = None,
    ) -> Union[IssueCredentialRecordModel, None]:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"

        if issuer_state:
            issuer_state_decoded = decode_header_and_claims_in_jwt(issuer_state)
            IssuerService.verify_issuer_state(issuer_state, self.key_did._key)

            credential_offer_id = issuer_state_decoded.claims.get("credential_offer_id")

            with self.issue_credential_record_repository as repo:
                credential_offer_entity = repo.get_by_id(credential_offer_id)
                if credential_offer_entity is None:
                    raise UpdateCredentialOfferError(
                        f"Credential offer with id {credential_offer_id} not found"
                    )

                if credential_offer_entity.isPreAuthorised:
                    raise CredentialOfferIsPreAuthorizedError(
                        f"Credential offer with id {credential_offer_id} is already pre-authorized"
                    )

                return repo.update(
                    credential_offer_id,
                    issuerState=issuer_state,
                    authorisationRequestState=authorisation_request_state,
                    clientId=client_id,
                    codeChallenge=code_challenge,
                    codeChallengeMethod=code_challenge_method,
                    redirectUri=redirect_uri,
                )
        else:
            # Search the credential offer by client ID.
            assert client_id is not None, "Client ID not found"
            if authn_request:
                authn_request_decoded = decode_header_and_claims_in_jwt(authn_request)
                authorization_details = authn_request_decoded.claims.get(
                    "authorization_details"
                )
                if len(authorization_details) == 0:
                    raise UpdateCredentialOfferError("Authorization details not found")

                requested_credential_types = authn_request_decoded.claims.get(
                    "authorization_details"
                )[0].get("types")

                with self.issue_credential_record_repository as repo:
                    credential_offers = repo.get_all_by_client_id(client_id)
                    if len(credential_offers) == 0:
                        raise UpdateCredentialOfferError(
                            f"Credential offer with client ID {client_id} not found"
                        )

                    is_credential_offer_found = False
                    for credential_offer_entity in credential_offers:
                        credential_offer_schema: V2DataAgreementModel = (
                            credential_offer_entity.dataAgreement
                        )
                        if (
                            credential_offer_schema.credentialTypes[-1]
                            == requested_credential_types[-1]
                        ):
                            is_credential_offer_found = True
                            break

                    if not is_credential_offer_found:
                        raise UpdateCredentialOfferError(
                            f"Credential offer with client ID {client_id} not found"
                        )
                    credential_offer_entity = repo.update(
                        credential_offer_entity.id,
                        issuerState=issuer_state,
                        authorisationRequestState=authorisation_request_state,
                        clientId=client_id,
                        codeChallenge=code_challenge,
                        codeChallengeMethod=code_challenge_method,
                        redirectUri=redirect_uri,
                    )
                    return credential_offer_entity
            else:
                with self.issue_credential_record_repository as repo:
                    credential_offers = repo.get_all_by_client_id(client_id)
                    if len(credential_offers) == 0:
                        raise UpdateCredentialOfferError(
                            f"Credential offer with client ID {client_id} not found"
                        )
                    credential_offer_entity = credential_offers[0]
                    credential_offer_entity = repo.update(
                        credential_offer_entity.id,
                        issuerState=issuer_state,
                        authorisationRequestState=authorisation_request_state,
                        clientId=client_id,
                        codeChallenge=code_challenge,
                        codeChallengeMethod=code_challenge_method,
                        redirectUri=redirect_uri,
                    )
                    return credential_offer_entity

    async def v2_prepare_redirect_url_with_id_token_request(
        self,
        credential_offer_id: str,
        client_metadata: dict,
        organisation_id: str,
        redirect_uri_suffix: str = None,
    ) -> str:
        assert self.auth_domain is not None, "Auth domain not found"
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"

        iss_service = IssuerService(
            self.credential_issuer_configuration.credential_endpoint,
            logger=self.logger,
        )
        state = str(uuid.uuid4())
        iss = self.auth_domain
        aud = self.key_did.did
        exp = int(time.time()) + 3600
        response_type = "id_token"
        response_mode = "direct_post"
        client_id = f"{self.auth_domain}/organisation/{organisation_id}"
        if redirect_uri_suffix:
            redirect_uri = (
                f"{self.auth_domain}/organisation/{organisation_id}/" + redirect_uri_suffix
            )
        else:
            redirect_uri = (
                f"{self.auth_domain}/organisation/{organisation_id}/service/direct_post"
            )
        scope = "openid"
        # nonce = auth_req.issuer_state
        nonce = str(uuid.uuid4())
        key = self.key_did._key
        key_id = key.key_id
        id_token_request = iss_service.create_id_token_request(
            state=state,
            iss=iss,
            aud=aud,
            exp=exp,
            response_type=response_type,
            response_mode=response_mode,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            key_id=key_id,
            key=key,
        )
        # Save state to credential offer.
        with self.issue_credential_record_repository as repo:
            repo.update(
                id=credential_offer_id,
                idTokenRequestState=state,
                idTokenRequest=id_token_request,
            )
        encoded_params = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "response_type": response_type,
                "scope": scope,
                "redirect_uri": redirect_uri,
                "request": id_token_request,
                "request_uri": f"{self.issuer_domain}/organisation/{organisation_id}/service/request-uri/{credential_offer_id}",
                "response_mode": response_mode,
                "state": state,
            }
        )
        redirection_base_url = client_metadata.get("authorization_endpoint")
        if redirection_base_url:
            redirection_url = f"{redirection_base_url}?{encoded_params}"
        else:
            redirection_url = f"openid:?{encoded_params}"

        return redirection_url

    async def prepare_redirect_url_with_authorisation_code_and_state_for_id_token(
        self,
        id_token_response: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"

        # TODO: Validate id token response by generating JWK from client id.
        # if did:key identifier then obtain from method specific id, else obtain from /jwks endpoint

        # Query credential offer by id_token request state
        with self.issue_credential_record_repository as repo:
            if id_token_response:
                credential_offer_entity = repo.get_by_id_token_request_state(state)
                if credential_offer_entity is None:
                    raise InvalidStateInIDTokenResponseError(
                        f"Invalid state {state} in ID token response"
                    )

            if credential_offer_entity.isPreAuthorised:
                raise CredentialOfferIsPreAuthorizedError(
                    f"Credential offer with id {str(credential_offer_entity.id)} is already pre-authorized"
                )

            # Create authorisation code and new state and save to db.
            authorisation_code = str(uuid.uuid4())
            authorisation_code_state = str(uuid.uuid4())
            credential_offer_entity = repo.update(
                id=credential_offer_entity.id,
                authorisationCode=authorisation_code,
                authorisationCodeState=authorisation_code_state,
            )
            redirect_base_uri = (
                credential_offer_entity.redirectUri
                if credential_offer_entity.redirectUri
                else "openid://"
            )
            redirect_url = f"{redirect_base_uri}?code={authorisation_code}"
            if credential_offer_entity.authorisationRequestState:
                redirect_url += (
                    f"&state={credential_offer_entity.authorisationRequestState}"
                )
            return redirect_url

    async def v2_create_access_token(
        self,
        grant_type: Optional[str] = None,
        code: Optional[str] = None,
        client_id: Optional[str] = None,
        code_verifier: Optional[str] = None,
        user_pin: Optional[str] = None,
        pre_authorised_code: Optional[str] = None,
        client_assertion: Optional[str] = None,
        client_assertion_type: Optional[str] = None,
    ) -> dict:
        assert grant_type in [
            authorisation_grant.value.grant_type
            for authorisation_grant in AuthorisationGrants
        ], "Invalid grant type"

        # Query credential offer by authorisation code
        with self.issue_credential_record_repository as repo:
            if grant_type == AuthorisationGrants.PreAuthorisedCode.value.grant_type:
                assert user_pin is not None, "User pin not found"
                assert pre_authorised_code is not None, "Pre-authorised code not found"

                IssuerService.verify_pre_authorised_code(
                    token=pre_authorised_code, key=self.key_did._key
                )

                pre_authorised_code_decoded = decode_header_and_claims_in_jwt(
                    pre_authorised_code
                )
                credential_offer_id = pre_authorised_code_decoded.claims.get(
                    "credential_offer_id"
                )
                credential_offer_entity = repo.get_by_id(credential_offer_id)
                if credential_offer_entity is None:
                    raise InvalidPreAuthorisedCodeError(
                        f"Invalid pre-authorised code {pre_authorised_code}"
                    )

                if credential_offer_entity.userPin != user_pin:
                    raise InvalidUserPinError(f"Invalid user pin {user_pin}")
            else:
                assert code is not None, "Code not found"
                assert client_id is not None, "Client id not found"

                credential_offer_entity = repo.get_by_authorisation_code(code)
                if credential_offer_entity is None:
                    raise InvalidAuthorisationCodeError(
                        f"Invalid authorisation code {code}"
                    )

                if credential_offer_entity.clientId != client_id:
                    raise InvalidClientError(f"Invalid client {client_id}")

                if code_verifier:
                    code_challenge_to_be_verified = generate_code_challenge(
                        code_verifier
                    )
                    if (
                        code_challenge_to_be_verified
                        != credential_offer_entity.codeChallenge
                    ):
                        raise InvalidCodeVerifierError(
                            f"Invalid code verifier {code_verifier}"
                        )

                if client_assertion:
                    # TODO: Verify client assertion
                    self.logger.debug(
                        f"Client assertion of type {client_assertion_type} is present."
                    )

            iat = int(time.time())
            exp = iat + 86400
            nonce = str(uuid.uuid4())

            access_token = AuthorisationService.create_access_token(
                iss=self.key_did.did,
                aud=self.key_did.did,
                sub=client_id,
                iat=iat,
                nbf=iat,
                exp=exp,
                nonce=nonce,
                kid=self.key_did._key.key_id,
                key=self.key_did._key,
                credential_offer_id=str(credential_offer_entity.id),
            )

            token_response = TokenResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=exp,
                c_nonce=nonce,
                c_nonce_expires_in=exp,
            )
            return token_response.to_dict()

    def _create_credential_token(
        self,
        credential_issuer: str,
        credential_id: str,
        credential_type: List[str],
        credential_context: List[str],
        credential_subject: dict,
        credential_schema: Union[dict, List[dict]],
        jti: str,
        iss: str,
        sub: str,
        kid: str,
        key: jwk.JWK,
        credential_status: Optional[dict] = None,
        terms_of_use: Optional[Union[dict, List[dict]]] = None,
    ) -> str:
        expiry_in_seconds = 3600
        iss_in_epoch, issuance_date = generate_ISO8601_UTC()
        exp_in_epoch, expiration_date = generate_ISO8601_UTC(expiry_in_seconds)
        vc = {
            "@context": credential_context,
            "id": credential_id,
            "type": credential_type,
            "issuer": credential_issuer,
            "issuanceDate": issuance_date,
            "validFrom": issuance_date,
            "expirationDate": expiration_date,
            "issued": issuance_date,
            "credentialSubject": credential_subject,
            "credentialSchema": credential_schema,
        }
        if credential_status:
            vc["credentialStatus"] = credential_status

        if terms_of_use:
            vc["termsOfUse"] = terms_of_use

        return create_credential_token(
            vc=vc,
            jti=jti,
            sub=sub,
            iss=iss,
            kid=kid,
            key=key,
            iat=iss_in_epoch,
            exp=exp_in_epoch,
        )

    async def v2_issue_credential(
        self,
        credential_request_proof_jwt: str,
        credential_type_to_be_issued: str,
        access_token: Optional[str] = None,
    ) -> dict:
        assert self.legal_entity_entity is not None, "Legal entity not found"
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"

        available_credential_types = [
            available_credential_type.value
            for available_credential_type in CredentialTypes
        ]

        if credential_type_to_be_issued in available_credential_types:
            credential_response = (
                await self.prepare_credential_response_for_tao_or_ti_credentials(
                    credential_request_proof_jwt,
                    credential_type_to_be_issued,
                    access_token,
                )
            )
        else:
            credential_response = await self.v2_prepare_credential_response_for_non_tao_or_non_ti_credentials(
                credential_request_proof_jwt, credential_type_to_be_issued, access_token
            )

        return credential_response.to_dict()

    async def v2_prepare_credential_response_for_non_tao_or_non_ti_credentials(
        self,
        credential_request_proof_jwt: str,
        credential_type_to_be_issued: str,
        access_token: Optional[str] = None,
    ):
        if not access_token:
            raise InvalidAccessTokenError(
                f"Access token is required for credential type {credential_type_to_be_issued}"
            )

        with self.issue_credential_record_repository as repo:
            decoded_claims = decode_header_and_claims_in_jwt(access_token)

            credential_offer_id = decoded_claims.claims.get("credential_offer_id")
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            if not credential_offer_entity:
                raise InvalidAccessTokenError(f"Invalid access token {access_token}")

            AuthorisationService.verify_access_token(
                token=access_token,
                aud=self.key_did.did,
                sub=credential_offer_entity.clientId,
                key=self.key_did._key,
            )

            if (
                credential_offer_entity.issuanceMode
                == CredentialIssuanceModes.Deferred.value
            ):
                acceptance_token = str(uuid.uuid4())
                credential_offer_entity = repo.update(
                    id=credential_offer_entity.id,
                    acceptanceToken=acceptance_token,
                )
                credential_response = AcceptanceTokenResponse(
                    acceptance_token=acceptance_token
                )
            else:
                data_agreement_model: V2DataAgreementModel = (
                    credential_offer_entity.dataAgreement
                )
                if data_agreement_model is not None:
                    credential_id = f"urn:did:{str(credential_offer_entity.id)}"
                    credential_type = data_agreement_model.credentialTypes
                    credential_context = ["https://www.w3.org/2018/credentials/v1"]
                    credential_schema = [
                        {
                            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                            "type": "FullJsonSchemaValidator2021",
                        }
                    ]
                    credential_subject = convert_data_attributes_to_credential(
                        credential_offer_entity.dataAttributeValues
                    )

                    credential_subject["id"] = credential_offer_entity.clientId
                    kid = f"{self.key_did.did}#{self.key_did._method_specific_id}"
                    jti = credential_id
                    iss = self.key_did.did
                    sub = credential_offer_entity.clientId
                    data_attributes_list = (
                        convert_data_attributes_raw_list_to_data_attributes_list(
                            credential_offer_entity.dataAttributeValues,
                            credential_offer_entity.limitedDisclosure,
                        )
                    )
                    if credential_offer_entity.limitedDisclosure:
                        format = "vc+sd-jwt"
                        to_be_issued_credential = create_w3c_vc_sd_jwt_for_data_attributes(
                            jti=jti,
                            iss=iss,
                            sub=sub,
                            kid=kid,
                            key=self.key_did._key,
                            credential_issuer=self.key_did.did,
                            credential_id=credential_id,
                            credential_type=credential_type,
                            credential_context=credential_context,
                            data_attributes=data_attributes_list,
                            credential_schema=credential_schema,
                            credential_status=None,
                            terms_of_use=None,
                            limited_disclosure=credential_offer_entity.limitedDisclosure,
                        )
                    else:
                        format = "jwt_vc"
                        to_be_issued_credential = (
                            create_w3c_vc_sd_jwt_for_data_attributes(
                                credential_id=credential_id,
                                credential_type=credential_type,
                                credential_context=credential_context,
                                credential_status=None,
                                terms_of_use=None,
                                credential_schema=credential_schema,
                                kid=kid,
                                jti=jti,
                                iss=iss,
                                sub=sub,
                                key=self.key_did._key,
                                credential_issuer=self.key_did.did,
                                limited_disclosure=False,
                                data_attributes=data_attributes_list,
                            )
                        )

                    # Update the credential offer entity with the DID of the client
                    credential_offer_entity = repo.update(
                        credential_offer_entity.id,
                        did=credential_offer_entity.clientId,
                        status=CredentialOfferStatuses.CredentialAcknowledged.value,
                    )

                    credential_response = CredentialResponse(
                        format=format, credential=to_be_issued_credential
                    )
                    if self.legal_entity_entity.webhook_url:
                        try:
                            send_webhook(
                                self.legal_entity_entity.webhook_url,
                                credential_offer_entity.to_dict(),
                            )
                        except Exception as e:
                            self.logger.error(
                                "Exception occurred during sending webhook"
                            )
                else:
                    credential_id = f"urn:did:{str(credential_offer_entity.id)}"
                    credential_type = credential_offer_entity.credential.get("type", {})
                    credential_context = ["https://www.w3.org/2018/credentials/v1"]
                    credential_schema = [
                        {
                            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                            "type": "FullJsonSchemaValidator2021",
                        }
                    ]
                    credential_subject = credential_offer_entity.credential.get(
                        "credentialSubject", {}
                    )
                    credential_subject["id"] = credential_offer_entity.clientId
                    kid = f"{self.key_did.did}#{self.key_did._method_specific_id}"
                    jti = credential_id
                    iss = self.key_did.did
                    sub = credential_offer_entity.clientId
                    if credential_offer_entity.disclosureMapping:
                        format = "vc+sd-jwt"
                        to_be_issued_credential = create_w3c_vc_jwt_with_disclosure_mapping(
                            jti=jti,
                            iss=iss,
                            sub=sub,
                            kid=kid,
                            key=self.key_did._key,
                            credential_issuer=self.key_did.did,
                            credential_id=credential_id,
                            credential_type=credential_type,
                            credential_context=credential_context,
                            credential_subject={
                                "credentialSubject": credential_subject
                            },
                            credential_schema=credential_schema,
                            credential_status=None,
                            terms_of_use=None,
                            disclosure_mapping=credential_offer_entity.disclosureMapping,
                        )
                    else:
                        format = "jwt_vc"
                        to_be_issued_credential = (
                            create_w3c_vc_jwt_with_disclosure_mapping(
                                jti=jti,
                                iss=iss,
                                sub=sub,
                                kid=kid,
                                key=self.key_did._key,
                                credential_issuer=self.key_did.did,
                                credential_id=credential_id,
                                credential_type=credential_type,
                                credential_context=credential_context,
                                credential_subject={
                                    "credentialSubject": credential_subject
                                },
                                credential_schema=credential_schema,
                                credential_status=None,
                                terms_of_use=None,
                                disclosure_mapping=None,
                            )
                        )

                    # Update the credential offer entity with the DID of the client
                    credential_offer_entity = repo.update(
                        credential_offer_entity.id,
                        did=credential_offer_entity.clientId,
                        status=CredentialOfferStatuses.CredentialAcknowledged.value,
                    )

                    credential_response = CredentialResponse(
                        format=format, credential=to_be_issued_credential
                    )
                    if self.legal_entity_entity.webhook_url:
                        try:
                            send_webhook(
                                self.legal_entity_entity.webhook_url,
                                credential_offer_entity.to_dict(),
                            )
                        except Exception as e:
                            self.logger.error(
                                "Exception occurred during sending webhook"
                            )
            return credential_response

    async def v2_issue_deferred_credential(
        self,
        acceptance_token: Optional[str] = None,
    ) -> dict:
        if not acceptance_token:
            raise InvalidAcceptanceTokenError(
                "Acceptance token is required to issue deferred credential"
            )

        with self.issue_credential_record_repository as repo:
            credential_offer_entity = repo.get_by_acceptance_token(acceptance_token)
            if not credential_offer_entity:
                raise CredentialOfferNotFoundError("Credential offer not found")

            data_agreement_model: V2DataAgreementModel = (
                credential_offer_entity.dataAgreement
            )

            if (
                credential_offer_entity.credentialStatus
                == CredentialStatuses.Pending.value
            ):
                raise CredentialPendingError("Credential is not available yet")

            if data_agreement_model is not None:
                credential_id = f"urn:did:{str(credential_offer_entity.id)}"

                credential_type = data_agreement_model.credentialTypes
                credential_context = ["https://www.w3.org/2018/credentials/v1"]
                credential_schema = [
                    {
                        "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                        "type": "FullJsonSchemaValidator2021",
                    }
                ]
                credential_subject = convert_data_attributes_to_credential(
                    credential_offer_entity.dataAttributeValues
                )

                credential_subject["id"] = credential_offer_entity.clientId
                kid = f"{self.key_did.did}#{self.key_did._method_specific_id}"
                jti = credential_id
                iss = self.key_did.did
                if credential_offer_entity.clientId:
                    sub = credential_offer_entity.clientId
                else:
                    sub = ""
                data_attributes_list = (
                    convert_data_attributes_raw_list_to_data_attributes_list(
                        credential_offer_entity.dataAttributeValues,
                        credential_offer_entity.limitedDisclosure,
                    )
                )
                if credential_offer_entity.limitedDisclosure:
                    format = "vc+sd-jwt"
                    to_be_issued_credential = create_w3c_vc_sd_jwt_for_data_attributes(
                        jti=jti,
                        iss=iss,
                        sub=sub,
                        kid=kid,
                        key=self.key_did._key,
                        credential_issuer=self.key_did.did,
                        credential_id=credential_id,
                        credential_type=credential_type,
                        credential_context=credential_context,
                        data_attributes=data_attributes_list,
                        credential_schema=credential_schema,
                        credential_status=None,
                        terms_of_use=None,
                        limited_disclosure=credential_offer_entity.limitedDisclosure,
                    )
                else:
                    format = "jwt_vc"
                    to_be_issued_credential = create_w3c_vc_sd_jwt_for_data_attributes(
                        jti=jti,
                        iss=iss,
                        sub=sub,
                        kid=kid,
                        key=self.key_did._key,
                        credential_issuer=self.key_did.did,
                        credential_id=credential_id,
                        credential_type=credential_type,
                        credential_context=credential_context,
                        data_attributes=data_attributes_list,
                        credential_schema=credential_schema,
                        credential_status=None,
                        terms_of_use=None,
                        limited_disclosure=False,
                    )
            else:
                credential_id = f"urn:did:{str(credential_offer_entity.id)}"
                credential_type = credential_offer_entity.credential.get("type", {})
                credential_context = ["https://www.w3.org/2018/credentials/v1"]
                credential_schema = [
                    {
                        "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                        "type": "FullJsonSchemaValidator2021",
                    }
                ]
                credential_subject = credential_offer_entity.credential.get(
                    "credentialSubject", {}
                )
                print("DEBUG>>")
                print(credential_offer_entity.credential)
                credential_subject["id"] = credential_offer_entity.clientId
                kid = f"{self.key_did.did}#{self.key_did._method_specific_id}"
                jti = credential_id
                iss = self.key_did.did
                sub = credential_offer_entity.clientId
                if credential_offer_entity.disclosureMapping:
                    format = "vc+sd-jwt"
                    to_be_issued_credential = create_w3c_vc_jwt_with_disclosure_mapping(
                        jti=jti,
                        iss=iss,
                        sub=sub,
                        kid=kid,
                        key=self.key_did._key,
                        credential_issuer=self.key_did.did,
                        credential_id=credential_id,
                        credential_type=credential_type,
                        credential_context=credential_context,
                        credential_subject={"credentialSubject": credential_subject},
                        credential_schema=credential_schema,
                        credential_status=None,
                        terms_of_use=None,
                        disclosure_mapping=credential_offer_entity.disclosureMapping,
                    )
                else:
                    print(credential_subject)
                    format = "jwt_vc"
                    to_be_issued_credential = create_w3c_vc_jwt_with_disclosure_mapping(
                        jti=jti,
                        iss=iss,
                        sub=sub,
                        kid=kid,
                        key=self.key_did._key,
                        credential_issuer=self.key_did.did,
                        credential_id=credential_id,
                        credential_type=credential_type,
                        credential_context=credential_context,
                        credential_subject={"credentialSubject": credential_subject},
                        credential_schema=credential_schema,
                        credential_status=None,
                        terms_of_use=None,
                        disclosure_mapping=None,
                    )

            credential_response = CredentialResponse(
                format=format, credential=to_be_issued_credential
            )
            credential_offer_entity = repo.update(
                credential_offer_entity.id,
                status=CredentialOfferStatuses.CredentialAcknowledged.value,
            )
            if self.legal_entity_entity.webhook_url:
                try:
                    send_webhook(
                        self.legal_entity_entity.webhook_url,
                        credential_offer_entity.to_dict(),
                    )
                except Exception as e:
                    self.logger.error("Exception occurred during sending webhook")
            return credential_response.to_dict()

    async def update_deferred_credential_offer_with_disclosure_mapping(
        self,
        credential_offer_id: str,
        credential: Optional[str] = None,
        disclosureMapping: Optional[dict] = None,
    ) -> Union[dict, None]:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"

        with self.issue_credential_record_repository as repo:
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            if credential_offer_entity is None:
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} not found"
                )

            if (
                credential_offer_entity.issuanceMode
                != CredentialIssuanceModes.Deferred.value
            ):
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} is not in deferred issuance mode"
                )

            if (
                credential_offer_entity.credentialStatus
                != CredentialStatuses.Pending.value
            ):
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} is not in pending status"
                )

            if not isinstance(credential, dict):
                raise UpdateCredentialOfferError(
                    f"Credential must be a valid JSON object"
                )
            if credential.get("credentialSubject") is None:
                raise UpdateCredentialOfferError(
                    f"Credential must contain credentialSubject field"
                )

            # Update credential present in DB with credentialSubject
            credential.setdefault(
                "type",
                credential_offer_entity.credential.get(
                    "type", ["VerifiableCredential"]
                ),
            )

            credential_offer_entity = repo.update(
                id=credential_offer_id,
                credentialStatus=CredentialStatuses.Ready.value,
                status=CredentialOfferStatuses.CredentialIssued.value,
                credential=credential,
                disclosureMapping=disclosureMapping,
            )
            if self.legal_entity_entity.webhook_url:
                try:
                    send_webhook(
                        self.legal_entity_entity.webhook_url,
                        credential_offer_entity.to_dict(),
                    )
                except Exception as e:
                    self.logger.error("Exception occurred during sending webhook")
            return credential_offer_entity.to_dict()

    async def update_deferred_credential_offer_with_data_attribute_values(
        self,
        data_agreement_id: str,
        credential_offer_id: str,
        data_attribute_values: list,
        limited_disclosure: Optional[bool] = None,
    ) -> Union[dict, None]:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"

        with self.issue_credential_record_repository as repo:
            credential_offer_entity = repo.get_by_id_and_data_agreement_id(
                credential_offer_id, data_agreement_id
            )
            if credential_offer_entity is None:
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} not found"
                )

            if (
                credential_offer_entity.issuanceMode
                != CredentialIssuanceModes.Deferred.value
            ):
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} is not in deferred issuance mode"
                )

            if (
                credential_offer_entity.credentialStatus
                != CredentialStatuses.Pending.value
            ):
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} is not in pending status"
                )

            data_agreement_model: V2DataAgreementModel = (
                credential_offer_entity.dataAgreement
            )
            if data_attribute_values:
                data_attributes_schema = convert_data_attributes_to_json_schema(
                    data_agreement_model.dataAttributes
                )
                data_attributes_credential = convert_data_attributes_to_credential(
                    data_attribute_values
                )
                data_attributes_credential["id"] = f"urn:did:{str(uuid.uuid4())}"
                try:
                    seconds_in_one_year = 31536000
                    _, issuance_date = generate_ISO8601_UTC()
                    _, expiration_date = generate_ISO8601_UTC(seconds_in_one_year)
                    vc = {
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "id": f"urn:did:{str(uuid.uuid4())}",
                        "type": data_agreement_model.credentialTypes,
                        "issuer": self.key_did.did,
                        "issuanceDate": issuance_date,
                        "validFrom": issuance_date,
                        "expirationDate": expiration_date,
                        "issued": issuance_date,
                        "credentialSubject": data_attributes_credential,
                        "credentialSchema": {
                            "id": "",
                            "type": "FullJsonSchemaValidator2021",
                        },
                    }
                    validate(instance=vc, schema=data_attributes_schema)
                    del data_attributes_credential["id"]
                    validate(
                        instance=data_attributes_credential,
                        schema=data_attributes_schema,
                    )
                except exceptions.ValidationError as e:
                    raise UpdateCredentialOfferError(e.message)

            credential_offer_entity = repo.update(
                id=credential_offer_id,
                dataAttributeValues=data_attribute_values,
                credentialStatus=CredentialStatuses.Ready.value,
                status=CredentialOfferStatuses.CredentialIssued.value,
                limitedDisclosure=limited_disclosure,
            )
            if self.legal_entity_entity.webhook_url:
                try:
                    send_webhook(
                        self.legal_entity_entity.webhook_url,
                        credential_offer_entity.to_dict(),
                    )
                except Exception as e:
                    self.logger.error("Exception occurred during sending webhook")
            return credential_offer_entity.to_dict()

    async def get_credential_offer_by_id(
        self,
        credential_offer_id: str,
    ) -> Union[IssueCredentialRecordModel, None]:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"
        with self.issue_credential_record_repository as repo:
            credential_offer_entity = repo.get_by_id(id=credential_offer_id)
            return credential_offer_entity

    async def get_all_credential_offers_by_organisation_id(
        self, organisation_id: str
    ) -> List[IssueCredentialRecordModel]:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"
        with self.issue_credential_record_repository as repo:
            return repo.get_all_by_organisation_id(organisation_id=organisation_id)

    async def get_all_credential_offers_by_data_agreement_id(
        self, data_agreement_id: str
    ) -> List[IssueCredentialRecordModel]:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"
        with self.issue_credential_record_repository as repo:
            return repo.get_all_by_data_agreement_id(
                data_agreement_id=data_agreement_id
            )

    async def delete_credential_offer(
        self, credential_offer_id: str, organisation_id: str
    ) -> bool:
        assert (
            self.issue_credential_record_repository is not None
        ), "Credential offer repository not found"
        with self.issue_credential_record_repository as repo:
            return repo.delete(credential_offer_id, organisation_id)

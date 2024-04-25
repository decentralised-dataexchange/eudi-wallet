from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository
from logging import Logger

from sqlalchemy.orm import Session
from eudi_wallet.ebsi.exceptions.application.organisation import (
    LegalEntityNotFoundError,
)
from eudi_wallet.ebsi.models.v2.data_agreement import V2DataAgreementModel
from eudi_wallet.ebsi.usecases.v2.organisation.list_all_data_agreements_usecase import (
    V2ListAllDataAgreementsUsecase,
)
from eudi_wallet.ebsi.repositories.v2.data_agreement import (
    SqlAlchemyV2DataAgreementRepository,
)


def service_get_well_known_openid_credential_issuer_config(
    wallet_domain: str,
    organisation_id: str,
    logger: Logger,
    legal_entity_repository: SqlAlchemyOrganisationRepository,
    data_agreement_repository: SqlAlchemyV2DataAgreementRepository,
):
    # For additional fields like logo, background color, text color e.t.c
    # Check https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

    with legal_entity_repository as repo:
        legal_entity = repo.get_by_id(id=organisation_id)

        if legal_entity is None:
            raise LegalEntityNotFoundError(
                f"Legal entity with id {organisation_id} not found"
            )

        usecase = V2ListAllDataAgreementsUsecase(
            dataagreement_repository=data_agreement_repository,
            logger=logger,
        )
        data_agreements = usecase.execute(organisation_id=organisation_id)

        credentials_supported = {}
        for data_agreement in data_agreements:
            if data_agreement.limitedDisclosure:
                format = "vc+sd-jwt"
            else:
                format = "jwt_vc"
            credential = {
                "format": format,
                "scope": data_agreement.purpose,
                "cryptographic_binding_methods_supported": ["jwk"],
                "cryptographic_suites_supported": ["ES256"],
                "display": [
                    {
                        "name": data_agreement.purpose,
                        "locale": "en-GB",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            }

            credentials_supported[data_agreement.purpose] = credential
            # credentials_supported.append(credential)

        openid_credential_issuer_config = {
            "credential_issuer": f"{wallet_domain}/organisation/{organisation_id}/service",
            "authorization_server": f"{wallet_domain}/organisation/{organisation_id}/service",
            "credential_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/credential",
            "deferred_credential_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/credential_deferred",
            "display": [
                {
                    "name": legal_entity.name,
                    "location": legal_entity.location,
                    "locale": "en-GB",
                    "cover": {
                        "url": legal_entity.cover_image_url,
                        "alt_text": legal_entity.name,
                    },
                    "logo": {
                        "url": legal_entity.logo_url,
                        "alt_text": legal_entity.name,
                    },
                    "description": legal_entity.description,
                }
            ],
            "credentials_supported": credentials_supported,
        }

    return openid_credential_issuer_config


def service_get_well_known_authn_openid_config(
    wallet_domain: str, organisation_id: str
):
    return {
        "redirect_uris": [
            f"{wallet_domain}/organisation/{organisation_id}/service/direct_post"
        ],
        "issuer": f"{wallet_domain}/organisation/{organisation_id}/service",
        "authorization_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/authorize",
        "token_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/token",
        "jwks_uri": f"{wallet_domain}/organisation/{organisation_id}/service/jwks",
        "scopes_supported": ["openid"],
        "response_types_supported": ["vp_token", "id_token"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "request_authentication_methods_supported": {
            "authorization_endpoint": ["request_object"]
        },
        "vp_formats_supported": {
            "jwt_vp": {"alg_values_supported": ["ES256"]},
            "jwt_vc": {"alg_values_supported": ["ES256"]},
            "sd_jwt": {"alg_values_supported": ["ES256"]},
        },
        "subject_syntax_types_supported": ["did:key", "did:ebsi"],
        "subject_syntax_types_discriminations": ["did:key:jwk_jcs-pub", "did:ebsi:v1"],
        "subject_trust_frameworks_supported": ["ebsi"],
        "id_token_types_supported": [
            "subject_signed_id_token",
            "attester_signed_id_token",
        ],
    }

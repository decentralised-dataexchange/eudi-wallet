from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository
from logging import Logger

from sqlalchemy.orm import Session
from eudi_wallet.ebsi.exceptions.application.organisation import (
    LegalEntityNotFoundError,
)
from eudi_wallet.ebsi.repositories.v2.issue_credential_record import (
    SqlAlchemyIssueCredentialRecordRepository,
)


def service_get_well_known_openid_credential_issuer_config(
    wallet_domain: str,
    organisation_id: str,
    logger: Logger,
    session: Session,
    legal_entity_repository: SqlAlchemyOrganisationRepository,
):
    # For additional fields like logo, background color, text color e.t.c
    # Check https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

    issue_credential_repository = SqlAlchemyIssueCredentialRecordRepository(
        session=session, logger=logger
    )

    assert issue_credential_repository is not None

    with issue_credential_repository as credential_repo:

        credential_offers = (
            credential_repo.get_all_by_organisation_id_and_with_credential(
                organisation_id=organisation_id
            )
        )

    with legal_entity_repository as repo:
        legal_entity = repo.get_by_id(id=organisation_id)

        if legal_entity is None:
            raise LegalEntityNotFoundError(
                f"Legal entity with id {organisation_id} not found"
            )
        credentials_supported = create_credential_supported_from_credential_offers(
            credential_offers=credential_offers
        )

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


def add_or_replace_suffix(credential_type, current_suffix, new_suffix):
    # Check if the credential type ends with the current suffix
    if credential_type.endswith(new_suffix):
        if new_suffix == "SdJwt":
            return credential_type
    if credential_type.endswith(current_suffix):
        # Remove the current suffix and add new suffix
        credential_type = credential_type[: -len(current_suffix)] + new_suffix
    elif not credential_type.endswith(new_suffix):
        # Add the new suffix if it's not already present
        credential_type += new_suffix
    return credential_type


def validate_credential_type_based_on_disclosure_mapping(
    credential: dict, disclosure_mapping: dict
) -> dict:
    credential_types = credential.get("type", [])
    credential_type = credential_types[-1]
    if disclosure_mapping:
        credential_type = add_or_replace_suffix(credential_type, "Jwt", "SdJwt")
        credential_types[-1] = credential_type
    else:
        credential_type = add_or_replace_suffix(credential_type, "SdJwt", "Jwt")
        credential_types[-1] = credential_type
    credential["type"] = credential_types
    return credential


def create_credential_supported_from_credential_offers(credential_offers: list) -> dict:
    credentials_supported = {}
    for credential_offer in credential_offers:
        credential_types = credential_offer.credential.get("type", [])
        if credential_types:
            credential = validate_credential_type_based_on_disclosure_mapping(
                credential=credential_offer.credential,
                disclosure_mapping=credential_offer.disclosureMapping,
            )
            credential_types = credential.get("type", [])

            if credential_offer.disclosureMapping:
                format = "vc+sd-jwt"
            else:
                format = "jwt_vc"
            credential_supported = {
                "format": format,
                "scope": credential_types[-1],
                "cryptographic_binding_methods_supported": ["jwk"],
                "cryptographic_suites_supported": ["ES256"],
                "display": [
                    {
                        "name": credential_types[-1],
                        "locale": "en-GB",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
            }

            credentials_supported[credential_types[-1]] = credential_supported

    return credentials_supported


def service_get_well_known_openid_credential_issuer_config_v2(
    wallet_domain: str,
    organisation_id: str,
    logger: Logger,
    session: Session,
    legal_entity_repository: SqlAlchemyOrganisationRepository,
):
    # For additional fields like logo, background color, text color e.t.c
    # Check https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

    issue_credential_repository = SqlAlchemyIssueCredentialRecordRepository(
        session=session, logger=logger
    )

    assert issue_credential_repository is not None

    with issue_credential_repository as credential_repo:

        credential_offers = (
            credential_repo.get_all_by_organisation_id_and_with_credential(
                organisation_id=organisation_id
            )
        )

    with legal_entity_repository as repo:
        legal_entity = repo.get_by_id(id=organisation_id)

        if legal_entity is None:
            raise LegalEntityNotFoundError(
                f"Legal entity with id {organisation_id} not found"
            )
        credentials_supported = create_credential_supported_from_credential_offers(
            credential_offers=credential_offers
        )

        openid_credential_issuer_config = {
            "credential_issuer": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid",
            "authorization_server": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid",
            "credential_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid/sdjwt/credential",
            "deferred_credential_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid/sdjwt/credential_deferred",
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


def service_get_well_known_authn_openid_config_v2(
    wallet_domain: str, organisation_id: str
):
    return {
        "redirect_uris": [
            f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid/direct_post"
        ],
        "issuer": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid",
        "authorization_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid/authorize",
        "token_endpoint": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid/token",
        "jwks_uri": f"{wallet_domain}/organisation/{organisation_id}/service/digital-wallet/openid/jwks",
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


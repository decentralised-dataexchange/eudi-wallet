def get_well_known_openid_credential_issuer_config(wallet_domain: str):
    # For additional fields like logo, background color, text color e.t.c
    # Check https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

    # TODO: Populate support credential schemas from db.
    return {
        "credential_issuer": f"{wallet_domain}/issuer",
        "authorization_server": f"{wallet_domain}/auth",
        "credential_endpoint": f"{wallet_domain}/issuer/credential",
        "deferred_credential_endpoint": f"{wallet_domain}/issuer/credential_deferred",
        "display": {
            "name": "iGrant.io - EBSI Wallet",
            "locale": "en-GB",
            "logo": {
                "url": "https://demo-api.igrant.io/v1/organizations/5c1509c75430460001af6232/image/5c150a315430460001af6234/web",
                "alt_text": "iGrant.io - EBSI Wallet",
            },
            "description": "iGrant.io is a data exchange platform that helps organisations to access personal data in a sustainable and human-centric manner.",
        },
        "credentials_supported": [
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTWalletSameDeferred",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {"name": "Conformance tests deferred", "locale": "en-GB"}
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTWalletSamePreAuthorised",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {"name": "Conformance tests pre-authorised", "locale": "en-GB"}
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTWalletSameInTime",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {"name": "Conformance tests in-time", "locale": "en-GB"}
                ],
            },
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
                "display": [{"name": "Conformance test revocation", "locale": "en-GB"}],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "VerifiableAuthorisationToOnboard",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {"name": "Verifiable Authorisation to onboard", "locale": "en-GB"}
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "VerifiableAccreditation",
                    "VerifiableAccreditationToAttest",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {"name": "Verifiable Accreditation to attest", "locale": "en-GB"}
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "VerifiableAccreditation",
                    "VerifiableAccreditationToAccredit",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {"name": "Verifiable Accreditation to accredit", "locale": "en-GB"}
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "VerifiableAuthorisationForTrustChain",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {
                        "name": "Verifiable Authorisation to issue verifiable tokens",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTAAQualificationCredential",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {
                        "name": "Verifiable Attestation Conformance Qualification To Accredit & Authorise",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTWalletQualificationCredential",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {
                        "name": "Verifiable Attestation Conformance Qualification Holder Wallet",
                        "locale": "en-GB",
                    }
                ],
            },
            {
                "format": "jwt_vc",
                "types": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTIssueQualificationCredential",
                ],
                "trust_framework": {
                    "name": "ebsi",
                    "type": "Accreditation",
                    "uri": "TIR link towards accreditation",
                },
                "display": [
                    {
                        "name": "Verifiable Attestation Conformance Qualification Issue to Holder",
                        "locale": "en-GB",
                    }
                ],
            },
        ],
    }


def get_well_known_authn_openid_config(wallet_domain: str):
    return {
        "redirect_uris": [f"{wallet_domain}/auth/direct_post"],
        "issuer": f"{wallet_domain}/auth",
        "authorization_endpoint": f"{wallet_domain}/auth/authorize",
        "token_endpoint": f"{wallet_domain}/auth/token",
        "jwks_uri": f"{wallet_domain}/auth/jwks",
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
        },
        "subject_syntax_types_supported": ["did:key", "did:ebsi"],
        "subject_syntax_types_discriminations": ["did:key:jwk_jcs-pub", "did:ebsi:v1"],
        "subject_trust_frameworks_supported": ["ebsi"],
        "id_token_types_supported": [
            "subject_signed_id_token",
            "attester_signed_id_token",
        ],
    }

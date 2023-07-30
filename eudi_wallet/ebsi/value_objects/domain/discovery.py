import typing
from dataclasses import dataclass

from dataclasses_json import DataClassJsonMixin


# Dataclass for request authentication methods supported
@dataclass
class RequestAuthenticationMethodsSupported(DataClassJsonMixin):
    authorization_endpoint: typing.List[str]


# Dataclass for JSON Web Key Set (JWKS) supported
@dataclass
class JWKSSupported(DataClassJsonMixin):
    alg_values_supported: typing.List[str]


# Dataclass for Verifiable Presentation (VP) formats supported
@dataclass
class VPFormatsSupported(DataClassJsonMixin):
    jwt_vp: JWKSSupported
    jwt_vc: JWKSSupported


# Dataclass for OpenID Connect Authorization Server configuration
@dataclass
class OpenIDAuthServerConfig(DataClassJsonMixin):
    redirect_uris: typing.List[str]
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    scopes_supported: typing.List[str]
    response_types_supported: typing.List[str]
    response_modes_supported: typing.List[str]
    grant_types_supported: typing.List[str]
    subject_types_supported: typing.List[str]
    id_token_signing_alg_values_supported: typing.List[str]
    request_object_signing_alg_values_supported: typing.List[str]
    request_parameter_supported: bool
    request_uri_parameter_supported: bool
    token_endpoint_auth_methods_supported: typing.List[str]
    request_authentication_methods_supported: RequestAuthenticationMethodsSupported
    vp_formats_supported: VPFormatsSupported
    subject_syntax_types_supported: typing.List[str]
    subject_syntax_types_discriminations: typing.List[str]
    subject_trust_frameworks_supported: typing.List[str]
    id_token_types_supported: typing.List[str]


# Dataclass for trust framework
@dataclass
class TrustFramework(DataClassJsonMixin):
    name: str
    type: str
    uri: str


# Dataclass for display
@dataclass
class Display(DataClassJsonMixin):
    name: str
    locale: str


# Dataclass for credential
@dataclass
class Credential(DataClassJsonMixin):
    format: str
    types: typing.List[str]
    trust_framework: TrustFramework
    display: typing.List[Display]


# Dataclass for OpenID Connect Credential Issuer configuration
@dataclass
class OpenIDCredentialIssuerConfig(DataClassJsonMixin):
    credential_issuer: str
    authorization_server: str
    credential_endpoint: str
    deferred_credential_endpoint: str
    credentials_supported: typing.List[Credential]

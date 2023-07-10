import typing
from dataclasses import dataclass
from eudi_wallet.util import http_call

# Constants for OpenID Connect endpoint URLs
OPENID_CREDENTIAL_ISSUER_CONFIGURATION_ENDPOINT = "/.well-known/openid-credential-issuer"
OPENID_AUTHN_SERVER_CONFIGURATION_ENDPOINT = "/.well-known/openid-configuration"

# Dataclass for request authentication methods supported 
@dataclass
class RequestAuthenticationMethodsSupported:
    authorization_endpoint: typing.List[str]

# Dataclass for JSON Web Key Set (JWKS) supported
@dataclass
class JWKSSupported:
    alg_values_supported: typing.List[str]

# Dataclass for Verifiable Presentation (VP) formats supported
@dataclass
class VPFormatsSupported:
    jwt_vp: JWKSSupported
    jwt_vc: JWKSSupported

# Dataclass for OpenID Connect Authorization Server configuration
@dataclass
class OpenIDAuthServerConfig:
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
class TrustFramework:
    name: str
    type: str
    uri: str

# Dataclass for display
@dataclass
class Display:
    name: str
    locale: str

# Dataclass for credential
@dataclass
class Credential:
    format: str
    types: typing.List[str]
    trust_framework: TrustFramework
    display: typing.List[Display]

# Dataclass for OpenID Connect Credential Issuer configuration
@dataclass
class OpenIDCredentialIssuerConfig:
    credential_issuer: str
    authorization_server: str
    credential_endpoint: str
    deferred_credential_endpoint: str
    credentials_supported: typing.List[Credential]


async def fetch_credential_issuer_config(issuer_uri: str) -> OpenIDCredentialIssuerConfig:
    """
    Fetches the OpenID Connect Credential Issuer configuration.
    
    Args:
        issuer_uri (str): The issuer URI.
    
    Returns:
        OpenIDCredentialIssuerConfig: The OpenID Connect Credential Issuer configuration.
    """
    
    issuer_config_url = f'{issuer_uri}{OPENID_CREDENTIAL_ISSUER_CONFIGURATION_ENDPOINT}'
    response = await http_call(issuer_config_url,
                               "GET",
                               data=None,
                               headers=None)
    return OpenIDCredentialIssuerConfig(**response)

async def fetch_authorization_server_config(authorization_server_uri: str) -> OpenIDAuthServerConfig:
    """
    Fetches the OpenID Connect Authorization Server configuration.
    
    Args:
        authorization_server_uri (str): The authorization server URI.
    
    Returns:
        OpenIDAuthServerConfig: The OpenID Connect Authorization Server configuration.
    """
    
    authorization_server_config_url = f'{authorization_server_uri}{OPENID_AUTHN_SERVER_CONFIGURATION_ENDPOINT}'
    response = await http_call(authorization_server_config_url, 
                               "GET", 
                               data=None, 
                               headers=None)
    return OpenIDAuthServerConfig(**response)

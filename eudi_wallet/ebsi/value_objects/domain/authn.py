import uuid
from collections import namedtuple
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from dataclasses_json import DataClassJsonMixin, config


@dataclass
class AuthorizationRequestQueryParams(DataClassJsonMixin):
    authorize_uri: Optional[str] = None
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    request: Optional[str] = None
    nonce: Optional[str] = None
    scope: str = "openid"
    response_type: Optional[str] = None
    issuer_state: Optional[str] = None
    state: Optional[str] = None
    authorization_details: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    client_metadata: Optional[str] = None


@dataclass
class AuthorisationGrant:
    grant_type: str
    grant_data: str


class AuthorisationGrants(Enum):
    AuthorisationCode = AuthorisationGrant(
        grant_type="authorization_code", grant_data="issuer_state"
    )
    PreAuthorisedCode = AuthorisationGrant(
        grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
        grant_data="pre-authorized_code",
    )


@dataclass
class IDTokenRequest(DataClassJsonMixin):
    client_id: Optional[str] = None
    response_type: Optional[str] = None
    scope: Optional[str] = None
    redirect_uri: Optional[str] = None
    request_uri: Optional[str] = None
    nonce: Optional[str] = None
    request: Optional[str] = None


@dataclass
class CreateClientAssertion(DataClassJsonMixin):
    kid: str
    iss: str
    sub: str
    aud: str
    jti: str


@dataclass
class ClientAssertionJWTToken(DataClassJsonMixin):
    token: str


@dataclass
class AuthorizationDetail(DataClassJsonMixin):
    locations: list
    types: list
    type: str = "openid_credential"
    format: str = "jwt_vc"


@dataclass
class CreateAuthorizationRequest(DataClassJsonMixin):
    kid: str
    issuer_uri: str
    authorize_uri: str
    redirect_uri: str
    jwks_uri: str
    authorization_details: list[AuthorizationDetail]
    response_type: str = "code"
    scope: str = "openid"
    nonce: str = str(uuid.uuid4())


@dataclass
class CreateIDTokenResponse(DataClassJsonMixin):
    kid: str
    iss: str
    sub: str
    aud: str
    nonce: str
    state: str


@dataclass
class IDTokenResponseJWTToken(DataClassJsonMixin):
    token: str


@dataclass
class SendIDTokenResponse(DataClassJsonMixin):
    direct_post_uri: str
    id_token: str
    state: str


@dataclass
class AuthorizationCodeRedirectResponse(DataClassJsonMixin):
    redirect_uri: Optional[str] = None
    code: Optional[str] = None


@dataclass
class SendTokenRequest(DataClassJsonMixin):
    token_uri: str
    client_id: str
    code: str
    client_assertion: str
    client_assertion_type: str = (
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    grant_type: str = "authorization_code"


@dataclass
class TokenResponse(DataClassJsonMixin):
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    id_token: Optional[str] = None
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None
    scope: Optional[str] = None


@dataclass
class GetPresentationDefinitionPayload(DataClassJsonMixin):
    presentation_definition_uri: str
    scope: str


@dataclass
class Filter:
    type: Optional[str] = None
    contains: Optional[Dict[str, str]] = None


@dataclass
class Path:
    path: Optional[List[str]] = None
    filter: Optional[Filter] = None


@dataclass
class Constraints:
    fields: Optional[List[Path]] = None


@dataclass
class InputDescriptor(DataClassJsonMixin):
    id: Optional[str] = None
    name: Optional[str] = None
    purpose: Optional[str] = None
    constraints: Optional[Constraints] = None


@dataclass
class Format(DataClassJsonMixin):
    jwt_vc: Optional[dict] = None
    jwt_vp: Optional[dict] = None


@dataclass
class PresentationDefinition(DataClassJsonMixin):
    id: Optional[str] = None
    input_descriptors: Optional[List[InputDescriptor]] = None
    format: Optional[Format] = None


@dataclass
class VerifiablePresentation(DataClassJsonMixin):
    context: List[str] = field(metadata=config(field_name="@context"))
    id: str
    type: List[str]
    holder: str
    verifiableCredential: List[str]


@dataclass
class DescriptorMapPath(DataClassJsonMixin):
    id: str
    format: str
    path: str


@dataclass
class DescriptorMap(DataClassJsonMixin):
    id: str
    path: str
    format: str
    path_nested: DescriptorMapPath


@dataclass
class PresentationSubmission(DataClassJsonMixin):
    definition_id: str
    descriptor_map: List[DescriptorMap]
    id: str = str(uuid.uuid4())


@dataclass
class VpJwtTokenPayloadModel(DataClassJsonMixin):
    kid: str
    iss: str
    aud: str
    sub: str
    vp: VerifiablePresentation
    nonce: str = str(uuid.uuid4())
    jti: str = f"urn:uuid:{str(uuid.uuid4())}"


@dataclass
class VpJwtTokenModel(DataClassJsonMixin):
    token: str
    presentation_submission: PresentationSubmission


@dataclass
class IDTokenRequestJWT(DataClassJsonMixin):
    state: Optional[str] = None
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    response_type: Optional[str] = None
    response_mode: Optional[str] = None
    scope: Optional[str] = None
    nonce: Optional[str] = None
    presentation_definition: Optional[PresentationDefinition] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    exp: Optional[int] = None

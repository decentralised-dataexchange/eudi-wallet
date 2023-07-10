import aiohttp
import time
import dataclasses
import uuid
import logging
import base64
import json
import typing
from enum import Enum
from dataclasses import dataclass, field
from dataclasses_json import DataClassJsonMixin, config
from jwcrypto import jwk, jwt
from eudi_wallet.util import (
    parse_query_string_parameters_from_url,
    get_element_by_index_from_list,
)
from dacite import from_dict


logger = logging.getLogger(__name__)


class CredentialTypes(Enum):
    VerifiableCredential = "VerifiableCredential"
    VerifiableAttestation = "VerifiableAttestation"
    VerifiableAuthorisationToOnboard = "VerifiableAuthorisationToOnboard"
    VerifiableAccreditation = "VerifiableAccreditation"
    VerifiableAccreditationToAttest = "VerifiableAccreditationToAttest"
    VerifiableAccreditationToAccredit = "VerifiableAccreditationToAccredit"
    VerifiableAuthorisationForTrustChain = "VerifiableAuthorisationForTrustChain"
    CTAAQualificationCredential = "CTAAQualificationCredential"
    CTWalletQualificationCredential = "CTWalletQualificationCredential"


class AuthorizationRequestError(Exception):
    pass


class TokenRequestError(Exception):
    pass


class CredentialRequestError(Exception):
    pass


@dataclass
class SendAuthorizationRequest:
    authorize_uri: str
    client_id: str
    redirect_uri: str
    request: str
    nonce: str
    scope: str = "openid"


@dataclass
class IDTokenRequest:
    client_id: str
    response_type: str
    scope: str
    redirect_uri: str
    request_uri: str
    nonce: str


@dataclass
class CreateClientAssertion:
    kid: str
    iss: str
    sub: str
    aud: str
    jti: str


@dataclass
class ClientAssertionJWTToken:
    token: str


@dataclass
class IDTokenRequestJWT:
    state: str
    client_id: str
    redirect_uri: str
    response_type: str
    response_mode: str
    scope: str
    nonce: str
    iss: str
    aud: str


@dataclass
class AuthorizationDetail:
    locations: list
    types: list
    type: str = "openid_credential"
    format: str = "jwt_vc"


@dataclass
class CreateAuthorizationRequest:
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
class AuthorizationRequestJWTToken:
    token: str


@dataclass
class CreateIDTokenResponse:
    kid: str
    iss: str
    sub: str
    aud: str
    nonce: str
    state: str


@dataclass
class IDTokenResponseJWTToken:
    token: str


@dataclass
class SendIDTokenResponse:
    direct_post_uri: str
    id_token: str
    state: str


@dataclass
class AuthorizationCodeRedirectResponse:
    redirect_uri: str


@dataclass
class SendTokenRequest:
    token_uri: str
    client_id: str
    code: str
    client_assertion: str
    client_assertion_type: str = (
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    grant_type: str = "authorization_code"


@dataclass
class TokenResponse:
    access_token: str = None
    token_type: str = None
    expires_in: int = None
    id_token: str = None
    c_nonce: str = None
    c_nonce_expires_in: str = None
    scope: str = None


@dataclass
class CreateCredentialRequest:
    kid: str
    iss: str
    aud: str
    nonce: str


@dataclass
class CredentialRequestJWTToken:
    token: str


@dataclass
class CredentialProof:
    jwt: str
    proof_type: str = "jwt"


@dataclass
class CredentialRequestPayload:
    types: typing.List[str]
    proof: CredentialProof
    format: str = "jwt_vc"


@dataclass
class SendCredentialRequest:
    credential_uri: str
    token: str
    payload: CredentialRequestPayload


@dataclass
class CredentialResponse:
    format: str = None
    credential: str = None
    c_nonce: str = None
    c_nonce_expires_in: str = None


async def send_authorization_request(
    authorization_request: SendAuthorizationRequest,
) -> IDTokenRequest:
    url = (
        f"{authorization_request.authorize_uri}?"
        + f"client_id={authorization_request.client_id}"
        + "&response_type=code"
        + f"&scope={authorization_request.scope}"
        + f"&redirect_uri={authorization_request.redirect_uri}"
        + f"&request={authorization_request.request}"
        + f"&nonce={authorization_request.nonce}"
    )
    async with aiohttp.ClientSession() as session:
        async with session.get(url, allow_redirects=False) as response:
            if response.status == 302:
                location_header_value = response.headers["Location"].split("'")[0]

                logger.info(
                    f"Authorisation request performed and obtained the id token request: {location_header_value}"
                )

                query_params = parse_query_string_parameters_from_url(
                    location_header_value
                )
                client_id = get_element_by_index_from_list(
                    query_params.get("client_id", [""]), 0
                )
                response_type = get_element_by_index_from_list(
                    query_params.get("response_type", [""]), 0
                )
                scope = get_element_by_index_from_list(
                    query_params.get("scope", [""]), 0
                )
                redirect_uri = get_element_by_index_from_list(
                    query_params.get("redirect_uri", [""]), 0
                )
                request_uri = get_element_by_index_from_list(
                    query_params.get("request_uri", [""]), 0
                )
                nonce = get_element_by_index_from_list(
                    query_params.get("nonce", [""]), 0
                )
                return IDTokenRequest(
                    client_id=client_id,
                    response_type=response_type,
                    scope=scope,
                    redirect_uri=redirect_uri,
                    request_uri=request_uri,
                    nonce=nonce,
                )
            else:
                raise AuthorizationRequestError("Invalid response status")


async def get_id_token_request_jwt(request_uri: str) -> IDTokenRequestJWT:
    async with aiohttp.ClientSession() as session:
        async with session.get(request_uri) as response:
            if response.status == 200:
                res_text = await response.text()
                claims_encoded = res_text.split(".")[1]
                claims_decoded = base64.b64decode(
                    claims_encoded + "=" * (-len(claims_encoded) % 4)
                )
                claims_dict = json.loads(claims_decoded)
                return IDTokenRequestJWT(**claims_dict)


def create_authorization_request(
    create_authorization_request: CreateAuthorizationRequest, key: jwk.JWK
) -> AuthorizationRequestJWTToken:
    header = {"typ": "JWT", "alg": "ES256", "kid": create_authorization_request.kid}
    iat = int(time.time())
    exp = iat + 3600
    payload = {
        "iss": create_authorization_request.issuer_uri,
        "aud": create_authorization_request.authorize_uri,
        "iat": iat,
        "exp": exp,
        "response_type": create_authorization_request.response_type,
        "scope": create_authorization_request.scope,
        "nonce": create_authorization_request.nonce,
        "client_id": create_authorization_request.issuer_uri,
        "redirect_uri": create_authorization_request.redirect_uri,
        "client_metadata": {
            "jwks_uri": create_authorization_request.jwks_uri,
            "authorization_endpoint": "openid://",
        },
        "authorization_details": dataclasses.asdict(create_authorization_request).get(
            "authorization_details"
        ),
    }
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)

    auth_req_token = AuthorizationRequestJWTToken(token=token.serialize())

    return auth_req_token


def create_id_token_response(
    create_id_token_response: CreateIDTokenResponse, key: jwk.JWK
) -> IDTokenResponseJWTToken:
    header = {"typ": "JWT", "alg": "ES256", "kid": create_id_token_response.kid}
    iat = int(time.time())
    exp = iat + 3600
    payload = {
        "iss": create_id_token_response.iss,
        "sub": create_id_token_response.sub,
        "aud": create_id_token_response.aud,
        "exp": exp,
        "iat": iat,
        "nonce": create_id_token_response.nonce,
        "state": create_id_token_response.state,
    }
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)

    auth_req_token = IDTokenResponseJWTToken(token=token.serialize())

    return auth_req_token


async def send_id_token_response(
    send_id_token_response: SendIDTokenResponse,
) -> AuthorizationCodeRedirectResponse:
    url = f"{send_id_token_response.direct_post_uri}"

    logger.info(f"Sending id token response to {url}")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            data="id_token="
            + send_id_token_response.id_token
            + "&state="
            + send_id_token_response.state,
            headers=headers,
            allow_redirects=False,
        ) as response:
            if response.status == 302:
                redirect_uri = response.headers["Location"]
                return AuthorizationCodeRedirectResponse(redirect_uri=redirect_uri)


async def send_token_request(send_token_request: SendTokenRequest) -> TokenResponse:
    url = f"{send_token_request.token_uri}"

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    data = (
        "grant_type="
        + send_token_request.grant_type
        + "&client_id="
        + send_token_request.client_id
        + "&code="
        + send_token_request.code
        + "&client_assertion_type="
        + send_token_request.client_assertion_type
        + "&client_assertion="
        + send_token_request.client_assertion
    )
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data, headers=headers) as response:
            if response.status == 200:
                token_dict = await response.json()
                return TokenResponse(**token_dict)
            else:
                logger.info(f"Error sending token request: {response.status}")
                raise TokenRequestError("Invalid response status")


def create_client_assertion(
    create_client_assertion: CreateClientAssertion, key: jwk.JWK
) -> ClientAssertionJWTToken:
    header = {"typ": "JWT", "alg": "ES256", "kid": create_client_assertion.kid}
    iat = int(time.time())
    exp = iat + 3600
    payload = {
        "iss": create_client_assertion.iss,
        "sub": create_client_assertion.sub,
        "aud": create_client_assertion.aud,
        "jti": create_client_assertion.jti,
        "exp": exp,
        "iat": iat,
    }
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)

    client_assertion_token = ClientAssertionJWTToken(token=token.serialize())

    return client_assertion_token


async def send_credential_request(
    send_credential_request: SendCredentialRequest,
) -> CredentialResponse:
    url = f"{send_credential_request.credential_uri}"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {send_credential_request.token}",
    }

    logger.info(f"Sending credential request to {url}")
    logger.info(
        f"Payload: {json.dumps(dataclasses.asdict(send_credential_request.payload))}"
    )

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            data=json.dumps(dataclasses.asdict(send_credential_request.payload)),
            headers=headers,
        ) as response:
            if response.status == 200:
                logger.info(f"Response status: {response.status}")
                credential_dict = await response.json()
                return from_dict(data_class=CredentialResponse, data=credential_dict)
            else:
                logger.info(f"Error sending credential request: {response.status}")
                logger.info(f"Response: {await response.text()}")
                raise CredentialRequestError("Invalid response status")


def create_credential_request(
    create_credential_request: CreateCredentialRequest, key: jwk.JWK
) -> CredentialRequestJWTToken:
    header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "kid": create_credential_request.kid,
    }
    payload = {
        "iss": create_credential_request.iss,
        "iat": int(time.time()),
        "aud": create_credential_request.aud,
        "exp": int(time.time()) + 86400,
        "nonce": create_credential_request.nonce,
    }
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)

    credential_request_token = CredentialRequestJWTToken(token=token.serialize())

    return credential_request_token


@dataclass
class GetPresentationDefinitionPayload(DataClassJsonMixin):
    presentation_definition_uri: str
    scope: str


@dataclass
class PresentationDefinition(DataClassJsonMixin):
    id: str
    input_descriptors: typing.List["InputDescriptor"]
    format: "Format"


@dataclass
class InputDescriptor(DataClassJsonMixin):
    id: str
    name: str
    purpose: str
    constraints: dict


@dataclass
class Format(DataClassJsonMixin):
    jwt_vc: dict
    jwt_vp: dict


class PresentationDefinitionError(Exception):
    pass


async def get_presentation_definition(
    payload: GetPresentationDefinitionPayload,
) -> PresentationDefinition:
    url = f"{payload.presentation_definition_uri}?scope={payload.scope}"

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                presentation_definition_dict = await response.json()
                return PresentationDefinition.from_dict(presentation_definition_dict)
            else:
                logger.info(f"Error getting presentation definition: {response.status}")
                raise PresentationDefinitionError(
                    "Error occured while getting presentation definition"
                )


@dataclass
class VerifiablePresentation(DataClassJsonMixin):
    context: typing.List[str] = field(metadata=config(field_name="@context"))
    id: str
    type: typing.List[str]
    holder: str
    verifiableCredential: typing.List[str]


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
    descriptor_map: typing.List[DescriptorMap]
    id: str = str(uuid.uuid4())


@dataclass
class CreateVPToken(DataClassJsonMixin):
    kid: str
    iss: str
    aud: str
    sub: str
    vp: VerifiablePresentation
    presentation_definition_id: str
    description_map_id: str
    nonce: str = str(uuid.uuid4())
    jti: str = f"urn:uuid:{str(uuid.uuid4())}"


@dataclass
class VPTokenJWT(DataClassJsonMixin):
    token: str
    presentation_submission: PresentationSubmission


def create_vp_token(payload: CreateVPToken, key: jwk.JWK) -> VPTokenJWT:
    header = {"typ": "JWT", "alg": "ES256", "kid": payload.kid}

    iat = int(time.time())
    nbf = iat
    exp = iat + 86400
    jwt_payload = {
        "iss": payload.iss,
        "aud": payload.aud,
        "sub": payload.sub,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "nonce": payload.nonce,
        "jti": payload.jti,
        "vp": payload.vp.to_dict(),
    }
    token = jwt.JWT(header=header, claims=jwt_payload)
    token.make_signed_token(key)

    presentation_submission = PresentationSubmission(
        definition_id=payload.presentation_definition_id,
        descriptor_map=[
            DescriptorMap(
                id=payload.description_map_id,
                path="$",
                format="jwt_vp",
                path_nested=DescriptorMapPath(
                    id=payload.description_map_id,
                    format="jwt_vc",
                    path="$.verifiableCredential[0]",
                ),
            )
        ],
    )
    vp_token = VPTokenJWT(
        token=token.serialize(), presentation_submission=presentation_submission
    )

    return vp_token


@dataclass
class SendVPToken(DataClassJsonMixin):
    token_uri: str
    grant_type: str
    scope: str
    vp_token: str
    presentation_submission: str


async def send_vp_token(payload: SendVPToken) -> TokenResponse:
    url = f"{payload.token_uri}"

    logger.info(f"Token URI: {url}")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    logger.info(f"VP token: {payload.vp_token}")
    logger.info(f"Presentation submission: {payload.presentation_submission}")

    data = (
        "grant_type="
        + payload.grant_type
        + "&scope="
        + payload.scope
        + "&vp_token="
        + payload.vp_token
        + "&presentation_submission="
        + payload.presentation_submission
    )
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data, headers=headers) as response:
            if response.status == 200:
                token_dict = await response.json()
                return TokenResponse(**token_dict)
            else:
                res_text = await response.text()
                logger.info(f"Error sending token request: {response.status}")
                logger.info(f"Response: {res_text}")
                raise TokenRequestError("Invalid response status")

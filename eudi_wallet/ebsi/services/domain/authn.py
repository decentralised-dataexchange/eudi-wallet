import time
import typing
from logging import Logger

from jwcrypto import jwk, jwt  # type: ignore
from jwcrypto.common import json_decode

from eudi_wallet.ebsi.exceptions.domain.authn import (
    AuthorizationCodeRedirectError,
    InvalidAccessTokenError,
    InvalidResponseStatusError,
)
from eudi_wallet.ebsi.services.domain.authn_request_builder import (
    AuthorizationRequestBuilder,
)
from eudi_wallet.ebsi.services.domain.utils.jwt import get_alg_for_key
from eudi_wallet.ebsi.utils.http_client import HttpClient
from eudi_wallet.ebsi.utils.jwt import decode_header_and_claims_in_jwt
from eudi_wallet.ebsi.value_objects.domain.authn import (
    AuthorizationCodeRedirectResponse,
    ClientAssertionJWTToken,
    CreateIDTokenResponse,
    DescriptorMap,
    DescriptorMapPath,
    IDTokenRequest,
    IDTokenRequestJWT,
    IDTokenResponseJWTToken,
    PresentationDefinition,
    PresentationSubmission,
    TokenResponse,
    VpJwtTokenPayloadModel,
)
from eudi_wallet.util import parse_query_string_parameters_from_url


class AuthnService:
    def __init__(
        self,
        authorization_endpoint: typing.Optional[str] = None,
        presentation_definition_endpoint: typing.Optional[str] = None,
        token_endpoint: typing.Optional[str] = None,
        logger: typing.Optional[Logger] = None,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.presentation_definition_endpoint = presentation_definition_endpoint
        self.token_endpoint = token_endpoint
        self.logger = logger

    def create_authorization_request(
        self,
        authn_request_jwt_payload: AuthorizationRequestBuilder.AuthorizationRequestJwtPayload,
        key_id: str,
        key: jwk.JWK,
    ) -> str:
        header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": key_id}
        token = jwt.JWT(header=header, claims=authn_request_jwt_payload.to_dict())
        token.make_signed_token(key)

        return token.serialize()

    async def send_authorization_request(
        self,
        client_id: str,
        scope: str,
        redirect_uri: str,
        request: str,
        nonce: str,
    ) -> IDTokenRequest:
        assert self.authorization_endpoint, "Authorization endpoint is not set"
        query_params = f"client_id={client_id}&response_type=code&scope={scope}&redirect_uri={redirect_uri}&request={request}&nonce={nonce}"
        url = f"{self.authorization_endpoint}?{query_params}"
        async with HttpClient() as http_client:
            response = await http_client.get(url)
        if response.status != 302:
            raise InvalidResponseStatusError("Invalid response status")

        location_header_value = response.headers["Location"].split("'")[0]

        query_params: dict[
            str, typing.List[str]
        ] = parse_query_string_parameters_from_url(location_header_value)

        error = query_params.get("error")
        if error:
            error_description = query_params.get("error_description")[0]
            raise AuthorizationCodeRedirectError(
                f"Error occured during authorization code redirect: {error_description}"
            )

        return IDTokenRequest(
            client_id=query_params.get("client_id", [""])[0],
            response_type=query_params.get("response_type", [""])[0],
            scope=query_params.get("scope", [""])[0],
            redirect_uri=query_params.get("redirect_uri", [""])[0],
            request_uri=query_params.get("request_uri", [""])[0],
            nonce=query_params.get("nonce", [""])[0],
        )

    async def get_id_token_request_jwt(self, request_uri: str) -> IDTokenRequestJWT:
        async with HttpClient() as http_client:
            response = await http_client.get(request_uri)
        if response.status != 200:
            raise InvalidResponseStatusError("Invalid response status")
        token_request_jwt = await response.text()
        decoded_token_request = decode_header_and_claims_in_jwt(token_request_jwt)
        return IDTokenRequestJWT(**decoded_token_request.claims)

    def create_id_token_response(
        self, create_id_token_response: CreateIDTokenResponse, key: jwk.JWK
    ) -> IDTokenResponseJWTToken:
        header = {
            "typ": "JWT",
            "alg": get_alg_for_key(key),
            "kid": create_id_token_response.kid,
        }
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
        self,
        direct_post_uri: str,
        id_token: str,
        state: str,
    ) -> AuthorizationCodeRedirectResponse:
        form_data = f"id_token={id_token}&state={state}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        async with HttpClient() as http_client:
            response = await http_client.post(direct_post_uri, form_data, headers)
        if response.status != 302:
            raise InvalidResponseStatusError("Invalid response status")
        location = response.headers["Location"]
        query_params = parse_query_string_parameters_from_url(location)

        error = query_params.get("error")
        if error:
            error_description = query_params.get("error_description")[0]
            raise AuthorizationCodeRedirectError(
                f"Error occured during authorization code redirect: {error_description}"
            )

        return AuthorizationCodeRedirectResponse(
            redirect_uri=location, code=query_params.get("code")[0]
        )

    def create_client_assertion(
        self, kid: str, iss: str, sub: str, aud: str, jti: str, key: jwk.JWK
    ) -> ClientAssertionJWTToken:
        header = {"typ": "JWT", "alg": "ES256", "kid": kid}
        iat = int(time.time())
        exp = iat + 3600
        payload = {
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "jti": jti,
            "exp": exp,
            "iat": iat,
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(key)

        client_assertion_token = ClientAssertionJWTToken(token=token.serialize())

        return client_assertion_token

    async def send_token_request(
        self,
        token_uri: str,
        client_id: str,
        code: str,
        client_assertion: str,
        client_assertion_type: str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        grant_type: str = "authorization_code",
    ) -> TokenResponse:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        form_data = f"grant_type={grant_type}&client_id={client_id}&code={code}&client_assertion_type={client_assertion_type}&client_assertion={client_assertion}"
        async with HttpClient() as http_client:
            response = await http_client.post(token_uri, form_data, headers)
        if response.status != 200:
            raise InvalidResponseStatusError("Invalid response status")
        token_dict = await response.json()
        return TokenResponse(**token_dict)

    async def get_presentation_definition(self, scope: str) -> PresentationDefinition:
        assert (
            self.presentation_definition_endpoint
        ), "Presentation definition endpoint is not set"
        url = f"{self.presentation_definition_endpoint}?scope={scope}"
        async with HttpClient() as http_client:
            response = await http_client.get(url)
        if response.status != 200:
            raise InvalidResponseStatusError("Invalid response status")
        presentation_definition_dict = await response.json()
        return PresentationDefinition.from_dict(presentation_definition_dict)

    @staticmethod
    def create_access_token(
        iss: str,
        aud: str,
        sub: str,
        iat: int,
        nbf: int,
        exp: int,
        nonce: str,
        kid: str,
        key: jwk.JWK,
        **kwargs,
    ) -> str:
        header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": kid}

        iat = int(time.time())
        nbf = iat
        exp = iat + 86400
        jwt_payload = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "nonce": nonce,
            **kwargs,
        }
        token = jwt.JWT(header=header, claims=jwt_payload)
        token.make_signed_token(key)

        return token.serialize()

    @staticmethod
    def verify_access_token(
        token: str,
        aud: str,
        sub: str,
        key: jwk.JWK,
    ) -> None:
        try:
            JWT = jwt.JWT(key=key, jwt=token)
            claims = JWT.claims

            # Verify claims
            claims_json = json_decode(claims)
            aud_claim = claims_json.get("aud", None)
            sub_claim = claims_json.get("sub", None)

            if aud_claim and aud_claim != aud:
                raise InvalidAccessTokenError(f"Invalid aud claim {aud_claim}")

            if sub_claim and sub_claim != sub:
                raise InvalidAccessTokenError(f"Invalid sub claim {sub_claim}")

        except jwt.JWTExpired:
            raise InvalidAccessTokenError(f"Access token {token} expired")

    def create_vp_token(self, payload: VpJwtTokenPayloadModel, key: jwk.JWK) -> str:
        header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": payload.kid}

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

        return token.serialize()

    def create_presentation_submission(
        self, presentation_definition_id: str = None, descriptor_map_id: str = None
    ) -> PresentationSubmission:
        presentation_submission = PresentationSubmission(
            definition_id=presentation_definition_id,
            descriptor_map=[
                DescriptorMap(
                    id=descriptor_map_id,
                    path="$",
                    format="jwt_vp",
                    path_nested=DescriptorMapPath(
                        id=descriptor_map_id,
                        format="jwt_vc",
                        path="$.verifiableCredential[0]",
                    ),
                )
            ]
            if descriptor_map_id
            else [],
        )
        return presentation_submission

    async def send_vp_token(
        self,
        grant_type: str,
        scope: str,
        vp_token: str,
        presentation_submission: str,
    ) -> TokenResponse:
        assert self.token_endpoint, "Token endpoint is not set"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = f"grant_type={grant_type}&scope={scope}&vp_token={vp_token}&presentation_submission={presentation_submission}"
        async with HttpClient() as http_client:
            response = await http_client.post(self.token_endpoint, data, headers)
        if response.status != 200:
            raise InvalidResponseStatusError("Invalid response status")
        token_dict = await response.json()
        return TokenResponse(**token_dict)

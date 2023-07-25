import time
import dataclasses
import base64
import json
from enum import Enum
import typing
from jwcrypto import jwk, jwt  # type: ignore
from eudi_wallet.ebsi.lib.auth.exceptions import InvalidResponseStatusError
from eudi_wallet.ebsi.lib.utils.http_client import HttpClient
from eudi_wallet.ebsi.lib.auth.models import (
    CreateAuthorizationRequest,
    AuthorizationRequestJWTToken,
    IDTokenRequest,
    IDTokenRequestJWT,
    IDTokenResponseJWTToken,
    AuthorizationCodeRedirectResponse,
    TokenResponse,
    ClientAssertionJWTToken,
    CreateIDTokenResponse,
    AuthorizationDetail,
    PresentationDefinition,
    VpJwtTokenPayloadModel,
    PresentationSubmission,
    DescriptorMap,
    DescriptorMapPath,
)
from eudi_wallet.util import (
    parse_query_string_parameters_from_url,
)


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


class AuthorizationRequestBuilder:
    def __init__(self, app, issuer_domain: str, authorization_server: str):
        self.app = app
        self.issuer_domain = issuer_domain
        self.authorization_server = authorization_server

    def _get_kid(self, key_did):
        return key_did.public_key_jwk.get("kid")

    def _get_endpoint_url(self, endpoint_url):
        return self.issuer_domain + endpoint_url

    def build_authorization_detail(
        self, credential_issuer_configuration, credential_types
    ):
        return AuthorizationDetail(
            locations=[credential_issuer_configuration.credential_issuer],
            types=credential_types,
        )

    def build_authorization_request(
        self,
        key_did,
        redirect_uri,
        jwks_uri,
        credential_issuer_configuration,
        credential_types,
    ):
        return CreateAuthorizationRequest(
            kid=self._get_kid(key_did),
            issuer_uri=self.issuer_domain,
            authorize_uri=self.authorization_server,
            redirect_uri=self._get_endpoint_url(redirect_uri),
            jwks_uri=self._get_endpoint_url(jwks_uri),
            authorization_details=[
                self.build_authorization_detail(
                    credential_issuer_configuration, credential_types
                )
            ],
        )


class AuthorizationClient:
    def __init__(
        self,
        authorization_endpoint: str | None = None,
        presentation_definition_endpoint: str | None = None,
        token_endpoint: str | None = None,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.presentation_definition_endpoint = presentation_definition_endpoint
        self.token_endpoint = token_endpoint

    def _construct_authorization_request_payload(
        self,
        create_authorization_request: CreateAuthorizationRequest,
        iat: int,
        exp: int,
    ) -> dict:
        return {
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
            "authorization_details": dataclasses.asdict(
                create_authorization_request
            ).get("authorization_details"),
        }

    def create_authorization_request(
        self, create_authorization_request: CreateAuthorizationRequest, key: jwk.JWK
    ) -> AuthorizationRequestJWTToken:
        header = {"typ": "JWT", "alg": "ES256", "kid": create_authorization_request.kid}
        iat = int(time.time())
        exp = iat + 3600
        payload = self._construct_authorization_request_payload(
            create_authorization_request, iat, exp
        )
        token = jwt.JWT(header=header, claims=payload)
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

        query_string_vals: dict[
            str, typing.List[str]
        ] = parse_query_string_parameters_from_url(location_header_value)
        return IDTokenRequest(
            client_id=query_string_vals.get("client_id", [""])[0],
            response_type=query_string_vals.get("response_type", [""])[0],
            scope=query_string_vals.get("scope", [""])[0],
            redirect_uri=query_string_vals.get("redirect_uri", [""])[0],
            request_uri=query_string_vals.get("request_uri", [""])[0],
            nonce=query_string_vals.get("nonce", [""])[0],
        )

    @staticmethod
    def _decode_claims_from_token_request_jwt(token_request_jwt: str) -> dict:
        claims_encoded = token_request_jwt.split(".")[1]
        claims_decoded = base64.b64decode(
            claims_encoded + "=" * (-len(claims_encoded) % 4)
        )
        return json.loads(claims_decoded)

    async def get_id_token_request_jwt(self, request_uri: str) -> IDTokenRequestJWT:
        async with HttpClient() as http_client:
            response = await http_client.get(request_uri)
        if response.status != 200:
            raise InvalidResponseStatusError("Invalid response status")
        token_request_jwt = await response.text()
        claims_dict = self._decode_claims_from_token_request_jwt(token_request_jwt)
        return IDTokenRequestJWT(**claims_dict)

    def create_id_token_response(
        self, create_id_token_response: CreateIDTokenResponse, key: jwk.JWK
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

    def create_vp_token(self, payload: VpJwtTokenPayloadModel, key: jwk.JWK) -> str:
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

        return token.serialize()

    def create_presentation_submission(
        self, presentation_definition_id: str, descriptor_map_id: str
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
            ],
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

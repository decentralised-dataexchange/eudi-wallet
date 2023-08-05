import dataclasses
import json
import logging
import time
import typing

from httpx import Response
from jwcrypto import jwk, jwt

from eudi_wallet.ebsi.exceptions.domain.issuer import (
    CredentialRequestError,
    ExpiredPreAuthorisedCodeTokenError,
    InvalidIssuerStateTokenError,
)
from eudi_wallet.ebsi.services.domain.utils.jwt import get_alg_for_key
from eudi_wallet.ebsi.utils.httpx_client import HttpxClient
from eudi_wallet.ebsi.value_objects.domain.issuer import (
    CredentialResponse,
    SendCredentialRequest,
)


class IssuerService:
    def __init__(
        self,
        credential_endpoint: typing.Optional[str] = None,
        logger: typing.Optional[logging.Logger] = None,
        credential_deferred_endpoint: typing.Optional[str] = None,
    ):
        self.credential_endpoint = credential_endpoint
        self.credential_deferred_endpoint = credential_deferred_endpoint
        self.logger = logger

    async def send_credential_deferred_request(
        self, acceptance_token
    ) -> CredentialResponse:
        assert (
            self.credential_deferred_endpoint is not None
        ), "No credential deferred endpoint set"
        headers = {
            "Authorization": f"Bearer {acceptance_token}",
        }

        async def is_credential_available(res: Response):
            return res.status_code == 200

        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.call_every_n_seconds(
                "post",
                self.credential_deferred_endpoint,
                is_credential_available,
                {},
                headers,
                5,
            )
        if response.status_code == 200:
            credential_dict = response.json()
            return CredentialResponse.from_dict(credential_dict)
        else:
            raise CredentialRequestError("Invalid response status")

    async def send_credential_request(
        self,
        send_credential_request: SendCredentialRequest,
    ) -> CredentialResponse:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {send_credential_request.token}",
        }
        data = json.dumps(dataclasses.asdict(send_credential_request.payload))
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.post(self.credential_endpoint, data, headers)
        if response.status_code == 200:
            credential_dict = response.json()
            return CredentialResponse.from_dict(credential_dict)
        else:
            raise CredentialRequestError("Invalid response status")

    def create_credential_request(
        self, kid: str, iss: str, aud: str, nonce: str, key: jwk.JWK
    ) -> str:
        header = {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "kid": kid,
        }
        payload = {
            "iss": iss,
            "iat": int(time.time()),
            "aud": aud,
            "exp": int(time.time()) + 86400,
            "nonce": nonce,
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(key)
        return token.serialize()

    def create_vp_token_request(
        self,
        state: str,
        iss: str,
        aud: str,
        exp: int,
        response_type: str,
        response_mode: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        nonce: str,
        key_id: str,
        key: jwk.JWK,
        presentation_definition: dict,
    ) -> str:
        header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": key_id}
        payload = {
            "state": state,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "response_mode": response_mode,
            "scope": scope,
            "nonce": nonce,
            "iss": iss,
            "aud": aud,
            "exp": exp,
            "presentation_definition": presentation_definition,
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(key)
        return token.serialize()

    def create_id_token_request(
        self,
        state: str,
        iss: str,
        aud: str,
        exp: int,
        response_type: str,
        response_mode: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        nonce: str,
        key_id: str,
        key: jwk.JWK,
    ) -> str:
        header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": key_id}
        payload = {
            "state": state,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "response_mode": response_mode,
            "scope": scope,
            "nonce": nonce,
            "iss": iss,
            "aud": aud,
            "exp": exp,
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(key)
        return token.serialize()

    @staticmethod
    def create_pre_authorised_code(
        iss: str,
        aud: str,
        sub: str,
        iat: int,
        nbf: int,
        exp: int,
        kid: str,
        key: jwk.JWK,
        credential_offer_id: str,
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
            "credential_offer_id": credential_offer_id,
            **kwargs,
        }
        token = jwt.JWT(header=header, claims=jwt_payload)
        token.make_signed_token(key)

        return token.serialize()

    @staticmethod
    def verify_pre_authorised_code(
        token: str,
        key: jwk.JWK,
    ) -> None:
        try:
            _ = jwt.JWT(key=key, jwt=token)
        except jwt.JWTExpired:
            raise ExpiredPreAuthorisedCodeTokenError(
                f"Issuer pre-authorised code expired: {token}"
            )

    @staticmethod
    def create_issuer_state(
        iss: str,
        aud: str,
        sub: str,
        iat: int,
        nbf: int,
        exp: int,
        kid: str,
        key: jwk.JWK,
        credential_offer_id: str,
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
            "credential_offer_id": credential_offer_id,
            **kwargs,
        }
        token = jwt.JWT(header=header, claims=jwt_payload)
        token.make_signed_token(key)

        return token.serialize()

    @staticmethod
    def verify_issuer_state(
        token: str,
        key: jwk.JWK,
    ) -> None:
        try:
            _ = jwt.JWT(key=key, jwt=token)
        except jwt.JWTExpired:
            raise InvalidIssuerStateTokenError(f"Issuer state token expired: {token}")

    @staticmethod
    def verify_vp_token(
        token: str,
        key: jwk.JWK,
    ) -> None:
        try:
            _ = jwt.JWT(key=key, jwt=token)
        except jwt.JWTExpired:
            raise InvalidIssuerStateTokenError(f"Issuer state token expired: {token}")

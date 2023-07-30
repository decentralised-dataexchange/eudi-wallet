import dataclasses
import json
import logging
import time
import typing

from jwcrypto import jwk, jwt

from eudi_wallet.ebsi.exceptions.domain.issuer import CredentialRequestError
from eudi_wallet.ebsi.utils.http_client import HttpClient
from eudi_wallet.ebsi.value_objects.domain.issuer import (
    CredentialResponse, SendCredentialRequest)


class IssuerService:
    def __init__(
        self,
        credential_endpoint: typing.Optional[str] = None,
        logger: typing.Optional[logging.Logger] = None,
    ):
        self.credential_endpoint = credential_endpoint
        self.logger = logger

    async def send_credential_request(
        self,
        send_credential_request: SendCredentialRequest,
    ) -> CredentialResponse:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {send_credential_request.token}",
        }
        data = json.dumps(dataclasses.asdict(send_credential_request.payload))
        async with HttpClient() as http_client:
            response = await http_client.post(self.credential_endpoint, data, headers)
        if response.status == 200:
            credential_dict = await response.json()
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

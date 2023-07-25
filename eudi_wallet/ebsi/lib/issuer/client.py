import logging
import json
import dataclasses
import time
from jwcrypto import jwk, jwt
from eudi_wallet.ebsi.lib.utils.http_client import HttpClient
from eudi_wallet.ebsi.lib.issuer.models import (
    CredentialResponse,
    SendCredentialRequest,
)
from eudi_wallet.ebsi.lib.issuer.exceptions import (
    CredentialRequestError,
)

logger = logging.getLogger(__name__)


class IssuerClient:
    def __init__(self, credential_endpoint: str):
        self.credential_endpoint = credential_endpoint

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

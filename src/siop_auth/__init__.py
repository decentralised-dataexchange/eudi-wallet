import json

from src.ebsi_client import EbsiClient
from ..ethereum import Ethereum
from urllib import parse

from .util import get_jwk, sign_did_auth_internal, aes_cbc_ecies_decrypt
from src.did_jwt import verify_jwt


class Agent:

    def __init__(self, private_key, did_registry):

        # Private key associated with Ethereum EOA.
        self._private_key = private_key

        # DID registry URL.
        self._did_registry = did_registry

    @property
    def private_key(self):
        return self._private_key

    @property
    def did_registry(self):
        return self._did_registry

    @private_key.setter
    def private_key(self, private_key):
        self._private_key = private_key

    @did_registry.setter
    def did_registry(self, did_registry):
        self._did_registry = did_registry

    async def create_authentication_response(self, did, nonce, redirect_uri, eth_client: Ethereum, claims={}):
        """
        Creates an authentication response.
        """

        SELF_ISSUED_V2 = "https://self-issued.me/v2"

        payload = {
            "iss": SELF_ISSUED_V2,
            "sub": eth_client.jwk_thumbprint,
            "aud": redirect_uri,
            "nonce": nonce,
            "sub_jwk": await get_jwk(f"{did}#key-1", eth_client),
            "did": did,
            "claims": {
                **claims
            }
        }

        jwt = await sign_did_auth_internal(did, payload, eth_client.private_key)

        url_response = {
            "urlEncoded": redirect_uri,
            "encoding": "application/x-www-form-urlencoded",
            "responseMode": "fragment",
            "bodyEncoded": jwt
        }

        return url_response

    async def verify_authentication_request(self, jwt):

        options = {
            "registry": self.did_registry
        }

        verified_jwt = await verify_jwt(jwt, options)

        return verified_jwt[0]

    async def verify_authentication_response(self, response, nonce, client: EbsiClient):

        ake1_enc_payload = response.get("ake1_enc_payload")

        decrypted_payload = await aes_cbc_ecies_decrypt(ake1_enc_payload, client)

        assert decrypted_payload.get(
            "did"), "DID not found in decrypted payload"
        assert decrypted_payload.get(
            "access_token"), "Access token not found in decrypted payload"

        decrypted_payload_nonce = decrypted_payload.get("nonce")

        if decrypted_payload_nonce:
            assert decrypted_payload_nonce == nonce, "Nonce mismatch"

        # TODO: Verify access token (JWT), audience : "ebsi-core-services"

        return decrypted_payload.get("access_token")

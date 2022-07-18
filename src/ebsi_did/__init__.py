import secrets
import base64
from multibase import encode
from ..ethereum import Ethereum


class EbsiDid:

    def __init__(self, did_version: int = 1):
        self._did = None
        self._did_version = did_version

    def generate_did(self, eth: Ethereum = None):
        if self.did_version == 2:
            self.generate_did_v2(eth=eth)
        else:
            self.generate_did_v1()

    def generate_did_v1(self):
        buffer = secrets.token_bytes(16)
        buffer = (1).to_bytes(2, 'big') + buffer
        self._did = encode("base58btc", buffer).decode("utf-8")
        self._did = f"did:ebsi:{self.did}"

    def generate_did_v2(self, eth: Ethereum):
        thumbprint = eth.jwk_thumbprint
        subject_identifier = base64.urlsafe_b64decode(thumbprint + "==")
        buffer = (1).to_bytes(2, 'big') + subject_identifier
        self._did = encode("base58btc", buffer).decode("utf-8")
        self._did = f"did:ebsi:{self.did}"

    @property
    def did(self):
        return self._did

    @property
    def did_version(self):
        return self._did_version

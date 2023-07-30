import random
import secrets

from jwcrypto.common import base64url_decode
from multibase import encode

from eudi_wallet.ethereum import Ethereum


class EbsiDid:
    def __init__(self, did_version: str = "v1", seed: bytes = None):
        self._did = None
        self._did_version = did_version
        self._seed = seed

    def generate_did(self, eth: Ethereum = None):
        if self.did_version == "v2":
            self.generate_did_v2(eth=eth)
        else:
            self.generate_did_v1()

    def generate_did_v1(self):
        if self._seed:
            rand_gen = random.Random(self._seed)
            buffer = bytearray(rand_gen.getrandbits(8) for _ in range(16))
            buffer = (1).to_bytes(2, "big") + bytes(buffer)
        else:
            buffer = secrets.token_bytes(16)
            buffer = (1).to_bytes(2, "big") + buffer
        self._did = encode("base58btc", buffer).decode("utf-8")
        self._did = f"did:ebsi:{self._did}"

    def generate_did_v2(self, eth: Ethereum):
        thumbprint = eth.jwk_thumbprint
        subject_identifier = base64url_decode(thumbprint)
        buffer = (2).to_bytes(2, "big") + subject_identifier
        self._did = encode("base58btc", buffer).decode("utf-8")
        self._did = f"did:ebsi:{self.did}"

    @property
    def did(self):
        return self._did

    @property
    def did_version(self):
        return self._did_version

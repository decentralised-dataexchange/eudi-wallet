import secrets

from multibase import encode


class EbsiDid:

    def __init__(self):
        self._did = None

    def generate_did(self):
        buffer = secrets.token_bytes(16)
        buffer = (1).to_bytes(2, 'big') + buffer
        self._did = encode("base58btc", buffer).decode("utf-8")
        self._did = f"did:ebsi:{self.did}"

    @property
    def did(self):
        return self._did

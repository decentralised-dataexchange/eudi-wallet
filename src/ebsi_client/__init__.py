from ..ethereum import Ethereum
from ..ebsi_did import EbsiDid


class EbsiClient:

    def __init__(self, did_version: str = "v1") -> None:

        self._ebsi_did = EbsiDid(did_version)
        self._eth = Ethereum()
        self._did_version = did_version

    @property
    def did_version(self):
        return self._did_version

    @property
    def ebsi_did(self) -> EbsiDid:
        return self._ebsi_did

    @property
    def eth(self) -> Ethereum:
        return self._eth

    def generate_did_document(self) -> str:
        return {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": f"{self._ebsi_did.did}",
            "verificationMethod": [
                {
                    "id": f"{self._ebsi_did.did}#keys-1",
                    "type": "Secp256k1VerificationKey2018",
                    "controller": f"{self._ebsi_did.did}",
                    "publicKeyJwk": {key: value for key, value in self._eth.public_key_to_jwk().items() if key != "kid"}
                }
            ],
            "authentication": [
                f"{self._ebsi_did.did}#keys-1",
            ],
            "assertionMethod": [
                f"{self._ebsi_did.did}#keys-1",
            ],
        }

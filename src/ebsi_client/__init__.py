from ..ethereum import Ethereum
from ..ebsi_did import EbsiDid


class EbsiClient:

    def __init__(self) -> None:

        self._ebsi_did = EbsiDid()
        self._eth = Ethereum()

    @property
    def ebsi_did(self) -> EbsiDid:
        return self._ebsi_did

    @property
    def eth(self) -> Ethereum:
        return self._eth

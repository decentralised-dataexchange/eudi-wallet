from eth_keys import KeyAPI
from . import Ethereum


async def recover_public_key_from_private_key(eth: Ethereum) -> str:
    """
    Recovers the public key from the private key.

    Args:
        hex: Public key in hex format.
    """

    keys = KeyAPI('eth_keys.backends.CoinCurveECCBackend')

    private_key = KeyAPI.PrivateKey(eth.private_key)

    return keys.private_key_to_public_key(private_key).to_hex()

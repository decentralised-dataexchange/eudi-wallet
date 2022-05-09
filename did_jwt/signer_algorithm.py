import hashlib
from .util import to_jose, leftpad
from eth_keys import KeyAPI


async def ES256K_signer_algorithm(private_key):
    """
    Return ES256K signer function for the given private key.

    Args:
        private_key_hex: Private key in hex string.
    """

    async def sign(payload: str) -> str:
        """
        Signs the payload.

        Args:
            payload: Payload to sign.

        Returns:
            str: Signature.
        """

        keys = KeyAPI('eth_keys.backends.CoinCurveECCBackend')

        sk = KeyAPI.PrivateKey(private_key)

        signature = keys.ecdsa_sign(hashlib.sha256(
            payload.encode('utf-8')).digest(), sk)

        # FIXME: recoverable=True doesn't work.
        jose_repr = to_jose(
            hex(signature.r),
            hex(signature.s),
            signature.v,
            recoverable=False
        )

        return jose_repr

    return sign

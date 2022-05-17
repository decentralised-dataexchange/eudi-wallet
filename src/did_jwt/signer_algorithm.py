import hashlib
import base64
from .util import to_jose
from eth_keys import KeyAPI
from src.util import pad_base64
from coincurve.keys import PublicKey


def to_signature_object(signature):
    sig = pad_base64(signature)

    decoded_sig = base64.urlsafe_b64decode(sig)

    r = decoded_sig[:32].hex()
    s = decoded_sig[32:].hex()

    sig_obj = {
        "r": r,
        "s": s
    }

    return sig_obj


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


async def verify_ES256K(data, sig, authenticator) -> bool:
    """
    Verify the signature of the data.

    Args:
        data: Data to verify.
        signature: Signature to verify.
        authenticator: Authenticator to verify.
    """

    keys = KeyAPI('eth_keys.backends.CoinCurveECCBackend')

    pub_key_x = authenticator["publicKeyJwk"]["x"]
    pub_key_y = authenticator["publicKeyJwk"]["y"]

    pub_key_x_bytes = base64.urlsafe_b64decode(pad_base64(pub_key_x))
    pub_key_y_bytes = base64.urlsafe_b64decode(pad_base64(pub_key_y))

    int_x = int.from_bytes(pub_key_x_bytes, byteorder="big")
    int_y = int.from_bytes(pub_key_y_bytes, byteorder="big")

    sig = pad_base64(sig)

    decoded_sig = base64.urlsafe_b64decode(sig)

    r = int.from_bytes(decoded_sig[:32], byteorder="big")
    s = int.from_bytes(decoded_sig[32:], byteorder="big")

    signature = keys.Signature(vrs=(0, r, s))

    public_key_cc = PublicKey.from_point(int_x, int_y)

    public_key_cc_compressed_bytes = public_key_cc.format()

    public_key_ethk = keys.PublicKey.from_compressed_bytes(
        public_key_cc_compressed_bytes)

    msg_bytes = hashlib.sha256(data.encode('utf-8')).digest()

    verify = keys.ecdsa_verify(msg_bytes, signature, public_key_ethk)

    return verify

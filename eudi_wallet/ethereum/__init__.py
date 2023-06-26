import json
import secrets
import typing

from coincurve import PrivateKey, PublicKey
from jwcrypto import jwk
from sha3 import keccak_256


class Ethereum:
    def __init__(self):

        # Ethereum private keys are 32 bytes long.
        self._private_key = keccak_256(secrets.token_bytes(32)).digest()

        # Ethereum public keys are 64 bytes long.
        # Uncompressed public key is 65 bytes long.
        # [1:] is for stripping out the byte that represents compressed or uncompressed format.
        # After stripping, size becomes 64 bytes long.
        self._public_key = PublicKey.from_valid_secret(self._private_key).format(
            compressed=False
        )[1:]

        # Ethereum address is 20 bytes long.
        # Address is the rightmost 20 bytes of the public key keccak-256 hash.
        self._eoa_address = keccak_256(self._public_key).digest()[-20:]

    @property
    def private_key(self):
        """
        Returns the private key.

        Returns:
            hex: Private key.
        """
        return self._private_key

    @property
    def public_key(self):
        """
        Returns the public key.

        Returns:
            bytes: Public key.
        """
        return self._public_key

    @property
    def eoa_address(self):
        """
        Returns the Ethereum address.
        """
        return self._eoa_address

    @property
    def eoa_address_hex(self):
        """
        Returns the ethereum address in hex format with 0x prefix.
        """
        return "0x" + self._eoa_address.hex()

    @property
    def private_key_hex(self):
        """
        Returns the private key in hex format.
        """
        return self._private_key.hex()

    @property
    def public_key_hex(self):
        """
        Returns the hex string of the public key.
        """
        return self._public_key.hex()

    def private_key_from_hex(self) -> PrivateKey:
        """
        Returns the private key from the hex string.

        Returns:
            PrivateKey: Private key.
        """
        return PrivateKey.from_hex(self.private_key_hex)

    def public_key_from_private_key(self) -> PublicKey:
        """
        Returns the public key from the private key.

        Returns:
            PublicKey: Public key.
        """
        return PublicKey.from_valid_secret(self._private_key)

    def public_key_export_point(self) -> typing.Tuple[int, int]:
        """
        Returns the x and y coordinates of the public key.

        Returns:
            Tuple[int, int]: x and y coordinates of the public key.
        """
        return self.public_key_from_private_key().point()

    def public_key_to_jwk(self) -> dict:
        """
        Returns the public key in JWK format.

        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "cdfNOPbpuw9oiafGhAu2xwvgM7z5sBQJCsfj-WKjDBY",
            "y": "RUrM3fNy-GCWIGPc4NIUYmW6w8WNN5JAfCE2ZmbCpN8"
        }

        Returns:
            dict: Public key in JWK format.
        """
        key = jwk.JWK.from_pem(self.private_key_from_hex().to_pem())
        return json.loads(key.export_public())

    def private_key_to_jwk(self) -> dict:
        """
        Returns the private key in JWK format.

        Returns:
            dict: Private key in JWK format.
        """
        key = jwk.JWK.from_pem(self.private_key_from_hex().to_pem())
        return json.loads(key.export_private())

    @property
    def jwk_thumbprint(self) -> str:
        """
        Returns the JWK thumbprint.

        Returns:
            str: JWK thumbprint.
        """
        key = jwk.JWK.from_pem(self.private_key_from_hex().to_pem())

        return key.thumbprint()

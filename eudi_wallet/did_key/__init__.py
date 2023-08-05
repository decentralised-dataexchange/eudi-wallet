import binascii
import dataclasses
import json
import time
import typing
import uuid
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk, jwt
from multiformats import multibase, multicodec


@dataclass
class PublicKeyJWK:
    crv: str
    kty: str
    x: str
    y: str


class KeyDid:
    def __init__(self, seed):
        self._seed = seed
        self._did = None
        self._method_specific_id = None
        self._private_key_jwk = None
        self._public_key_jwk = None
        self._key = None
        self._public_key = None

    @property
    def did(self):
        return self._did

    @property
    def private_key_jwk(self):
        return self._private_key_jwk

    @property
    def public_key_jwk(self):
        return self._public_key_jwk

    def create_keypair(self):
        curve = ec.SECP256R1()
        private_key = ec.derive_private_key(
            int.from_bytes(self._seed, "big"), curve, default_backend()
        )
        public_key = private_key.public_key()

        private_key_jwk = jwk.JWK.from_pem(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_key_jwk = jwk.JWK.from_pem(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        self._key = private_key_jwk
        self._public_key = public_key_jwk
        self._public_key_jwk = public_key_jwk.export_public(as_dict=True)
        self._private_key_jwk = private_key_jwk.export_private(as_dict=True)

        # self._key = jwk.JWK.generate(kty='EC', crv='P-256')
        # self._public_key_jwk = self._key.export_public(as_dict=True)
        # self._private_key_jwk = self._key.export_private(as_dict=True)

    def generate_did(self, jwk: PublicKeyJWK):
        # Convert jwk to json string
        jwk_json = json.dumps(dataclasses.asdict(jwk), separators=(",", ":"))
        # UTF-8 encode the json string
        jwk_json_utf8 = jwk_json.encode("utf-8")
        # multicodec wrap the utf-8 encoded bytes with jwk_jcs-pub (0xeb51) codec identifier
        jwk_multicodec = multicodec.wrap(
            "jwk_jcs-pub", jwk_json_utf8
        )  # multibase base58-btc encode the jwk_multicodec bytes
        jwk_multibase = multibase.encode(jwk_multicodec, "base58btc")
        # prefix the string with 'did:key:'
        self._did = "did:key:" + jwk_multibase
        self._method_specific_id = jwk_multibase

    def method_specific_identifier_to_jwk(
        self, method_specific_identifier: str
    ) -> jwk.JWK:
        decoded = multibase.decode(method_specific_identifier)
        _, raw_data = multicodec.unwrap(decoded)
        jwk_str = raw_data.decode("utf-8")
        jwk_dict = json.loads(jwk_str)
        return jwk.JWK(**jwk_dict)

    def generate_id_token(self, did: str = None, auth_server_uri: str = None, nonce: str = None) -> str:
        header = {
            "typ": "JWT",
            "alg": "ES256",
            "kid": f"{did or self._did}#{self._key.key_id}",
        }
        payload = {
            "iss": did or self._did,
            "sub": did or self._did,
            "aud": auth_server_uri,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nonce": nonce,
        }

        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self._key)

        return token.serialize()

    def generate_credential_request(self, did: str = None, issuer_uri: str = None, nonce: str = None) -> str:
        header = {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "kid": f"{did or self._did}#{self._key.key_id}",
        }
        payload = {
            "iss": self._did,
            "iat": int(time.time()),
            "aud": issuer_uri,
            "exp": int(time.time()) + 86400,
            "nonce": nonce,
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self._key)

        return token.serialize()

    def generate_vp_token_response(
        self, auth_server_uri: str, nonce: str, verifiable_credentials: typing.List[str]
    ) -> str:
        header = {
            "typ": "JWT",
            "alg": "ES256",
            "kid": f"{self._did}#{self._method_specific_id}",
        }

        iat = int(time.time())
        exp = iat + 3600
        nbf = iat
        jti = f"urn:uuid:{uuid.uuid4()}"
        payload = {
            "iss": self._did,
            "sub": self._did,
            "aud": auth_server_uri,
            "exp": exp,
            "iat": iat,
            "nbf": nbf,
            "nonce": nonce,
            "jti": jti,
            "vp": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "id": jti,
                "type": ["VerifiablePresentation"],
                "holder": self._did,
                "verifiableCredential": verifiable_credentials,
            },
        }

        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self._key)

        return token.serialize()

    def generate_sd_jwt(self, _sd: typing.List[str]) -> str:
        header = {
            "alg": "ES256",
        }
        iat = int(time.time())
        exp = iat + 3600
        payload = {
            "_sd": _sd,
            "iss": "https://issuer.igrant.io",
            "iat": iat,
            "exp": exp,
            "_sd_alg": "sha-256",
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self._key)

        return token.serialize()

    @property
    def jwk_thumbprint(self) -> str:
        return self._public_key.thumbprint()

    @property
    def public_key_hex(self) -> str:
        return binascii.hexlify(
            json.dumps(
                self._public_key.export_public(as_dict=True), separators=(",", ":")
            ).encode("utf-8")
        ).decode()

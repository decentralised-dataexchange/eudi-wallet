import json
import dataclasses
import time
from dataclasses import dataclass
from multiformats import multicodec, multibase
from jwcrypto import jwk, jwt

@dataclass
class PublicKeyJWK:
    crv: str
    kty: str
    x: str
    y: str

class KeyDid:
    def __init__(self):
        self._did = None
        self._method_specific_id = None
        self._private_key_jwk = None
        self._public_key_jwk = None
        self._key = None
    
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
        self._key = jwk.JWK.generate(kty='EC', crv='P-256')
        self._public_key_jwk = self._key.export_public(as_dict=True)
        self._private_key_jwk = self._key.export_private(as_dict=True)
    
    def generate_did(self, jwk: PublicKeyJWK):
        # Convert jwk to json string
        jwk_json = json.dumps(dataclasses.asdict(jwk), separators=(',', ':'))
        # UTF-8 encode the json string
        jwk_json_utf8 = jwk_json.encode('utf-8')
        # multicodec wrap the utf-8 encoded bytes with jwk_jcs-pub (0xeb51) codec identifier
        jwk_multicodec = multicodec.wrap('jwk_jcs-pub', jwk_json_utf8)\
        # multibase base58-btc encode the jwk_multicodec bytes
        jwk_multibase = multibase.encode(jwk_multicodec, 'base58btc')
        # prefix the string with 'did:key:'
        self._did = 'did:key:' + jwk_multibase
        self._method_specific_id = jwk_multibase
    
    def generate_id_token(self, auth_server_uri: str, nonce: str) -> str:
        header = {
            "typ": 'JWT',
            "alg": 'ES256',
            "kid": f'{self._did}#{self._method_specific_id}'
        }
        payload = {
            "iss": self._did,
            "sub": self._did,
            "aud": auth_server_uri,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nonce": nonce
        }

        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(self._key)

        return token.serialize()
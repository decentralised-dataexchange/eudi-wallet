import hmac
import json
import sslcrypto
import typing
import dataclasses
import urllib.parse
import hashlib
import base64
import secrets
import string
from dataclasses import dataclass
from coincurve import PublicKey
from ebsi_wallet.did_jwt import create_jwt, decode_jwt
from ebsi_wallet.did_jwt.signer_algorithm import ES256K_signer_algorithm
from ebsi_wallet.ethereum import Ethereum
from ebsi_wallet.util import (
    http_call, 
    http_call_text, 
    http_call_text_redirects_disabled,
    parse_query_string_parameters_from_url
)


def get_audience(jwt):
    decoded_jwt = decode_jwt(jwt)

    payload = decoded_jwt.get("payload")

    assert payload is not None, "No payload found"

    audience = payload.get("aud")

    return audience


async def get_jwk(kid: str, eth_client: Ethereum) -> dict:
    """
    Returns the JWK for the given kid.
    """

    return {**eth_client.public_key_to_jwk(), "kid": kid}


async def sign_did_auth_internal(did, payload, private_key):
    """
    Signs the payload with the given private key.
    """

    header = {
        "alg": "ES256K",
        "typ": "JWT",
        "kid": f"{did}#key-1",
    }

    SELF_ISSUED_V2 = "https://self-issued.me/v2"

    response = await create_jwt(
        {**payload},
        {
            "issuer": SELF_ISSUED_V2,
            "signer": await ES256K_signer_algorithm(private_key),
        },
        header,
    )

    return response


async def aes_cbc_ecies_decrypt(ake1_enc_payload, client):
    private_key = client.eth.private_key

    ake1_enc_payload_bytes = bytes.fromhex(ake1_enc_payload)

    iv = ake1_enc_payload_bytes[:16]
    ephermal_public_key = ake1_enc_payload_bytes[16:49]
    mac = ake1_enc_payload_bytes[49:81]
    ciphertext = ake1_enc_payload_bytes[81:]

    cc_ephermal_public_key = PublicKey(ephermal_public_key)

    enc_jwe = {
        "iv": iv.hex(),
        "ephermal_public_key": cc_ephermal_public_key.format(False).hex(),
        "mac": mac.hex(),
        "ciphertext": ciphertext.hex(),
    }

    curve = sslcrypto.ecc.get_curve("secp256k1")

    ecdh = curve.derive(private_key, bytes.fromhex(enc_jwe.get("ephermal_public_key")))
    key = curve._digest(ecdh, "sha512")

    k_enc_len = curve._aes.get_algo_key_length("aes-256-cbc")
    if len(key) < k_enc_len:
        raise ValueError("Too short digest")
    k_enc, k_mac = key[:k_enc_len], key[k_enc_len:]

    orig_ciphertext = (
        bytes.fromhex(enc_jwe.get("iv"))
        + bytes.fromhex(enc_jwe.get("ephermal_public_key"))
        + bytes.fromhex(enc_jwe.get("ciphertext"))
    )
    tag = bytes.fromhex(enc_jwe.get("mac"))

    # Verify MAC tag
    h = hmac.new(k_mac, digestmod="sha256")
    h.update(orig_ciphertext)
    expected_tag = h.digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Invalid MAC tag")

    decrypted = curve._aes.decrypt(
        ciphertext, bytes.fromhex(enc_jwe.get("iv")), k_enc, algo="aes-256-cbc"
    )

    return json.loads(decrypted.decode("utf-8"))

@dataclass
class Credential:
    format: str
    types: typing.List[str]
    trust_framework: typing.Dict[str, str]

@dataclass
class Grants:
    authorization_code: typing.Dict[str, str]

@dataclass
class CredentialOffer:
    credential_issuer: str
    credentials: typing.List[Credential]
    grants: Grants

async def accept_and_fetch_credential_offer(credential_offer_uri: str) -> CredentialOffer:
    cred_offer = await http_call(credential_offer_uri, "GET", data=None, headers=None)
    return CredentialOffer(**cred_offer)


@dataclass
class TrustFramework:
    name: str
    type: str
    uri: str

@dataclass
class Display:
    name: str
    locale: str

@dataclass
class Credential:
    format: str
    types: typing.List[str]
    trust_framework: TrustFramework
    display: typing.List[Display]

@dataclass
class OpenIDCredentialIssuerConfig:
    credential_issuer: str
    authorization_server: str
    credential_endpoint: str
    deferred_credential_endpoint: str
    credentials_supported: typing.List[Credential]

async def fetch_openid_credential_issuer_configuration(credential_issuer_uri: str) -> OpenIDCredentialIssuerConfig:
    wellknown_uri = credential_issuer_uri + "/.well-known/openid-credential-issuer"
    openid_credential_issuer_config = await http_call(wellknown_uri, "GET", data=None, headers=None)
    return OpenIDCredentialIssuerConfig(**openid_credential_issuer_config)

@dataclass
class RequestAuthenticationMethodsSupported:
    authorization_endpoint: typing.List[str]

@dataclass
class JWKSSupported:
    alg_values_supported: typing.List[str]

@dataclass
class VPFormatsSupported:
    jwt_vp: JWKSSupported
    jwt_vc: JWKSSupported

@dataclass
class OpenIDAuthServerConfig:
    redirect_uris: typing.List[str]
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    scopes_supported: typing.List[str]
    response_types_supported: typing.List[str]
    response_modes_supported: typing.List[str]
    grant_types_supported: typing.List[str]
    subject_types_supported: typing.List[str]
    id_token_signing_alg_values_supported: typing.List[str]
    request_object_signing_alg_values_supported: typing.List[str]
    request_parameter_supported: bool
    request_uri_parameter_supported: bool
    token_endpoint_auth_methods_supported: typing.List[str]
    request_authentication_methods_supported: RequestAuthenticationMethodsSupported
    vp_formats_supported: VPFormatsSupported
    subject_syntax_types_supported: typing.List[str]
    subject_syntax_types_discriminations: typing.List[str]
    subject_trust_frameworks_supported: typing.List[str]
    id_token_types_supported: typing.List[str]

async def fetch_openid_auth_server_configuration(authorization_server_uri: str) -> dict:
    wellknown_uri = authorization_server_uri + "/.well-known/openid-configuration"
    openid_auth_server_config = await http_call(wellknown_uri, "GET", data=None, headers=None)
    return OpenIDAuthServerConfig(**openid_auth_server_config)

@dataclass
class AuthorizationRequestQueryParams:
    response_type: str
    scope: str
    state: str
    client_id: str
    authorization_details: str
    redirect_uri: str
    nonce: str
    code_challenge: str
    code_challenge_method: str
    client_metadata: str
    issuer_state: str

async def perform_authorization(authorization_server_uri: str,
                                query_params: AuthorizationRequestQueryParams) -> str:
    encoded_params = urllib.parse.urlencode(dataclasses.asdict(query_params))
    auth_url = f'{authorization_server_uri}?{encoded_params}'
    issuer_authorize_response = await http_call_text_redirects_disabled(auth_url, 
                                                                        "GET", 
                                                                        data=None, 
                                                                        headers=None)
    return issuer_authorize_response


async def fetch_credential_offer(client_id):
    url = 'https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer'
    params = {
        'credential_type': 'CTWalletCrossInTime',
        'client_id': client_id,
        'credential_offer_endpoint': 'openid-credential-offer://'
    }
    encoded_params = urllib.parse.urlencode(params)
    url = f'{url}?{encoded_params}'

    resp = await http_call_text(url, "GET")
    return resp

@dataclass
class AuthorizationResponseQueryParams:
    state: str
    client_id: str
    redirect_uri: str
    response_type: str
    response_mode: str
    scope: str
    nonce: str
    request_uri: str

def get_authorization_response_query_params(authorization_response_uri: str) -> AuthorizationResponseQueryParams:
    query_params = parse_query_string_parameters_from_url(authorization_response_uri)

    state = query_params.get('state', [''])[0]
    client_id = query_params.get('client_id', [''])[0]
    redirect_uri = query_params.get('redirect_uri', [''])[0]
    response_type = query_params.get('response_type', [''])[0]
    response_mode = query_params.get('response_mode', [''])[0]
    scope = query_params.get('scope', [''])[0]
    nonce = query_params.get('nonce', [''])[0]
    request_uri = query_params.get('request_uri', [''])[0]

    return AuthorizationResponseQueryParams(state, 
                                            client_id, 
                                            redirect_uri, 
                                            response_type, 
                                            response_mode, 
                                            scope, nonce, 
                                            request_uri)

def generate_code_verifier(length=128):
    valid_characters = string.ascii_letters + string.digits + "-._~"
    code_verifier = ''.join(secrets.choice(valid_characters) for _ in range(length))
    return code_verifier

def generate_code_challenge(code_verifier: str) -> str:
    if len(code_verifier) < 43 or len(code_verifier) > 128:
        raise ValueError("code_verifier must be between 43 and 128 characters long.")
    valid_characters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    if not all(char in valid_characters for char in code_verifier):
        raise ValueError("code_verifier contains invalid characters.")
    code_verifier_bytes = code_verifier.encode("utf-8")
    sha256_hash = hashlib.sha256(code_verifier_bytes).digest()
    base64url_encoded = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode("utf-8")

    return base64url_encoded

async def send_id_token_response(auth_server_direct_post_uri: str,
                                id_token: str,
                                state: str) -> str:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    issuer_authorize_response = await http_call_text_redirects_disabled(auth_server_direct_post_uri, 
                                                                        "POST", 
                                                                        data="id_token=" + id_token + "&state=" + state, 
                                                                        headers=headers)
    return issuer_authorize_response

@dataclass
class AccessTokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    id_token: str
    c_nonce: str
    c_nonce_expires_in: int

async def exchange_auth_code_for_access_token(token_uri: str,
                                              client_id: str,
                                              code: str,
                                              code_verifier: str) -> AccessTokenResponse:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    query_params = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "code_verifier": code_verifier
    }
    encoded_params = urllib.parse.urlencode(query_params)
    access_token_response = await http_call(token_uri,
                                                "POST",
                                                data=encoded_params,
                                                headers=headers)
    return AccessTokenResponse(**access_token_response)

async def send_credential_request(credentials_uri: str,
                                  access_token: str,
                                  credential_request_jwt: str):

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    data = {
        "types": ["VerifiableCredential","VerifiableAttestation","CTWalletCrossInTime"],
        "format": "jwt_vc",
        "proof": {
            "proof_type": "jwt",
            "jwt": credential_request_jwt
        }
    }
    print(access_token)

    credential_response = await http_call(credentials_uri, "POST", data=json.dumps(data),headers=headers)

    return credential_response

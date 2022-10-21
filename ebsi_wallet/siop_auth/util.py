import hmac
import json

import sslcrypto
from coincurve import PublicKey
from ebsi_wallet.did_jwt import create_jwt, decode_jwt
from ebsi_wallet.did_jwt.signer_algorithm import ES256K_signer_algorithm
from ebsi_wallet.ethereum import Ethereum


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

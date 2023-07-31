import base64
import hashlib


def generate_code_challenge(code_verifier: str) -> str:
    if len(code_verifier) < 43 or len(code_verifier) > 128:
        raise ValueError("code_verifier must be between 43 and 128 characters long.")
    valid_characters = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    if not all(char in valid_characters for char in code_verifier):
        raise ValueError("code_verifier contains invalid characters.")
    code_verifier_bytes = code_verifier.encode("utf-8")
    sha256_hash = hashlib.sha256(code_verifier_bytes).digest()
    base64url_encoded = (
        base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode("utf-8")
    )

    return base64url_encoded

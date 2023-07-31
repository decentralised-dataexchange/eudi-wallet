from jwcrypto import jwk


def get_alg_for_key(key: jwk.JWK):
    if key.key_curve == "P-256":
        alg = "ES256"
    else:
        alg = "ES256K"
    return alg

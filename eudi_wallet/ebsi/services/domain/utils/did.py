import typing

from eudi_wallet.did_key import KeyDid, PublicKeyJWK
from eudi_wallet.ebsi_did import EbsiDid
from eudi_wallet.ethereum import Ethereum


async def generate_and_store_did(
    crypto_seed: str,
) -> typing.Tuple[Ethereum, EbsiDid, KeyDid]:
    crypto_seed = crypto_seed.encode("utf-8")

    # Generate EBSI DID for legal entity
    eth = Ethereum(seed=crypto_seed)
    ebsi_did = EbsiDid(seed=crypto_seed)
    ebsi_did.generate_did(eth=eth)

    # Generate EBSI DID for natural person
    key_did = KeyDid(seed=crypto_seed)
    key_did.create_keypair()
    public_key_jwk = PublicKeyJWK(
        kty=key_did.public_key_jwk["kty"],
        crv=key_did.public_key_jwk["crv"],
        x=key_did.public_key_jwk["x"],
        y=key_did.public_key_jwk["y"],
    )
    key_did.generate_did(public_key_jwk)

    return eth, ebsi_did, key_did

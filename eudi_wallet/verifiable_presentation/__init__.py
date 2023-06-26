from eudi_wallet.util import format_iat_date


async def create_verifiable_presentation(presentation, required_proof, signature):
    verifiable_presentation = {
        **presentation,
        "proof": {
            "type": required_proof["type"],
            "created": format_iat_date(signature["iat"]),
            "proofPurpose": required_proof["proofPurpose"],
            "verificationMethod": required_proof["verificationMethod"],
            "jws": signature["proofValue"],
        },
    }

    return verifiable_presentation

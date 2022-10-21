from ebsi_wallet.util import http_call


async def resolve(did, options):

    did_document = await http_call(f"{options['registry']}/{did}", "GET")

    return {
        "didDocument": did_document,
        "didDocumentMetadata": {},
        "didResolutionMetadata": {"Content-Type": "application/did+ld+json"},
    }

from ...did_jwt import decode_jwt


async def verify_vc_jwt(vc, config=None, options={}):
    decoded = decode_jwt(vc)

    return decoded

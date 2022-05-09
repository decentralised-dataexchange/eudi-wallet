import base64


def leftpad(data: str, size=64):
    """
    Left-pads the data with zeros.

    Args:

        data: Data to pad.
        size: Size of the padded data.

    Returns:

        str: Padded data.

    """
    return data.rjust(size, "0")


def to_jose(r, s, v, recoverable=False):
    """
    Converts the signature to JOSE format.

    Args:

            r: Signature r.
            s: Signature s.
            v: Signature v.
            recoverable: Whether the signature is recoverable.

    Returns:

            str: URL safe base64 encoded str.
    """

    jose = bytes.fromhex(r[2:]) + bytes.fromhex(s[2:])

    # FIXME: Recoverable signature is not working for some reason.
    if recoverable:
        jose += bytes([v])

    return base64.urlsafe_b64encode(jose).decode("utf-8")

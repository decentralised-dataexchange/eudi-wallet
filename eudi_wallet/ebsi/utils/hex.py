import binascii


def convert_string_to_hex(str_val: str) -> str:
    return binascii.hexlify(str_val.encode("utf-8")).decode()

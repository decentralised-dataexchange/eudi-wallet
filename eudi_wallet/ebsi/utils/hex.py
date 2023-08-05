import binascii
import os


def convert_string_to_hex(str_val: str) -> str:
    return binascii.hexlify(str_val.encode("utf-8")).decode()


def generate_random_ebsi_reserved_attribute_id() -> str:
    return binascii.hexlify(os.urandom(32)).decode()

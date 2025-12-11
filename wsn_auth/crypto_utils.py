import hashlib
from typing import List, Any

HASH_LEN = 32  # bytes for SHA-256


def to_bytes(x: Any) -> bytes:
    """Convert int/str/bytes to bytes in a consistent way."""
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode("utf-8")
    if isinstance(x, int):
        if x == 0:
            return b"\x00"
        length = (x.bit_length() + 7) // 8
        return x.to_bytes(length, "big")
    raise TypeError(f"Unsupported type for to_bytes: {type(x)}")


def H(*parts: Any) -> bytes:
    """Length-prefixed SHA-256 over a sequence of parts (ints/str/bytes)."""
    m = hashlib.sha256()
    for p in parts:
        b = to_bytes(p)
        m.update(len(b).to_bytes(4, "big"))
        m.update(b)
    return m.digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def stream_cipher(key: bytes, length: int) -> bytes:
    """
    Very simple stream-like construction:

      keystream = H(key, 0) || H(key, 1) || ...

    This is NOT cryptographically strong. It is only for simulation.
    """
    out = b""
    counter = 0
    while len(out) < length:
        out += H(key, counter)
        counter += 1
    return out[:length]


def enc_sym(key: bytes, plaintext: bytes) -> bytes:
    keystream = stream_cipher(key, len(plaintext))
    return xor_bytes(plaintext, keystream)


def dec_sym(key: bytes, ciphertext: bytes) -> bytes:
    keystream = stream_cipher(key, len(ciphertext))
    return xor_bytes(ciphertext, keystream)


def pack_fields(*fields: Any) -> bytes:
    """Pack arbitrary fields into bytes as [len(2 bytes)][data]..."""
    out = b""
    for f in fields:
        b = to_bytes(f)
        if len(b) > 65535:
            raise ValueError("Field too long to pack")
        out += len(b).to_bytes(2, "big") + b
    return out


def unpack_fields(data: bytes) -> List[bytes]:
    """Unpack data produced by pack_fields."""
    fields: List[bytes] = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("Truncated packed data")
        length = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if i + length > len(data):
            raise ValueError("Truncated field data")
        fields.append(data[i:i + length])
        i += length
    return fields

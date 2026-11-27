"""A tiny DER (ASN.1) reader, just enough to walk an X.509 certificate.

Only the features real certificates use are implemented: single-byte tags,
short and long definite-length encodings, and nested SEQUENCE/SET traversal.
"""

from __future__ import annotations

from dataclasses import dataclass

# Tag constants used by the certificate parser.
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
OID = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x30
SET = 0x31
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18


class DERError(ValueError):
    """Raised on malformed DER input."""


@dataclass(frozen=True)
class TLV:
    tag: int
    value: bytes
    end: int  # offset just past this element in the parent buffer


def read_tlv(data: bytes, offset: int = 0) -> TLV:
    """Read one tag-length-value triple starting at ``offset``."""
    if offset + 2 > len(data):
        raise DERError("truncated TLV header")
    tag = data[offset]
    length_byte = data[offset + 1]
    pos = offset + 2

    if length_byte < 0x80:
        length = length_byte
    else:
        num = length_byte & 0x7F
        if num == 0 or pos + num > len(data):
            raise DERError("bad long-form length")
        length = int.from_bytes(data[pos:pos + num], "big")
        pos += num

    end = pos + length
    if end > len(data):
        raise DERError("TLV value overruns buffer")
    return TLV(tag=tag, value=data[pos:end], end=end)


def read_items(content: bytes) -> list[TLV]:
    """Read every TLV in a constructed value's content."""
    items: list[TLV] = []
    offset = 0
    while offset < len(content):
        tlv = read_tlv(content, offset)
        items.append(tlv)
        offset = tlv.end
    return items


def decode_oid(data: bytes) -> str:
    """Decode an OID value's content bytes into dotted-decimal form."""
    if not data:
        raise DERError("empty OID")
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)

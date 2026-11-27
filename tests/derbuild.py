"""Minimal DER encoder used only by the tests to craft certificates."""

from lumen_prakash import der


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(value)) + value


# Known OID content bytes.
OID_CN = bytes([0x55, 0x04, 0x03])
OID_RSA = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
OID_EC = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
OID_P256 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
OID_SAN = bytes([0x55, 0x1D, 0x11])


def name_with_cn(cn: str) -> bytes:
    attr = tlv(der.SEQUENCE, tlv(der.OID, OID_CN) + tlv(der.UTF8_STRING, cn.encode()))
    return tlv(der.SEQUENCE, tlv(der.SET, attr))


def rsa_spki(bits: int = 2048) -> bytes:
    nbytes = bits // 8
    modulus = tlv(der.INTEGER, b"\x00" + b"\xff" * nbytes)  # positive, MSB set
    exponent = tlv(der.INTEGER, b"\x01\x00\x01")
    rsapub = tlv(der.SEQUENCE, modulus + exponent)
    algid = tlv(der.SEQUENCE, tlv(der.OID, OID_RSA) + tlv(0x05, b""))  # NULL params
    return tlv(der.SEQUENCE, algid + tlv(der.BIT_STRING, b"\x00" + rsapub))


def ec_spki() -> bytes:
    algid = tlv(der.SEQUENCE, tlv(der.OID, OID_EC) + tlv(der.OID, OID_P256))
    pub = b"\x04" + b"\x11" * 64  # uncompressed point placeholder
    return tlv(der.SEQUENCE, algid + tlv(der.BIT_STRING, b"\x00" + pub))


def san_extension(dns_names: list[str]) -> bytes:
    gns = b"".join(bytes([0x82]) + enc_len(len(d)) + d.encode() for d in dns_names)
    general_names = tlv(der.SEQUENCE, gns)
    san_ext = tlv(der.SEQUENCE, tlv(der.OID, OID_SAN) + tlv(der.OCTET_STRING, general_names))
    extensions = tlv(der.SEQUENCE, san_ext)
    return tlv(0xA3, extensions)  # explicit [3]


def certificate(
    spki: bytes,
    subject_cn: str = "example.com",
    issuer_cn: str = "Test CA",
    not_before: bytes = b"230101000000Z",
    not_after: bytes = b"330101000000Z",
    dns_names: list[str] | None = None,
) -> bytes:
    version = tlv(0xA0, tlv(der.INTEGER, b"\x02"))  # explicit [0] v3
    serial = tlv(der.INTEGER, b"\x01")
    sigalg = tlv(der.SEQUENCE, tlv(der.OID, OID_RSA))
    issuer = name_with_cn(issuer_cn)
    validity = tlv(der.SEQUENCE, tlv(der.UTC_TIME, not_before) + tlv(der.UTC_TIME, not_after))
    subject = name_with_cn(subject_cn)
    body = version + serial + sigalg + issuer + validity + subject + spki
    if dns_names:
        body += san_extension(dns_names)
    tbs = tlv(der.SEQUENCE, body)
    return tlv(der.SEQUENCE, tbs + sigalg + tlv(der.BIT_STRING, b"\x00sig"))

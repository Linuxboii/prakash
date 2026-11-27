"""Extract fields from an X.509 certificate's DER encoding.

These helpers are deliberately dependency-free and side-effect-free so they can
be unit-tested against crafted DER bytes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import der

# Object identifiers we care about.
OID_CN = "2.5.4.3"
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"
OID_SAN = "2.5.29.17"

# Named-curve OIDs -> (label, key size in bits).
_CURVES = {
    "1.2.840.10045.3.1.7": ("P-256 (secp256r1)", 256),
    "1.3.132.0.34": ("P-384 (secp384r1)", 384),
    "1.3.132.0.35": ("P-521 (secp521r1)", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}


def _tbs_fields(cert_der: bytes) -> list[der.TLV]:
    """Return the top-level TLVs of the tbsCertificate."""
    cert = der.read_tlv(cert_der)
    if cert.tag != der.SEQUENCE:
        raise der.DERError("certificate is not a SEQUENCE")
    cert_items = der.read_items(cert.value)
    tbs = cert_items[0]
    if tbs.tag != der.SEQUENCE:
        raise der.DERError("tbsCertificate is not a SEQUENCE")
    return der.read_items(tbs.value)


def _ordered_fields(tbs_items: list[der.TLV]) -> list[der.TLV]:
    """Drop the optional explicit [0] version so field indexing is stable."""
    if tbs_items and tbs_items[0].tag == 0xA0:
        return tbs_items[1:]
    return tbs_items


def public_key_info(cert_der: bytes) -> dict:
    """Return {"type", "bits", "curve"} describing the subject public key."""
    fields = _ordered_fields(_tbs_fields(cert_der))
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    spki = fields[5]
    spki_items = der.read_items(spki.value)
    algid_items = der.read_items(spki_items[0].value)
    oid = der.decode_oid(algid_items[0].value)
    bitstring = spki_items[1].value  # first byte = unused bits count

    if oid == OID_RSA:
        key_bytes = bitstring[1:]  # strip unused-bits byte
        rsa_seq = der.read_tlv(key_bytes)
        modulus = der.read_items(rsa_seq.value)[0]
        n = int.from_bytes(modulus.value, "big")
        return {"type": "RSA", "bits": n.bit_length(), "curve": None}

    if oid == OID_EC:
        curve = "unknown"
        bits = None
        if len(algid_items) > 1 and algid_items[1].tag == der.OID:
            curve_oid = der.decode_oid(algid_items[1].value)
            label, bits = _CURVES.get(curve_oid, (curve_oid, None))
            curve = label
        return {"type": "EC", "bits": bits, "curve": curve}

    if oid in (OID_ED25519, OID_ED448):
        name = "Ed25519" if oid == OID_ED25519 else "Ed448"
        return {"type": name, "bits": 256 if oid == OID_ED25519 else 456,
                "curve": name}

    return {"type": f"OID {oid}", "bits": None, "curve": None}


def _first_cn(name_der_value: bytes) -> str | None:
    """Extract the Common Name from an RDNSequence value."""
    for rdn in der.read_items(name_der_value):  # each RDN is a SET
        if rdn.tag != der.SET:
            continue
        for attr in der.read_items(rdn.value):  # SEQUENCE { OID, value }
            attr_items = der.read_items(attr.value)
            if len(attr_items) >= 2 and der.decode_oid(attr_items[0].value) == OID_CN:
                return attr_items[1].value.decode("utf-8", "replace")
    return None


def subject_cn(cert_der: bytes) -> str | None:
    fields = _ordered_fields(_tbs_fields(cert_der))
    return _first_cn(fields[4].value)  # subject


def issuer_cn(cert_der: bytes) -> str | None:
    fields = _ordered_fields(_tbs_fields(cert_der))
    return _first_cn(fields[2].value)  # issuer


def parse_time(tlv: der.TLV) -> datetime:
    """Parse a UTCTime or GeneralizedTime TLV into an aware UTC datetime."""
    raw = tlv.value.decode("ascii")
    if tlv.tag == der.UTC_TIME:  # YYMMDDHHMMSSZ
        dt = datetime.strptime(raw, "%y%m%d%H%M%SZ")
    elif tlv.tag == der.GENERALIZED_TIME:  # YYYYMMDDHHMMSSZ
        dt = datetime.strptime(raw, "%Y%m%d%H%M%SZ")
    else:
        raise der.DERError(f"unexpected time tag {tlv.tag:#x}")
    return dt.replace(tzinfo=timezone.utc)


def validity(cert_der: bytes) -> tuple[datetime, datetime]:
    """Return (not_before, not_after) as aware UTC datetimes."""
    fields = _ordered_fields(_tbs_fields(cert_der))
    validity_items = der.read_items(fields[3].value)
    return parse_time(validity_items[0]), parse_time(validity_items[1])


def san_dns_names(cert_der: bytes) -> list[str]:
    """Return the dNSName entries from the Subject Alternative Name extension."""
    fields = _ordered_fields(_tbs_fields(cert_der))
    # Extensions live in the explicit [3] element (tag 0xA3), if present.
    exts_container = None
    for f in fields[6:]:
        if f.tag == 0xA3:
            exts_container = f
            break
    if exts_container is None:
        return []

    ext_seq = der.read_tlv(exts_container.value)  # SEQUENCE OF Extension
    names: list[str] = []
    for ext in der.read_items(ext_seq.value):
        ext_items = der.read_items(ext.value)
        if der.decode_oid(ext_items[0].value) != OID_SAN:
            continue
        # Last item is the OCTET STRING wrapping GeneralNames.
        octet = ext_items[-1]
        general_names = der.read_tlv(octet.value)
        for gn in der.read_items(general_names.value):
            if gn.tag == 0x82:  # [2] dNSName, IA5String
                names.append(gn.value.decode("ascii", "replace"))
    return names


def days_until(not_after: datetime, now: datetime | None = None) -> int:
    """Whole days from ``now`` until ``not_after`` (negative if expired)."""
    if now is None:
        now = datetime.now(timezone.utc)
    return (not_after - now).days

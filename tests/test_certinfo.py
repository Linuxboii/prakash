import unittest
from datetime import datetime, timezone

from prakash import certinfo, der

from . import derbuild


class TestDER(unittest.TestCase):
    def test_read_tlv_short(self):
        tlv = der.read_tlv(bytes([0x02, 0x01, 0x07]))
        self.assertEqual(tlv.tag, der.INTEGER)
        self.assertEqual(tlv.value, b"\x07")
        self.assertEqual(tlv.end, 3)

    def test_read_tlv_long_length(self):
        value = b"A" * 200
        data = bytes([0x04, 0x81, 200]) + value
        tlv = der.read_tlv(data)
        self.assertEqual(tlv.value, value)

    def test_read_items(self):
        data = derbuild.tlv(der.SEQUENCE, b"")
        inner = der.read_tlv(data)
        self.assertEqual(inner.value, b"")

    def test_decode_oid(self):
        self.assertEqual(der.decode_oid(derbuild.OID_CN), "2.5.4.3")
        self.assertEqual(der.decode_oid(derbuild.OID_RSA), "1.2.840.113549.1.1.1")
        self.assertEqual(der.decode_oid(derbuild.OID_P256), "1.2.840.10045.3.1.7")

    def test_truncated_raises(self):
        with self.assertRaises(der.DERError):
            der.read_tlv(b"\x30")


class TestCertInfo(unittest.TestCase):
    def setUp(self):
        self.rsa_cert = derbuild.certificate(
            derbuild.rsa_spki(2048),
            subject_cn="example.com",
            issuer_cn="Test CA",
            dns_names=["example.com", "www.example.com"],
        )
        self.ec_cert = derbuild.certificate(derbuild.ec_spki(), subject_cn="ec.test")

    def test_rsa_key_info(self):
        info = certinfo.public_key_info(self.rsa_cert)
        self.assertEqual(info["type"], "RSA")
        self.assertEqual(info["bits"], 2048)

    def test_ec_key_info(self):
        info = certinfo.public_key_info(self.ec_cert)
        self.assertEqual(info["type"], "EC")
        self.assertEqual(info["bits"], 256)
        self.assertIn("P-256", info["curve"])

    def test_subject_and_issuer(self):
        self.assertEqual(certinfo.subject_cn(self.rsa_cert), "example.com")
        self.assertEqual(certinfo.issuer_cn(self.rsa_cert), "Test CA")

    def test_validity(self):
        nb, na = certinfo.validity(self.rsa_cert)
        self.assertEqual(nb.year, 2023)
        self.assertEqual(na.year, 2033)
        self.assertEqual(na.tzinfo, timezone.utc)

    def test_san(self):
        self.assertEqual(
            certinfo.san_dns_names(self.rsa_cert),
            ["example.com", "www.example.com"],
        )

    def test_san_absent(self):
        cert = derbuild.certificate(derbuild.rsa_spki(2048))
        self.assertEqual(certinfo.san_dns_names(cert), [])

    def test_days_until(self):
        na = datetime(2033, 1, 1, tzinfo=timezone.utc)
        now = datetime(2032, 12, 2, tzinfo=timezone.utc)
        self.assertEqual(certinfo.days_until(na, now), 30)
        past = datetime(2033, 1, 11, tzinfo=timezone.utc)
        self.assertEqual(certinfo.days_until(na, past), -10)

    def test_generalized_time(self):
        cert = derbuild.certificate(
            derbuild.rsa_spki(2048),
        )
        # swap not_after to a generalized-time cert
        cert2 = derbuild.certificate(
            derbuild.rsa_spki(2048),
            not_before=b"230101000000Z",
            not_after=b"330101000000Z",
        )
        nb, na = certinfo.validity(cert2)
        self.assertEqual(na.year, 2033)


if __name__ == "__main__":
    unittest.main()

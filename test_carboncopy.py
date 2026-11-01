import unittest
from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption


class TestCarbonCopyPKCS12(unittest.TestCase):
    def test_pkcs12_serialization_fallback(self):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.set_serial_number(1)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(3600)
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        pfxdata = None
        try:
            pfx = crypto.PKCS12()
            pfx.set_privatekey(k)
            pfx.set_certificate(cert)
            pfxdata = pfx.export()
        except (AttributeError, Exception):
            pfxdata = pkcs12.serialize_key_and_certificates(
                name=b"certificate",
                key=k.to_cryptography_key(),
                cert=cert.to_cryptography(),
                cas=None,
                encryption_algorithm=NoEncryption(),
            )

        self.assertIsNotNone(pfxdata)
        self.assertGreater(len(pfxdata), 0)
        self.assertIsInstance(pfxdata, bytes)


if __name__ == "__main__":
    unittest.main()

"""Kiem thu tu dong cho de tai 1.2 (CA / X.509 / CRL / OCSP / TLS).
    python3 -m unittest tests.test_pki
"""
import http.client
import os
import shutil
import ssl
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID

from common.group import ca_common_name
from pki.ca import CertificateAuthority
from pki.https_server import Handler, make_context


class TestCA(unittest.TestCase):
    def setUp(self):
        self.store = tempfile.mkdtemp(prefix="ca_")
        self.ca = CertificateAuthority(self.store)
        self.ca.init(force=True)

    def tearDown(self):
        shutil.rmtree(self.store, ignore_errors=True)

    def test_root_subject_has_mssv(self):
        cn = self.ca.load_cert().subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, ca_common_name())
        self.assertTrue(cn.startswith("CA-Root-"))

    def test_issue_and_verify(self):
        cert, prefix = self.ca.issue("localhost", ["localhost", "127.0.0.1"])
        r = self.ca.verify(prefix + ".crt")
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["chain"] and r["time_valid"])
        # co SAN
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        self.assertIn("localhost", san)

    def test_revocation_reflected_in_crl_and_verify(self):
        cert, prefix = self.ca.issue("revoke-me")
        serial = "%x" % cert.serial_number
        self.ca.revoke(serial, "key_compromise")
        crl, path = self.ca.build_crl()
        self.assertTrue(os.path.exists(path))
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(
            cert.serial_number))
        r = self.ca.verify(prefix + ".crt")
        self.assertFalse(r["ok"])
        self.assertTrue(r["revoked"])

    def test_foreign_cert_rejected(self):
        # chung thu do mot CA khac cap -> chuoi tin cay that bai
        other = CertificateAuthority(tempfile.mkdtemp(prefix="ca2_"))
        other.init(force=True)
        _, prefix = other.issue("intruder")
        r = self.ca.verify(prefix + ".crt")
        self.assertFalse(r["chain"])
        self.assertFalse(r["ok"])


class TestTLS(unittest.TestCase):
    def test_https_with_issued_cert(self):
        store = tempfile.mkdtemp(prefix="ca_tls_")
        ca = CertificateAuthority(store)
        ca.init(force=True)
        _, prefix = ca.issue("localhost", ["localhost", "127.0.0.1"])
        import http.server
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        httpd.socket = make_context(prefix + ".fullchain.crt",
                                    prefix + ".key").wrap_socket(
            httpd.socket, server_side=True)
        port = httpd.socket.getsockname()[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
        time.sleep(0.2)
        try:
            ctx = ssl.create_default_context(cafile=ca.cert_path)
            conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            body = resp.read()
            self.assertEqual(resp.status, 200)
            self.assertIn(b"HTTPS/TLS thanh cong", body)
            conn.close()
        finally:
            httpd.shutdown()
            shutil.rmtree(store, ignore_errors=True)



class TestOCSP(unittest.TestCase):
    def test_ocsp_good_and_revoked(self):
        import http.server
        from pki.ocsp_responder import OCSPHandler, check_status
        store = tempfile.mkdtemp(prefix="ca_ocsp_")
        ca = CertificateAuthority(store)
        ca.init(force=True)
        cert, _ = ca.issue("ocsp-host")
        serial = "%x" % cert.serial_number
        OCSPHandler.ca = ca
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OCSPHandler)
        port = httpd.socket.getsockname()[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
        time.sleep(0.2)
        try:
            self.assertEqual(check_status("127.0.0.1", port, serial, ca.load_cert()), "good")
            self.assertEqual(check_status("127.0.0.1", port, "ffff", ca.load_cert()), "unknown")
            ca.revoke(serial, "superseded")
            self.assertEqual(check_status("127.0.0.1", port, serial, ca.load_cert()), "revoked")
        finally:
            httpd.shutdown()
            shutil.rmtree(store, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

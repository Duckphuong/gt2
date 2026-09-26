"""Kich ban trinh dien day du de tai 1.2 (CA / X.509 / CRL / OCSP / TLS).

Chay: python3 demo_pki.py
Tao mot kho CA tam thoi, cap chung thu cho Web Server, khoi dong HTTPS,
dung curl-tuong-duong de xac thuc TLS, roi thu hoi chung thu va kiem tra
lai qua CRL va OCSP.
"""
import http.client
import shutil
import ssl
import tempfile
import threading
import time

from pki.ca import CertificateAuthority
from pki.https_server import Handler, make_context
from pki.ocsp_responder import OCSPHandler, check_status


def hr(t):
    print("\n" + "=" * 70 + "\n " + t + "\n" + "=" * 70)


def main():
    store = tempfile.mkdtemp(prefix="demo_ca_")
    ca = CertificateAuthority(store)
    try:
        hr("1) Khoi tao Root CA (Subject long MSSV nhom)")
        root = ca.init(force=True)
        print("   Subject:", root.subject.rfc4514_string())

        hr("2) Cap chung thu cho Web Server localhost")
        cert, prefix = ca.issue("localhost", ["localhost", "127.0.0.1"])
        serial = "%x" % cert.serial_number
        print("   Serial :", serial)
        print("   Verify :", ca.verify(prefix + ".crt"))

        hr("3) Khoi dong HTTPS/TLS va truy cap co xac thuc CA")
        import http.server
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        httpd.socket = make_context(prefix + ".fullchain.crt",
                                    prefix + ".key").wrap_socket(
            httpd.socket, server_side=True)
        port = httpd.socket.getsockname()[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)
        ctx = ssl.create_default_context(cafile=ca.cert_path)
        conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=5)
        conn.connect()
        peer = conn.sock.getpeercert()
        conn.request("GET", "/")
        resp = conn.getresponse()
        print("   GET https://localhost:%d/ -> %d %s" % (port, resp.status, resp.reason))
        print("   Server cert CN:",
              [t[0][1] for t in peer["subject"] if t[0][0] == "commonName"])
        conn.close()

        hr("4) Khoi dong OCSP responder - kiem tra trang thai TRUOC thu hoi")
        OCSPHandler.ca = ca
        ocsp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OCSPHandler)
        oport = ocsp.socket.getsockname()[1]
        threading.Thread(target=ocsp.serve_forever, daemon=True).start()
        time.sleep(0.2)
        print("   OCSP status:", check_status("127.0.0.1", oport, serial, ca.load_cert()))

        hr("5) Thu hoi chung thu -> cap nhat CRL & kiem tra lai")
        ca.revoke(serial, "key_compromise")
        crl, path = ca.build_crl()
        print("   CRL: %d chung thu bi thu hoi -> %s" % (len(list(crl)), path))
        print("   Verify (CRL):", ca.verify(prefix + ".crt")["errors"])
        print("   OCSP status :", check_status("127.0.0.1", oport, serial, ca.load_cert()))

        httpd.shutdown(); ocsp.shutdown()
        hr("HOAN TAT demo 1.2")
    finally:
        shutil.rmtree(store, ignore_errors=True)


if __name__ == "__main__":
    main()

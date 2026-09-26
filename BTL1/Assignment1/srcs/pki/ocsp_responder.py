"""OCSP-style responder don gian cho CA noi bo (de tai 1.2).

De giu phu thuoc gon nhe, responder dung giao thuc JSON qua HTTP thay cho
ASN.1/RFC 6960 day du, nhung mo phong dung ban chat OCSP: client hoi trang
thai mot chung thu theo serial, responder tra ve good / revoked / unknown
kem chu ky cua CA tren cau tra loi (chong gia mao).

    python3 -m pki.ocsp_responder --port 8888        # chay responder
    # Client:
    from pki.ocsp_responder import check_status
    check_status("127.0.0.1", 8888, serial_hex)
"""
import argparse
import http.server
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .ca import DEFAULT_STORE, CertificateAuthority


class OCSPHandler(http.server.BaseHTTPRequestHandler):
    ca = None  # gan tu ngoai

    def do_GET(self):
        # /status?serial=<hex>
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        serial = (q.get("serial") or [""])[0].lower()
        db = self.ca._load_db()
        meta = db["certs"].get(serial)
        if meta is None:
            status = "unknown"
        elif meta["status"] == "revoked":
            status = "revoked"
        else:
            status = "good"
        payload = {"serial": serial, "status": status,
                   "produced_at": int(time.time()),
                   "responder": self.ca.load_cert().subject.rfc4514_string()}
        import base64
        sig = self.ca.load_key().sign(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
            padding.PKCS1v15(), hashes.SHA256())
        body = json.dumps({"response": payload,
                           "signature": base64.b64encode(sig).decode()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def check_status(host, port, serial_hex, ca_cert):
    """Client goi responder va XAC THUC chu ky CA tren cau tra loi."""
    import base64
    import http.client
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/status?serial=%s" % serial_hex.lower())
    data = json.loads(conn.getresponse().read())
    conn.close()
    payload, sig = data["response"], base64.b64decode(data["signature"])
    ca_cert.public_key().verify(
        sig, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
        padding.PKCS1v15(), hashes.SHA256())   # ValueError neu gia mao
    return payload["status"]


def serve(host, port, store):
    ca = CertificateAuthority(store)
    OCSPHandler.ca = ca
    httpd = http.server.ThreadingHTTPServer((host, port), OCSPHandler)
    print("[ocsp] responder tai http://%s:%d/status?serial=<hex>" % (host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def main():
    ap = argparse.ArgumentParser(description="OCSP-style responder")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--store", default=DEFAULT_STORE)
    args = ap.parse_args()
    serve(args.host, args.port, args.store)


if __name__ == "__main__":
    main()

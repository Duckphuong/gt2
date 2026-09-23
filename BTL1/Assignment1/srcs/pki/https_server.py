"""Web Server HTTPS/TLS dung chung thu do CA noi bo cap (de tai 1.2).

    python3 -m pki.cli init
    python3 -m pki.cli issue --cn localhost --san localhost --san 127.0.0.1
    python3 -m pki.https_server --cert store/issued/localhost.fullchain.crt \
                                --key  store/issued/localhost.key --port 8443

Kiem thu client tin cay CA:
    curl --cacert store/ca.crt https://localhost:8443/
"""
import argparse
import http.server
import os
import ssl

from .ca import DEFAULT_STORE

PAGE = b"""<!doctype html><meta charset=utf-8>
<title>CA noi bo - TLS demo</title>
<h1>Ket noi HTTPS/TLS thanh cong</h1>
<p>Trang nay duoc phuc vu boi Web Server dung chung thu X.509 do CA noi bo cap.</p>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, fmt, *args):
        print("[https]", self.address_string(), fmt % args, flush=True)


def make_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


def serve(host, port, certfile, keyfile):
    httpd = http.server.ThreadingHTTPServer((host, port), Handler)
    httpd.socket = make_context(certfile, keyfile).wrap_socket(
        httpd.socket, server_side=True)
    print("[https] phuc vu tai https://%s:%d/ (Ctrl+C de dung)" % (host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def main():
    d = os.path.join(DEFAULT_STORE, "issued")
    ap = argparse.ArgumentParser(description="Web Server HTTPS dung chung thu CA noi bo")
    ap.add_argument("--cert", default=os.path.join(d, "localhost.fullchain.crt"))
    ap.add_argument("--key", default=os.path.join(d, "localhost.key"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()
    serve(args.host, args.port, args.cert, args.key)


if __name__ == "__main__":
    main()

"""Client chat & truyen tep ma hoa dau cuoi (SCP/1).

Vi du (moi lenh o mot terminal, dung trong thu muc srcs/):
    python3 -m e2e_chat.keygen alice bob
    python3 -m e2e_chat.server --port 9000 --log
    python3 -m e2e_chat.client --user alice --peer bob --port 9000
    python3 -m e2e_chat.client --user bob   --peer alice --port 9000

Lenh trong phien chat:
    <van ban>        gui tin nhan
    /file <duong_dan> gui tep
    /quit            thoat
"""
import argparse
import hashlib
import os
import socket
import sys
import threading

from common.group import group_key, hello_message
from . import protocol as P

CHUNK = 48 * 1024
DEFAULT_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


class SecureClient:
    def __init__(self, user, peer, host="127.0.0.1", port=9000, room="bk",
                 datadir=DEFAULT_DATA, secure=True, on_event=None, verbose=True):
        self.user, self.expected_peer = user, peer
        self.host, self.port, self.room = host, port, room
        self.datadir, self.secure = datadir, secure
        self.on_event = on_event or (lambda kind, data: None)
        self.verbose = verbose
        self.sock = None
        self.rl = None
        self.peer = None
        self.initiator = None
        self.session_info = {}
        self._rx_file = None
        self._send_lock = threading.Lock()
        self.closed = threading.Event()
        if secure:
            self.id_key = P.load_private(os.path.join(datadir, "keys", user + ".key"))

    # ------------------------------------------------------------ helpers
    def log(self, *a):
        if self.verbose:
            print("[%s]" % self.user, *a, flush=True)

    def _pinned(self, user):
        path = os.path.join(self.datadir, "trusted", user + ".pub")
        if not os.path.exists(path):
            raise P.SecurityError("khong co khoa cong khai tin cay cho '%s'" % user)
        return P.load_public(path)

    def _send(self, frame):
        with self._send_lock:
            P.send_frame(self.sock, frame)

    # ---------------------------------------------------------- handshake
    def connect(self, timeout=30):
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        P.send_frame(self.sock, {"type": "JOIN", "user": self.user, "room": self.room})
        while True:
            f = P.recv_frame(self.sock)
            if f["type"] == "WAITING":
                self.log("dang cho doi tac trong phong '%s'..." % self.room)
            elif f["type"] == "PEER_JOINED":
                self.peer, self.initiator = f["peer"], f["initiator"]
                break
            elif f["type"] == "ERROR":
                raise P.ProtocolError(f["reason"])
        if self.expected_peer and self.peer != self.expected_peer:
            raise P.SecurityError("doi tac '%s' khong phai '%s'"
                                  % (self.peer, self.expected_peer))
        self.sock.settimeout(None)
        if self.initiator:
            self._handshake_initiator()
        else:
            self._handshake_responder()
        threading.Thread(target=self._rx_loop, daemon=True).start()
        return self

    def _handshake_initiator(self):
        eph, eph_pub = P.new_ephemeral()
        ch = P.build_client_hello(self.user, hello_message(), eph_pub)
        self._send(ch)
        self.log(">> CLIENT_HELLO  hello=%r" % ch["hello"])
        sh = P.recv_frame(self.sock)
        if sh.get("type") != "SERVER_HELLO" or sh.get("ver") != P.VERSION:
            raise P.ProtocolError("mong doi SERVER_HELLO")
        if sh["user"] != self.peer:
            raise P.SecurityError("SERVER_HELLO tu '%s' thay vi '%s'" % (sh["user"], self.peer))
        th = P.transcript_hash(ch, sh)
        if self.secure:
            pub = self._pinned(sh["user"])
            P.verify(pub, P.b64d(sh.get("sig_b", "")), b"SCP1-SH" + th)
            self.log("<< SERVER_HELLO  chu ky cua %s HOP LE (fp %s)"
                     % (sh["user"], P.fingerprint(pub)))
        else:
            self.log("<< SERVER_HELLO  (CHE DO KHONG XAC THUC - de bi MitM!)")
        shared = P.dh(eph, P.b64d(sh["eph_b"]))
        keys = P.derive_keys(shared, group_key(), th)
        cf = {"type": "CLIENT_FINISH",
              "mac_a": P.b64e(P.finished_mac(keys["fin"], th))}
        if self.secure:
            cf["sig_a"] = P.b64e(P.sign(self.id_key, b"SCP1-CF" + th))
        self._send(cf)
        self.rl = P.RecordLayer(keys, True)
        self._finish_setup(th, keys)
        # Ban ghi dau tien: thong diep khoi tao chua MSSV (plaintext kiem thu)
        self._send(self.rl.seal({"t": "hello", "text": hello_message()}))
        self.log(">> CLIENT_FINISH + ban ghi ma hoa #0: %r" % hello_message())

    def _handshake_responder(self):
        ch = P.recv_frame(self.sock)
        if ch.get("type") != "CLIENT_HELLO" or ch.get("ver") != P.VERSION:
            raise P.ProtocolError("mong doi CLIENT_HELLO")
        if ch["user"] != self.peer:
            raise P.SecurityError("CLIENT_HELLO tu '%s' thay vi '%s'" % (ch["user"], self.peer))
        if ch["hello"] != hello_message():
            raise P.SecurityError("thong diep khoi tao khong dung: %r" % ch["hello"])
        self.log("<< CLIENT_HELLO  hello=%r" % ch["hello"])
        eph, eph_pub = P.new_ephemeral()
        sh = P.build_server_hello(self.user, eph_pub)
        th = P.transcript_hash(ch, sh)
        if self.secure:
            sh["sig_b"] = P.b64e(P.sign(self.id_key, b"SCP1-SH" + th))
        self._send(sh)
        self.log(">> SERVER_HELLO")
        shared = P.dh(eph, P.b64d(ch["eph_a"]))
        keys = P.derive_keys(shared, group_key(), th)
        cf = P.recv_frame(self.sock)
        if cf.get("type") != "CLIENT_FINISH":
            raise P.ProtocolError("mong doi CLIENT_FINISH")
        if self.secure:
            pub = self._pinned(ch["user"])
            P.verify(pub, P.b64d(cf.get("sig_a", "")), b"SCP1-CF" + th)
            self.log("<< CLIENT_FINISH chu ky cua %s HOP LE (fp %s)"
                     % (ch["user"], P.fingerprint(pub)))
        if not P.hmac.compare_digest(P.b64d(cf["mac_a"]),
                                     P.finished_mac(keys["fin"], th)):
            raise P.SecurityError("Finished MAC sai - khoa phien khong khop")
        self.rl = P.RecordLayer(keys, False)
        first = self.rl.open(P.recv_frame(self.sock))
        if first.get("t") != "hello" or first.get("text") != hello_message():
            raise P.SecurityError("ban ghi xac nhan khoa khong dung")
        self.log("<< ban ghi ma hoa #0 giai ma OK: %r" % first["text"])
        self._finish_setup(th, keys)

    def _finish_setup(self, th, keys):
        self.session_info = {"transcript": th.hex(),
                             "key_id": hashlib.sha256(keys["enc_a2b"]).hexdigest()[:16]}
        self.log("*** Kenh an toan da thiet lap voi %s (session %s) ***"
                 % (self.peer, self.session_info["key_id"]))
        self.on_event("ready", self.session_info)

    # ------------------------------------------------------------ sending
    def send_text(self, text):
        with self._send_lock:
            P.send_frame(self.sock, self.rl.seal({"t": "msg", "text": text}))

    def send_file(self, path):
        with open(path, "rb") as f:
            data = f.read()
        name = os.path.basename(path)
        digest = hashlib.sha256(data).hexdigest()
        with self._send_lock:
            P.send_frame(self.sock, self.rl.seal(
                {"t": "file_start", "name": name, "size": len(data), "sha256": digest}))
            for i in range(0, len(data), CHUNK):
                P.send_frame(self.sock, self.rl.seal(
                    {"t": "file_chunk", "data": P.b64e(data[i:i + CHUNK])}))
            P.send_frame(self.sock, self.rl.seal({"t": "file_end"}))
        self.log("da gui tep %s (%d byte, sha256=%s...)" % (name, len(data), digest[:16]))

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.closed.set()

    # ---------------------------------------------------------- receiving
    def _rx_loop(self):
        try:
            while True:
                frame = P.recv_frame(self.sock)
                t = frame.get("type")
                if t == "PEER_LEFT":
                    self.on_event("peer_left", frame["peer"])
                    break
                if t != "DATA":
                    continue
                self._handle(self.rl.open(frame))
        except P.SecurityError as e:
            self.log("!!! CANH BAO AN TOAN:", e)
            self.on_event("security_error", str(e))
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            self.closed.set()
            self.on_event("closed", None)

    def _handle(self, msg):
        t = msg.get("t")
        if t == "msg":
            self.on_event("message", msg["text"])
        elif t == "file_start":
            self._rx_file = {"name": os.path.basename(msg["name"]), "size": msg["size"],
                             "sha256": msg["sha256"], "buf": bytearray()}
        elif t == "file_chunk" and self._rx_file is not None:
            self._rx_file["buf"] += P.b64d(msg["data"])
        elif t == "file_end" and self._rx_file is not None:
            info, self._rx_file = self._rx_file, None
            data = bytes(info["buf"])
            ok = hashlib.sha256(data).hexdigest() == info["sha256"] and len(data) == info["size"]
            out_dir = os.path.join(self.datadir, "downloads", self.user)
            os.makedirs(out_dir, exist_ok=True)
            out = os.path.join(out_dir, info["name"])
            if ok:
                with open(out, "wb") as f:
                    f.write(data)
            self.on_event("file", {"name": info["name"], "path": out, "size": len(data),
                                   "sha256": info["sha256"], "ok": ok})


def main():
    ap = argparse.ArgumentParser(description="SCP/1 E2E chat client")
    ap.add_argument("--user", required=True)
    ap.add_argument("--peer", required=True, help="ten doi tac mong doi")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--room", default="bk")
    ap.add_argument("--datadir", default=DEFAULT_DATA)
    ap.add_argument("--insecure", action="store_true",
                    help="TAT xac thuc chu ky (chi de minh hoa tan cong MitM)")
    args = ap.parse_args()

    def on_event(kind, data):
        if kind == "message":
            print("\r<%s> %s" % (cli.peer, data), flush=True)
        elif kind == "file":
            print("\r[tep] nhan %s (%d byte) -> %s [%s]" % (
                data["name"], data["size"], data["path"],
                "SHA-256 KHOP" if data["ok"] else "SHA-256 SAI - da huy"), flush=True)
        elif kind == "security_error":
            print("\r[!] Ket noi bi huy vi ly do an toan: %s" % data, flush=True)
        elif kind == "peer_left":
            print("\r[i] %s da roi phong" % data, flush=True)

    cli = SecureClient(args.user, args.peer, args.host, args.port, args.room,
                       args.datadir, not args.insecure, on_event)
    try:
        cli.connect()
    except P.ProtocolError as e:
        print("[!] Bat tay that bai:", e)
        sys.exit(2)
    print("Go tin nhan, '/file <duong_dan>' de gui tep, '/quit' de thoat.")
    for line in sys.stdin:
        line = line.rstrip("\n")
        if cli.closed.is_set():
            break
        if line == "/quit":
            break
        if line.startswith("/file "):
            try:
                cli.send_file(line[6:].strip())
            except OSError as e:
                print("[!]", e)
        elif line:
            cli.send_text(line)
    cli.close()


if __name__ == "__main__":
    main()

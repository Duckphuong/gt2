"""Relay server (Server trong mo hinh Client-Server).

Server chi ghep cap hai client trong cung mot "phong" va chuyen tiep cac
frame giua ho. Server KHONG nam giu khoa nao nen khong the doc noi dung
(ma hoa dau cuoi). Tuy chon --log in ra moi frame di qua de chung minh
server chi thay ban ma.

    python3 -m e2e_chat.server --port 9000 --log
"""
import argparse
import socket
import threading

from .protocol import recv_frame, send_frame

CONTROL = {"JOIN"}


class Room:
    def __init__(self, name):
        self.name = name
        self.members = []  # [(user, sock)]
        self.lock = threading.Lock()


class RelayServer:
    def __init__(self, host="127.0.0.1", port=9000, log=False):
        self.host, self.port, self.log = host, port, log
        self.rooms = {}
        self.lock = threading.Lock()
        self.sock = None
        self._stop = threading.Event()

    def _p(self, *a):
        if self.log:
            print("[relay]", *a, flush=True)

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print("[relay] dang lang nghe tai %s:%d" % (self.host, self.port), flush=True)
        return self

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _peer_of(self, room, sock):
        with room.lock:
            for u, s in room.members:
                if s is not sock:
                    return u, s
        return None, None

    def _handle(self, conn, addr):
        room, user = None, None
        try:
            join = recv_frame(conn)
            if join.get("type") != "JOIN":
                send_frame(conn, {"type": "ERROR", "reason": "can JOIN truoc"})
                return
            user, rname = str(join["user"]), str(join["room"])
            with self.lock:
                room = self.rooms.setdefault(rname, Room(rname))
            with room.lock:
                if len(room.members) >= 2:
                    send_frame(conn, {"type": "ERROR", "reason": "phong da du 2 nguoi"})
                    return
                room.members.append((user, conn))
                peers = list(room.members)
            self._p("%s (%s:%d) vao phong '%s'" % (user, addr[0], addr[1], rname))
            if len(peers) == 2:
                (u1, s1), (u2, s2) = peers
                # Nguoi vao sau la initiator (gui CLIENT_HELLO)
                send_frame(s1, {"type": "PEER_JOINED", "peer": u2, "initiator": False})
                send_frame(s2, {"type": "PEER_JOINED", "peer": u1, "initiator": True})
            else:
                send_frame(conn, {"type": "WAITING", "room": rname})
            while True:
                frame = recv_frame(conn)
                if frame.get("type") in CONTROL:
                    continue
                self._p("%s -> peer: %s" % (user, _summary(frame)))
                _, psock = self._peer_of(room, conn)
                if psock is None:
                    send_frame(conn, {"type": "ERROR", "reason": "chua co doi tac"})
                    continue
                send_frame(psock, frame)
        except (ConnectionError, OSError, ValueError, KeyError):
            pass
        finally:
            if room is not None:
                with room.lock:
                    room.members = [(u, s) for u, s in room.members if s is not conn]
                    rest = list(room.members)
                for _, s in rest:
                    try:
                        send_frame(s, {"type": "PEER_LEFT", "peer": user})
                    except OSError:
                        pass
                self._p("%s roi phong '%s'" % (user, room.name))
            conn.close()


def _summary(frame):
    t = frame.get("type")
    if t == "DATA":
        return "DATA seq=%d ct=%s..." % (frame["seq"], frame["ct"][:32])
    keys = ",".join(sorted(k for k in frame if k != "type"))
    return "%s {%s}" % (t, keys)


def main():
    ap = argparse.ArgumentParser(description="SCP/1 relay server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--log", action="store_true", help="in ra cac frame di qua")
    args = ap.parse_args()
    srv = RelayServer(args.host, args.port, args.log).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()

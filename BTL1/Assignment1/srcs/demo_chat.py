"""Kich ban trinh dien day du de tai 1.1 (Chat & truyen tep E2E).

Chay: python3 demo_chat.py
Khoi dong relay server, cho hai client alice/bob bat tay, trao doi tin nhan
va truyen mot tep; sau do chay phan tich an toan truoc MitM.
"""
import os
import threading
import time

from e2e_chat.client import SecureClient
from e2e_chat.keygen import main as keygen_main
from e2e_chat.mitm_analysis import run as run_mitm
from e2e_chat.server import RelayServer

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e_chat", "data")


def hr(t):
    print("\n" + "=" * 70 + "\n " + t + "\n" + "=" * 70)


def main():
    hr("0) Sinh khoa dinh danh RSA (alice, bob)")
    import sys
    sys.argv = ["keygen", "alice", "bob", "--datadir", DATA]
    keygen_main()

    hr("1) Khoi dong relay server (khong tin cay - chi thay ban ma)")
    srv = RelayServer(port=0, log=True).start()

    hr("2) Hai client bat tay va trao doi du lieu ma hoa dau cuoi")
    a = SecureClient("alice", "bob", port=srv.port, room="demo")
    b = SecureClient("bob", "alice", port=srv.port, room="demo")
    t = threading.Thread(target=a.connect); t.start()
    time.sleep(0.2); b.connect(); t.join()
    time.sleep(0.2)
    a.send_text("Chao bob, day la kenh bao mat.")
    b.send_text("Chao alice, minh nhan duoc roi.")
    sample = os.path.join(DATA, "secret.txt")
    with open(sample, "w", encoding="utf-8") as f:
        f.write("Tai lieu mat cua nhom - " + "x" * 5000)
    a.send_file(sample)
    time.sleep(0.8)
    a.close(); b.close(); srv.stop()

    hr("3) Phan tich an toan truoc tan cong MitM")
    run_mitm()


if __name__ == "__main__":
    main()

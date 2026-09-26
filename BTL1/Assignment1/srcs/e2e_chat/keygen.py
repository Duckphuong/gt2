"""Sinh cap khoa dinh danh RSA-2048 dai han cho cac nguoi dung va
cai khoa cong khai vao kho tin cay (trusted/) - mo phong viec trao doi
va so khop fingerprint qua kenh ngoai (out-of-band).

    python3 -m e2e_chat.keygen alice bob [--datadir DIR]
"""
import argparse
import os

from . import protocol as P
from .client import DEFAULT_DATA


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("users", nargs="+")
    ap.add_argument("--datadir", default=DEFAULT_DATA)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    kd = os.path.join(args.datadir, "keys")
    td = os.path.join(args.datadir, "trusted")
    os.makedirs(kd, exist_ok=True)
    os.makedirs(td, exist_ok=True)
    for u in args.users:
        kp = os.path.join(kd, u + ".key")
        if os.path.exists(kp) and not args.force:
            key = P.load_private(kp)
            state = "da co"
        else:
            key = P.generate_identity()
            P.save_private(key, kp)
            state = "moi tao"
        P.save_public(key.public_key(), os.path.join(td, u + ".pub"))
        print("%-8s RSA-2048 (%s)  fingerprint %s" % (u, state, P.fingerprint(key.public_key())))


if __name__ == "__main__":
    main()

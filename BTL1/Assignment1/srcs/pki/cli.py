"""Giao dien dong lenh cho dich vu CA noi bo (de tai 1.2).

    python3 -m pki.cli init
    python3 -m pki.cli issue --cn localhost --san localhost --san 127.0.0.1
    python3 -m pki.cli list
    python3 -m pki.cli revoke --serial <hex> --reason key_compromise
    python3 -m pki.cli crl
    python3 -m pki.cli verify --cert store/issued/localhost.crt
"""
import argparse
import json

from .ca import CAError, CertificateAuthority, DEFAULT_STORE


def main(argv=None):
    ap = argparse.ArgumentParser(description="CA noi bo X.509")
    ap.add_argument("--store", default=DEFAULT_STORE)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init"); p.add_argument("--force", action="store_true")
    p.add_argument("--days", type=int, default=3650)

    p = sub.add_parser("issue")
    p.add_argument("--cn", required=True)
    p.add_argument("--san", action="append", default=[])
    p.add_argument("--client", action="store_true", help="cap cho client thay vi server")
    p.add_argument("--days", type=int, default=825)

    sub.add_parser("list")

    p = sub.add_parser("revoke")
    p.add_argument("--serial", required=True)
    p.add_argument("--reason", default="unspecified")

    sub.add_parser("crl")

    p = sub.add_parser("verify")
    p.add_argument("--cert", required=True)
    p.add_argument("--no-crl", action="store_true")

    args = ap.parse_args(argv)
    ca = CertificateAuthority(args.store)
    try:
        return _dispatch(ca, args)
    except CAError as e:
        print("[loi]", e)
        return 1


def _dispatch(ca, args):
    if args.cmd == "init":
        cert = ca.init(days=args.days, force=args.force)
        print("Da tao Root CA:")
        print("  Subject:", cert.subject.rfc4514_string())
        print("  Serial :", "%x" % cert.serial_number)
        print("  Luu tai:", ca.cert_path)
    elif args.cmd == "issue":
        cert, prefix = ca.issue(args.cn, args.san or [args.cn],
                                is_server=not args.client)
        print("Da cap chung thu cho '%s'" % args.cn)
        print("  Serial   :", "%x" % cert.serial_number)
        print("  Key      :", prefix + ".key")
        print("  Cert     :", prefix + ".crt")
        print("  Fullchain:", prefix + ".fullchain.crt")
    elif args.cmd == "list":
        db = ca._load_db()
        if not db["certs"]:
            print("(chua cap chung thu nao)")
        for serial, m in db["certs"].items():
            print("%-16s %-20s %-8s het han %s" % (
                serial, m["cn"], m["status"], m["not_after"][:10]))
    elif args.cmd == "revoke":
        m = ca.revoke(args.serial, args.reason)
        print("Da thu hoi serial %s (%s) - ly do: %s"
              % (args.serial, m["cn"], m.get("reason")))
        ca.build_crl()
        print("Da cap nhat CRL:", ca.store + "/ca.crl")
    elif args.cmd == "crl":
        crl, path = ca.build_crl()
        n = len(list(crl))
        print("Da xuat CRL (%d chung thu bi thu hoi) -> %s" % (n, path))
    elif args.cmd == "verify":
        r = ca.verify(args.cert, check_crl=not args.no_crl)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return 0 if r["ok"] else 3
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

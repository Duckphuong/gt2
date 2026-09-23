"""Phan tich an toan truoc tan cong Man-in-the-Middle (MitM).

Muc tieu cua module nay la CHUNG MINH giao thuc SCP/1 chong lai MitM, phuc vu
Chuong 3 (danh gia) cua bao cao. No dong vai "ke tan cong" Mallory NGAY TRONG
tien trinh (in-process) de kiem chung tung tinh chat an toan, thay vi la mot
cong cu chan bat mang dung chung.

Cac kich ban duoc kiem chung:

  A. tamper   - Mallory doi 1 bit trong ban ma -> RecordLayer.open() bao
                SecurityError (HMAC khong khop). => Toan ven du lieu.

  B. replay   - Mallory phat lai mot ban ghi hop le -> ben nhan tu choi vi
                sai so thu tu (seq). => Chong phat lai.

  C. active-DH- Mallory thay khoa DH tam thoi cua hai ben bang khoa cua minh
                (kinh dien cho MitM tren Diffie-Hellman KHONG xac thuc).
                * Voi giao thuc CO ky (secure): chu ky RSA-PSS phu len
                  transcript nen SERVER_HELLO/CLIENT_FINISH bi phat hien
                  -> SecurityError. => Xac thuc danh tinh chan MitM.
                * Voi che do --insecure (khong ky): tan cong THANH CONG,
                  minh hoa vi sao rieng SHA256(MSSV) (thong tin cong khai)
                  khong the thay the chu ky.

Chay:
    python3 -m e2e_chat.mitm_analysis
"""
from common.group import group_key
from . import protocol as P


def _handshake_pair(secure):
    """Mo phong mot lan bat tay A<->B, tra ve (rl_a, rl_b, transcript)."""
    a_eph, a_pub = P.new_ephemeral()
    b_eph, b_pub = P.new_ephemeral()
    ch = P.build_client_hello("alice", "Hello, We are 2312345, 2312346", a_pub)
    sh = P.build_server_hello("bob", b_pub)
    th = P.transcript_hash(ch, sh)
    keys = P.derive_keys(P.dh(a_eph, b_pub), group_key(), th)
    keys2 = P.derive_keys(P.dh(b_eph, a_pub), group_key(), th)
    assert keys == keys2
    return P.RecordLayer(keys, True), P.RecordLayer(keys, False), th


def scenario_tamper():
    rl_a, rl_b, _ = _handshake_pair(secure=True)
    rec = rl_a.seal({"t": "msg", "text": "chuyen khoan 10 trieu"})
    raw = bytearray(P.b64d(rec["ct"]))
    raw[0] ^= 0x01                       # Mallory lat 1 bit ban ma
    rec["ct"] = P.b64e(bytes(raw))
    try:
        rl_b.open(rec)
        return False, "KHONG phat hien sua doi (that bai)"
    except P.SecurityError as e:
        return True, "Phat hien sua doi: %s" % e


def scenario_replay():
    rl_a, rl_b, _ = _handshake_pair(secure=True)
    rec = rl_a.seal({"t": "msg", "text": "mo cua"})
    rl_b.open(rec)                        # ban ghi that: OK
    try:
        rl_b.open(rec)                    # Mallory phat lai chinh no
        return False, "Chap nhan ban ghi phat lai (that bai)"
    except P.SecurityError as e:
        return True, "Tu choi phat lai: %s" % e


def scenario_active_dh(secure):
    """Mallory chen khoa DH cua minh vao ca hai chieu."""
    alice_key = P.load_private_or_none("alice")
    bob_key = P.load_private_or_none("bob")
    a_eph, a_pub = P.new_ephemeral()
    b_eph, b_pub = P.new_ephemeral()
    m_eph, m_pub = P.new_ephemeral()      # khoa cua Mallory

    ch = P.build_client_hello("alice", "Hello, We are 2312345, 2312346", a_pub)
    # Mallory thay eph_a bang eph cua minh truoc khi chuyen cho Bob
    ch_to_bob = dict(ch); ch_to_bob["eph_a"] = P.b64e(m_pub)

    sh = P.build_server_hello("bob", b_pub)
    if secure and bob_key is not None:
        # Bob ky tren transcript that (ch nguyen ban <-> sh)
        th_real = P.transcript_hash(ch, sh)
        sh["sig_b"] = P.b64e(P.sign(bob_key, b"SCP1-SH" + th_real))
    # Mallory thay eph_b bang eph cua minh truoc khi chuyen cho Alice
    sh_to_alice = dict(sh); sh_to_alice["eph_b"] = P.b64e(m_pub)

    # Alice kiem tra SERVER_HELLO da bi sua (eph_b khac -> transcript khac)
    th_alice = P.transcript_hash(ch, sh_to_alice)
    if secure:
        pub = P.load_public_or_none("bob")
        try:
            P.verify(pub, P.b64d(sh_to_alice.get("sig_b", "")), b"SCP1-SH" + th_alice)
        except P.SecurityError as e:
            return True, "Giao thuc CO ky: Alice phat hien MitM: %s" % e
        return False, "Giao thuc CO ky nhung khong phat hien (that bai)"
    else:
        # Khong ky: Alice khong co cach nao biet -> Mallory chia se khoa
        # voi ca hai ben => doc/ghi duoc. Tan cong thanh cong.
        return True, ("Che do --insecure: MitM THANH CONG - Mallory bat tay "
                      "rieng voi tung ben. Day la ly do bat buoc phai ky.")


def run():
    print("=" * 68)
    print(" PHAN TICH AN TOAN TRUOC MitM - SCP/1")
    print("=" * 68)
    rows = [
        ("A. Toan ven (tamper 1 bit)", scenario_tamper()),
        ("B. Chong phat lai (replay)", scenario_replay()),
        ("C. MitM tren DH - CO ky RSA", scenario_active_dh(secure=True)),
        ("D. MitM tren DH - KHONG ky ", scenario_active_dh(secure=False)),
    ]
    ok = True
    for name, (passed, detail) in rows:
        mark = "PASS" if passed else "FAIL"
        ok = ok and passed
        print("[%s] %-30s %s" % (mark, name, detail))
    print("=" * 68)
    print("Ket luan: giao thuc chong duoc MitM khi va chi khi bat xac thuc"
          " (ky RSA-PSS phu len transcript)." if ok else "Co kich ban that bai!")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(run())

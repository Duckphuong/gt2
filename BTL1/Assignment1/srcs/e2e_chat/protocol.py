"""SCP/1 - Secure Chat Protocol v1.

Giao thuc bao mat dau cuoi (end-to-end) giua hai client A (initiator) va B
(responder), di qua mot relay server khong tin cay.

  1. A -> B  CLIENT_HELLO  {ver, user, hello, nonce_a, eph_a}
  2. B -> A  SERVER_HELLO  {user, nonce_b, eph_b, sig_b}
             sig_b = RSA-PSS-SHA256(SK_B, "SCP1-SH" || H(CH || SH*))
  3. A -> B  CLIENT_FINISH {sig_a, mac_a}
             sig_a = RSA-PSS-SHA256(SK_A, "SCP1-CF" || H(CH || SH))
             mac_a = HMAC(k_fin, "client finished" || H(CH || SH))
  4. Hai ben co 4 khoa phien (enc/mac cho moi chieu):
        Z      = X25519(eph_a, eph_b)                 (Diffie-Hellman)
        salt   = SHA256(MSSV_1 || MSSV_2 || ..)       (khoa khoi tao)
        keys   = HKDF-SHA256(Z, salt, "SCP1 keys" || H(CH || SH), 160 byte)
  5. Ban ghi du lieu: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC),
     so thu tu (seq) tang dan de chong phat lai (replay).

Ban ghi dau tien A gui la thong diep "Hello, We are MSSV_1, ..", B kiem tra
de xac nhan khoa (key confirmation).
"""
import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = "SCP/1"
MAX_FRAME = 1 << 20


class ProtocolError(Exception):
    pass


class SecurityError(ProtocolError):
    """Phat hien tan cong / vi pham an toan (chu ky sai, MAC sai, replay...)."""


# ----------------------------------------------------------------- framing
def b64e(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


def send_frame(sock, obj):
    data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    if len(data) > MAX_FRAME:
        raise ProtocolError("frame qua lon")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("ket noi bi dong")
        buf += chunk
    return buf


def recv_frame(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise ProtocolError("frame qua lon")
    return json.loads(_recv_exact(sock, n).decode())


def canon(obj):
    """Ma hoa chuan tac (canonical) de bam transcript."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


# ------------------------------------------------------------ identity keys
def generate_identity(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def save_private(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(path, 0o600)


def save_public(pub, path):
    with open(path, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def fingerprint(pub):
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


_PSS = apad.PSS(mgf=apad.MGF1(hashes.SHA256()), salt_length=apad.PSS.MAX_LENGTH)


def sign(priv, data):
    return priv.sign(data, _PSS, hashes.SHA256())


def verify(pub, sig, data):
    try:
        pub.verify(sig, data, _PSS, hashes.SHA256())
    except InvalidSignature:
        raise SecurityError("chu ky RSA-PSS khong hop le - nghi ngo MitM")


# ----------------------------------------------------------- key schedule
def new_ephemeral():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return priv, pub


def dh(priv, peer_pub_bytes):
    return priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))


def transcript_hash(ch, sh):
    """H(CH || SH) - sh khong bao gom truong sig_b."""
    sh = {k: v for k, v in sh.items() if k != "sig_b"}
    return hashlib.sha256(canon(ch) + canon(sh)).digest()


def derive_keys(shared, salt, th):
    okm = HKDF(algorithm=hashes.SHA256(), length=160, salt=salt,
               info=b"SCP1 keys" + th).derive(shared)
    return {
        "enc_a2b": okm[0:32], "mac_a2b": okm[32:64],
        "enc_b2a": okm[64:96], "mac_b2a": okm[96:128],
        "fin": okm[128:160],
    }


def finished_mac(k_fin, th):
    return hmac.new(k_fin, b"client finished" + th, hashlib.sha256).digest()


# ------------------------------------------------------------ record layer
class RecordLayer:
    """AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) voi so thu tu chong replay."""

    def __init__(self, keys, is_initiator):
        if is_initiator:
            self.k_enc_out, self.k_mac_out = keys["enc_a2b"], keys["mac_a2b"]
            self.k_enc_in, self.k_mac_in = keys["enc_b2a"], keys["mac_b2a"]
            self.dir_out, self.dir_in = b"A>B", b"B>A"
        else:
            self.k_enc_out, self.k_mac_out = keys["enc_b2a"], keys["mac_b2a"]
            self.k_enc_in, self.k_mac_in = keys["enc_a2b"], keys["mac_a2b"]
            self.dir_out, self.dir_in = b"B>A", b"A>B"
        self.seq_out = 0
        self.seq_in = 0

    @staticmethod
    def _tag(k_mac, direction, seq, iv, ct):
        m = direction + struct.pack(">Q", seq) + iv + ct
        return hmac.new(k_mac, m, hashlib.sha256).digest()

    def seal(self, payload):
        pt = canon(payload)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        pt = padder.update(pt) + padder.finalize()
        enc = Cipher(algorithms.AES(self.k_enc_out), modes.CBC(iv)).encryptor()
        ct = enc.update(pt) + enc.finalize()
        seq = self.seq_out
        self.seq_out += 1
        tag = self._tag(self.k_mac_out, self.dir_out, seq, iv, ct)
        return {"type": "DATA", "seq": seq, "iv": b64e(iv), "ct": b64e(ct),
                "tag": b64e(tag)}

    def open(self, rec):
        seq, iv, ct, tag = rec["seq"], b64d(rec["iv"]), b64d(rec["ct"]), b64d(rec["tag"])
        # 1) Xac thuc truoc (EtM) - khong giai ma du lieu chua duoc xac thuc
        exp = self._tag(self.k_mac_in, self.dir_in, seq, iv, ct)
        if not hmac.compare_digest(exp, tag):
            raise SecurityError("HMAC khong khop - ban ghi bi sua doi/gia mao")
        # 2) Chong phat lai / dao thu tu
        if seq != self.seq_in:
            raise SecurityError("sai so thu tu (seq=%d, mong doi %d) - replay?"
                                % (seq, self.seq_in))
        self.seq_in += 1
        dec = Cipher(algorithms.AES(self.k_enc_in), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(pt) + unpadder.finalize()
        return json.loads(pt.decode())


# ------------------------------------------------------------- handshake
def build_client_hello(user, hello, eph_pub, nonce=None):
    return {"type": "CLIENT_HELLO", "ver": VERSION, "user": user,
            "hello": hello, "nonce_a": b64e(nonce or os.urandom(32)),
            "eph_a": b64e(eph_pub)}


def build_server_hello(user, eph_pub, nonce=None):
    return {"type": "SERVER_HELLO", "ver": VERSION, "user": user,
            "nonce_b": b64e(nonce or os.urandom(32)), "eph_b": b64e(eph_pub)}


# ---------------------------------------------- tien ich cho phan tich MitM
def _data_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def load_private_or_none(user):
    p = os.path.join(_data_dir(), "keys", user + ".key")
    return load_private(p) if os.path.exists(p) else None


def load_public_or_none(user):
    p = os.path.join(_data_dir(), "trusted", user + ".pub")
    return load_public(p) if os.path.exists(p) else None

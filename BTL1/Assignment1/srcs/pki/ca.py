"""Dich vu Certificate Authority (CA) noi bo dua tren chuan X.509.

Chuc nang:
  - init      : tao khoa + chung thu goc (Root CA) tu ky
  - issue     : cap phat chung thu cho mot chu the (Web Server / client)
  - revoke    : thu hoi mot chung thu (ghi vao co so du lieu thu hoi)
  - crl       : xuat Danh sach thu hoi chung thu (CRL) da ky
  - verify    : xac thuc mot chung thu theo chuoi tin cay + kiem tra CRL

MSSV nhom duoc long vao Subject cua chung thu goc:
    CN = CA-Root-[MSSV_1]-[MSSV_2] ..
    OU = Faculty of Computer Science and Engineer - [MSSV_1]-[MSSV_2] ..

Lop CA lay OpenSSL/cryptography lam nen; du lieu luu duoi thu muc --store.
"""
import datetime
import ipaddress
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common.group import ca_common_name, ca_org_unit, load_mssv

UTC = datetime.timezone.utc
DEFAULT_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "store")


def _now():
    return datetime.datetime.now(UTC)


def _naive_after(cert):
    """Tra ve not_valid_after dang timezone-aware, tuong thich moi phien ban."""
    dt = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _naive_before(cert):
    dt = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class CAError(Exception):
    pass


class CertificateAuthority:
    def __init__(self, store=DEFAULT_STORE):
        self.store = store
        self.key_path = os.path.join(store, "ca.key")
        self.cert_path = os.path.join(store, "ca.crt")
        self.db_path = os.path.join(store, "index.json")
        self.issued_dir = os.path.join(store, "issued")

    # --------------------------------------------------------------- state
    def _load_db(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, encoding="utf-8") as f:
                return json.load(f)
        return {"serial": 1000, "certs": {}}

    def _save_db(self, db):
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2, ensure_ascii=False)

    def load_key(self):
        with open(self.key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_cert(self):
        with open(self.cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    # ---------------------------------------------------------------- init
    def init(self, days=3650, force=False):
        if os.path.exists(self.cert_path) and not force:
            raise CAError("CA da ton tai (dung --force de tao lai)")
        os.makedirs(self.issued_dir, exist_ok=True)
        ids = load_mssv()
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               "Ho Chi Minh City University of Technology"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ca_org_unit(ids)),
            x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name(ids)),
        ])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_now() - datetime.timedelta(minutes=1))
                .not_valid_after(_now() + datetime.timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False), True)
                .add_extension(ski, False)
                .add_extension(x509.AuthorityKeyIdentifier
                               .from_issuer_subject_key_identifier(ski), False)
                .sign(key, hashes.SHA256()))
        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        os.chmod(self.key_path, 0o600)
        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self._save_db({"serial": 1000, "certs": {}})
        return cert

    # --------------------------------------------------------------- issue
    def issue(self, common_name, sans=None, days=825, is_server=True,
              out_prefix=None):
        if not os.path.exists(self.cert_path):
            raise CAError("chua khoi tao CA (chay 'init')")
        ca_key, ca_cert = self.load_key(), self.load_cert()
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               "Ho Chi Minh City University of Technology"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        san_objs = []
        for s in (sans or [common_name]):
            try:
                san_objs.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                san_objs.append(x509.DNSName(s))
        eku = (ExtendedKeyUsageOID.SERVER_AUTH if is_server
               else ExtendedKeyUsageOID.CLIENT_AUTH)
        ca_ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value
        builder = (x509.CertificateBuilder()
                   .subject_name(subject).issuer_name(ca_cert.subject)
                   .public_key(leaf_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(_now() - datetime.timedelta(minutes=1))
                   .not_valid_after(_now() + datetime.timedelta(days=days))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, key_encipherment=True,
                       content_commitment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=False, crl_sign=False,
                       encipher_only=False, decipher_only=False), True)
                   .add_extension(x509.ExtendedKeyUsage([eku]), False)
                   .add_extension(x509.SubjectAlternativeName(san_objs), False)
                   .add_extension(x509.SubjectKeyIdentifier
                                  .from_public_key(leaf_key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier
                                  .from_issuer_subject_key_identifier(ca_ski), False))
        cert = builder.sign(ca_key, hashes.SHA256())

        db = self._load_db()
        serial = "%x" % cert.serial_number
        db["certs"][serial] = {"cn": common_name, "status": "valid",
                               "issued": _now().isoformat(),
                               "not_after": _naive_after(cert).isoformat()}
        self._save_db(db)

        prefix = out_prefix or os.path.join(self.issued_dir, common_name)
        with open(prefix + ".key", "wb") as f:
            f.write(leaf_key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        os.chmod(prefix + ".key", 0o600)
        with open(prefix + ".crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        # chuoi day du: leaf + CA (fullchain) de dung cho TLS
        with open(prefix + ".fullchain.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        return cert, prefix

    # -------------------------------------------------------------- revoke
    def revoke(self, serial_hex, reason="unspecified"):
        db = self._load_db()
        serial = serial_hex.lower().replace("0x", "")
        if serial not in db["certs"]:
            raise CAError("khong tim thay serial %s" % serial)
        db["certs"][serial]["status"] = "revoked"
        db["certs"][serial]["revoked_at"] = _now().isoformat()
        db["certs"][serial]["reason"] = reason
        self._save_db(db)
        return db["certs"][serial]

    def revoked_serials(self):
        db = self._load_db()
        return {int(s, 16): v for s, v in db["certs"].items()
                if v["status"] == "revoked"}

    # ----------------------------------------------------------------- CRL
    def build_crl(self, days=7):
        ca_key, ca_cert = self.load_key(), self.load_cert()
        builder = (x509.CertificateRevocationListBuilder()
                   .issuer_name(ca_cert.subject)
                   .last_update(_now())
                   .next_update(_now() + datetime.timedelta(days=days)))
        reason_map = {
            "key_compromise": x509.ReasonFlags.key_compromise,
            "superseded": x509.ReasonFlags.superseded,
            "cessation": x509.ReasonFlags.cessation_of_operation,
            "unspecified": x509.ReasonFlags.unspecified,
        }
        for serial, meta in self.revoked_serials().items():
            revoked = (x509.RevokedCertificateBuilder()
                       .serial_number(serial)
                       .revocation_date(_now())
                       .add_extension(x509.CRLReason(
                           reason_map.get(meta.get("reason"),
                                          x509.ReasonFlags.unspecified)), False)
                       .build())
            builder = builder.add_revoked_certificate(revoked)
        crl = builder.sign(ca_key, hashes.SHA256())
        path = os.path.join(self.store, "ca.crl")
        with open(path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        return crl, path

    # -------------------------------------------------------------- verify
    def verify(self, cert_path, check_crl=True):
        """Xac thuc chung thu leaf: chu ky CA, thoi han, va trang thai CRL."""
        ca_cert = self.load_cert()
        with open(cert_path, "rb") as f:
            leaf = x509.load_pem_x509_certificate(f.read())
        result = {"cn": leaf.subject.rfc4514_string(),
                  "serial": "%x" % leaf.serial_number,
                  "chain": False, "time_valid": False, "revoked": None,
                  "ok": False, "errors": []}
        # 1) chu ky do CA cap
        try:
            ca_cert.public_key().verify(
                leaf.signature, leaf.tbs_certificate_bytes,
                _pkcs1(), leaf.signature_hash_algorithm)
            result["chain"] = True
        except Exception as e:  # noqa: BLE001
            result["errors"].append("chu ky khong do CA nay cap: %s" % e)
        # 2) thoi han
        now = datetime.datetime.now(UTC)
        if _naive_before(leaf) <= now <= _naive_after(leaf):
            result["time_valid"] = True
        else:
            result["errors"].append("ngoai thoi han hieu luc")
        # 3) CRL
        if check_crl:
            revoked = leaf.serial_number in self.revoked_serials()
            result["revoked"] = revoked
            if revoked:
                result["errors"].append("chung thu da bi thu hoi (CRL)")
        result["ok"] = result["chain"] and result["time_valid"] and not result["revoked"]
        return result


def _pkcs1():
    from cryptography.hazmat.primitives.asymmetric import padding
    return padding.PKCS1v15()

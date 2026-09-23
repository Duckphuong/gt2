"""Thong tin nhom (MSSV) dung chung cho ca hai de tai 1.1 va 1.2.

Thu tu uu tien:
  1. Bien moi truong MSSV (vd: MSSV="2312345,2312346")
  2. Tep srcs/group.json
"""
import hashlib
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
GROUP_FILE = os.path.join(os.path.dirname(_HERE), "group.json")


def load_mssv():
    env = os.environ.get("MSSV")
    if env:
        ids = [x.strip() for x in env.split(",") if x.strip()]
    else:
        with open(GROUP_FILE, encoding="utf-8") as f:
            ids = json.load(f)["mssv"]
    if len(ids) < 1 or not all(i.isdigit() for i in ids):
        raise ValueError("Danh sach MSSV khong hop le: %r" % (ids,))
    return ids


def hello_message(ids=None):
    """Thong diep bat tay bat buoc: 'Hello, We are MSSV_1, MSSV_2, ..'"""
    ids = ids or load_mssv()
    return "Hello, We are " + ", ".join(ids)


def group_key(ids=None):
    """Key = SHA256(MSSV_1 || MSSV_2 || ..) - khoa khoi tao dua vao KDF."""
    ids = ids or load_mssv()
    return hashlib.sha256("".join(ids).encode("ascii")).digest()


def ca_common_name(ids=None):
    ids = ids or load_mssv()
    return "CA-Root-" + "-".join(ids)


def ca_org_unit(ids=None):
    ids = ids or load_mssv()
    return "Faculty of Computer Science and Engineer – " + "-".join(ids)


if __name__ == "__main__":
    ids = load_mssv()
    print("MSSV         :", ids)
    print("Hello        :", hello_message(ids))
    print("SHA256(MSSV) :", group_key(ids).hex())
    print("CA CN        :", ca_common_name(ids))
    print("CA OU        :", ca_org_unit(ids))

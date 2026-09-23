"""Kiem thu tu dong cho de tai 1.1 (chat E2E) - chay bang unittest, khong
can pytest:  python3 -m unittest tests.test_e2e
"""
import os
import threading
import time
import unittest

from common.group import group_key, hello_message, load_mssv
from e2e_chat import protocol as P
from e2e_chat.client import SecureClient
from e2e_chat.keygen import main as keygen_main
from e2e_chat.mitm_analysis import (scenario_active_dh, scenario_replay,
                                    scenario_tamper)
from e2e_chat.server import RelayServer

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "e2e_chat", "data")


def ensure_keys():
    import sys
    argv = sys.argv
    sys.argv = ["keygen", "alice", "bob", "mallory", "--datadir", DATA]
    try:
        keygen_main()
    finally:
        sys.argv = argv


class TestGroup(unittest.TestCase):
    def test_hello_and_key(self):
        ids = load_mssv()
        self.assertTrue(hello_message(ids).startswith("Hello, We are "))
        self.assertEqual(len(group_key(ids)), 32)          # SHA-256 = 32 byte


class TestRecordLayer(unittest.TestCase):
    def setUp(self):
        keys = P.derive_keys(b"z" * 32, group_key(), b"t" * 32)
        self.a = P.RecordLayer(keys, True)
        self.b = P.RecordLayer(keys, False)

    def test_roundtrip(self):
        for i in range(5):
            self.assertEqual(self.b.open(self.a.seal({"i": i}))["i"], i)

    def test_tamper_detected(self):
        rec = self.a.seal({"x": 1})
        raw = bytearray(P.b64d(rec["ct"])); raw[0] ^= 1
        rec["ct"] = P.b64e(bytes(raw))
        self.assertRaises(P.SecurityError, self.b.open, rec)

    def test_replay_detected(self):
        rec = self.a.seal({"x": 1})
        self.b.open(rec)
        self.assertRaises(P.SecurityError, self.b.open, rec)


class TestMitmAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_keys()

    def test_tamper(self):
        self.assertTrue(scenario_tamper()[0])

    def test_replay(self):
        self.assertTrue(scenario_replay()[0])

    def test_signed_blocks_mitm(self):
        self.assertTrue(scenario_active_dh(secure=True)[0])

    def test_unsigned_is_vulnerable(self):
        # o che do khong ky, MitM thanh cong -> ham tra True kem loi giai thich
        ok, detail = scenario_active_dh(secure=False)
        self.assertTrue(ok)
        self.assertIn("THANH CONG", detail)


class TestLiveSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_keys()
        cls.srv = RelayServer(port=0).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def _pair(self, secure=True):
        ev = {"alice": [], "bob": []}
        room = "t%d" % time.time_ns()
        mk = lambda u, p: SecureClient(
            u, p, port=self.srv.port, room=room,
            secure=secure, verbose=False,
            on_event=lambda k, d, u=u: ev[u].append((k, d)))
        a = mk("alice", "bob"); b = mk("bob", "alice")
        t = threading.Thread(target=a.connect); t.start()
        time.sleep(0.15); b.connect(); t.join()
        return a, b, ev

    def test_chat_and_file(self):
        a, b, ev = self._pair()
        # cung chung ket qua bat tay
        self.assertEqual(a.session_info["key_id"], b.session_info["key_id"])
        b.send_text("chao alice")
        tmp = os.path.join(DATA, "sample.bin")
        with open(tmp, "wb") as f:
            f.write(os.urandom(120000))
        b.send_file(tmp)
        time.sleep(0.6)
        msgs = [d for k, d in ev["alice"] if k == "message"]
        files = [d for k, d in ev["alice"] if k == "file"]
        self.assertIn("chao alice", msgs)
        self.assertTrue(files and files[0]["ok"])
        a.close(); b.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

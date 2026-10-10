"""Run from tools/lumma_go:  python -m unittest discover -s tests -v

The sample tests only run if you point them at the files:
  LUMMA_GO_STAGE1=<loader>  LUMMA_GO_STAGE2=<payload>
"""
import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import extract_config as ec  # noqa: E402
import lumma_crypto as lc  # noqa: E402
import unpack_stage1 as up  # noqa: E402

STAGE1 = "a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805"
STAGE2 = "7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df"
C2 = ["convuey.cyou", "bendavo.su/asdsa", "conxmsw.su/vcsf", "narroxp.su/rewd", "squeaue.su/qwe",
      "ozonelf.su/asd", "exposqw.su/casc", "squatje.su/asdasd", "vicareu.su/bcdf"]


class Crypto(unittest.TestCase):
    def test_chacha_zero_vector(self):
        self.assertEqual(lc.chacha20(b"\0" * 32, b"\0" * 8, b"\0" * 16).hex(), "76b8e0ada0f13d90405d6ae55386bd28")

    def test_rot15(self):
        self.assertEqual(lc.rot15("lza"), "aop")
        self.assertEqual(lc.rot15("Ab.1-z"), "Aq.1-o")

    def test_fnv1a(self):
        self.assertEqual(lc.fnv1a(b"WinHttpSetTimeouts"), 0xCF43BDCF)

    def test_loader_decode(self):
        raw = bytes([0xA8]) + struct.pack("<H", 0xA835) + b"".join(
            struct.pack("<Q", q) for q in (0xBB2DAF2CB522B5EB, 0x9A0C9AF377199F22, 0xB234B6199F10BC30, 0x86F79F199A26B121))
        self.assertEqual(up.decode(raw), b"C:\\\\Windows\\\\SysWOW64\\\\explorer.exe")

    def test_bad_input(self):
        with self.assertRaises(up.UnpackError):
            up.unpack(b"nope")
        with self.assertRaises(ec.ExtractError):
            ec.extract(b"nope")


@unittest.skipUnless(os.environ.get("LUMMA_GO_STAGE1"), "LUMMA_GO_STAGE1 not set")
class Loader(unittest.TestCase):
    def test_unpack(self):
        pe = open(os.environ["LUMMA_GO_STAGE1"], "rb").read()
        self.assertEqual(hashlib.sha256(pe).hexdigest(), STAGE1)
        payload, info = up.unpack(pe)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), STAGE2)
        self.assertEqual(info["blob_size"], 0x51A08)

    def test_config_through_loader(self):
        cfg = ec.extract(open(os.environ["LUMMA_GO_STAGE1"], "rb").read())
        self.assertEqual([e["c2"] for e in cfg["c2"]], C2)


@unittest.skipUnless(os.environ.get("LUMMA_GO_STAGE2"), "LUMMA_GO_STAGE2 not set")
class Payload(unittest.TestCase):
    def test_config(self):
        cfg = ec.extract(open(os.environ["LUMMA_GO_STAGE2"], "rb").read())
        self.assertEqual(cfg["sha256"], STAGE2)
        self.assertEqual([e["c2"] for e in cfg["c2"]], C2)
        self.assertEqual([e["counter"] for e in cfg["c2"]], [2 + 2 * i for i in range(9)])
        self.assertEqual(cfg["chacha20_key"], "972ce069e3b6756f6de83a46dd2cbb35a0a4d4d5280966145020d6924e31e1da")
        self.assertEqual(cfg["chacha20_nonce"], "cd1fbfdb5c98bb36")
        self.assertEqual(cfg["uid"], "dc8e5f3081889c0e241b9a0281076771effc3817c5b1cd4ddb43b54f")
        self.assertEqual(cfg["cid"], "")


if __name__ == "__main__":
    unittest.main()

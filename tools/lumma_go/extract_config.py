"""Config extractor for the Lumma payload from the GO campaign.

Takes the payload or the Go loader (unpacks it first). Finds the ChaCha20 key,
nonce and C2 table by code pattern, so it doesn't rely on fixed offsets.
The Steam dead drop is a stack string and isn't decoded here; it's printed
only for the known sample.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lumma_crypto import chacha20  # noqa: E402

KNOWN_SHA256 = "7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df"
KNOWN_DEAD_DROP = "https://steamcommunity.com/profiles/76561199880317058"

KEY_INIT = re.compile(rb"\xB8(?P<key>.{4})\xBF.{4}\xB9\x08\x00\x00\x00\x96\xF3\xA5\x96\xB8(?P<nonce>.{4})", re.DOTALL)
TABLE = re.compile(rb"\xC1\xE1\x07\x8D\x89(?P<va>.{4})", re.DOTALL)
SLOTS = re.compile(rb"\x0F\xB6\x05.{4}\x34.\x3C(?P<max>.)\x77", re.DOTALL)
UID = re.compile(rb"(?<![0-9a-f])([0-9a-f]{32,64})\x00")
ENTRY = 128


class ExtractError(Exception):
    pass


class PE:
    def __init__(self, data):
        if data[:2] != b"MZ":
            raise ExtractError("not a PE file")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e + 4] != b"PE\0\0":
            raise ExtractError("not a PE file")
        self.machine, count = struct.unpack_from("<HH", data, e + 4)
        opt = struct.unpack_from("<H", data, e + 20)[0]
        pe32 = struct.unpack_from("<H", data, e + 24)[0] == 0x10B
        self.base = struct.unpack_from("<I" if pe32 else "<Q", data, e + (52 if pe32 else 48))[0]
        self.secs, off = [], e + 24 + opt
        for _ in range(count):
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, off + 8)
            self.secs.append((va, max(vsize, rsize), raw, rsize))
            off += 40
        self.data = data

    def read(self, va, n):
        rva = va - self.base
        for sva, size, raw, rsize in self.secs:
            if sva <= rva < sva + size and rva - sva < rsize:
                o = raw + rva - sva
                return self.data[o:o + n]
        raise ExtractError(f"VA 0x{va:x} not in the file")

    def va_of(self, off):
        for va, _, raw, rsize in self.secs:
            if raw <= off < raw + rsize:
                return self.base + va + off - raw
        raise ExtractError(f"offset 0x{off:x} not in a section")


def looks_like_host(b):
    s = b.split(b"\0")[0]
    return len(s) >= 4 and b"." in s and all(33 <= c < 127 for c in s)


def extract(data):
    pe = PE(data)
    if pe.machine == 0x8664:
        import unpack_stage1
        data, _ = unpack_stage1.unpack(data)
        pe = PE(data)
    if pe.machine != 0x14C:
        raise ExtractError("expected the x86 payload")

    m = KEY_INIT.search(data)
    t = TABLE.search(data)
    if not m or not t:
        raise ExtractError("ChaCha20 setup or C2 table not found")
    key = pe.read(struct.unpack("<I", m.group("key"))[0], 32)
    nonce = pe.read(struct.unpack("<I", m.group("nonce"))[0], 8)
    table = struct.unpack("<I", t.group("va"))[0]
    s = SLOTS.search(data)
    count = s.group("max")[0] + 1 if s else 9

    # the cipher keeps its block counter between calls: slot i uses 2 + 2*i here
    c2 = []
    for i in range(count):
        ct = pe.read(table + ENTRY * i, ENTRY)
        for ctr in [2 + 2 * i] + [c for c in range(128) if c != 2 + 2 * i]:
            pt = chacha20(key, nonce, ct, ctr)
            if looks_like_host(pt):
                c2.append({"slot": i, "c2": pt.split(b"\0")[0].decode(), "counter": ctr})
                break
        else:
            c2.append({"slot": i, "c2": None, "counter": None})

    uids = sorted({u.decode() for u in UID.findall(data)})
    cid = None
    if len(uids) == 1:
        uid_off = data.find(uids[0].encode() + b"\0")
        ptr = data.find(struct.pack("<I", pe.va_of(uid_off)))
        if ptr >= 0:
            try:
                cid = pe.read(struct.unpack_from("<I", data, ptr + 4)[0], 256).split(b"\0")[0].decode("latin-1")
            except ExtractError:
                pass

    sha = hashlib.sha256(data).hexdigest()
    return {
        "sha256": sha,
        "uid": uids[0] if len(uids) == 1 else uids,
        "cid": cid,
        "chacha20_key": key.hex(),
        "chacha20_nonce": nonce.hex(),
        "c2": c2,
        "dead_drop": KNOWN_DEAD_DROP if sha == KNOWN_SHA256 else None,
    }


def main():
    p = argparse.ArgumentParser(description="Extract the config from a GO campaign Lumma sample")
    p.add_argument("sample", help="the payload, or the Go loader")
    p.add_argument("--defang", action="store_true")
    a = p.parse_args()

    try:
        cfg = extract(open(a.sample, "rb").read())
    except Exception as e:
        sys.exit(f"error: {e}")

    if a.defang:
        for e in cfg["c2"]:
            if e["c2"]:
                e["c2"] = e["c2"].replace(".", "[.]")
        if cfg["dead_drop"]:
            cfg["dead_drop"] = cfg["dead_drop"].replace("https", "hxxps").replace(".", "[.]")
    print(json.dumps(cfg, indent=2))


if __name__ == "__main__":
    main()

"""Static config extractor for the Lumma payloads of both chains.

Both builds store the C2 table the same way:

    key (32 B) | nonce (8 B) | table: N slots x 0x80 bytes

The table is decrypted as one continuous ChaCha20 keystream starting at
counter 0, so slot i uses block counter 2*i. Slot 0 is not a C2 string in
either build. The key and nonce are found through the code that copies them
into the cipher state, so no fixed offsets are used:

    GO build : B8 <key> BF <dst> B9 08 00 00 00 96 F3 A5 96 B8 <nonce>
    AIO build: B8 <key> B9 08 00 00 00 BF <dst> 96 F3 A5 96 B8 <nonce>

Works on the unpacked payload on disk, on the GO loader (unpacked first), and
on an image dumped from memory (--layout mapped, e.g. a Volatility VAD dump of
the hollowed process). Never executes anything.
"""
import argparse
import hashlib
import json
import re
import struct
import sys

from crypto import chacha20
from pe import PE, PEError, MACHINE_AMD64, MACHINE_I386

SLOT = 0x80
DEFAULT_SLOTS = 10

KEY_COPY = re.compile(
    rb"\xB8(?P<key>.{4})(?:\xBF.{4}\xB9\x08\x00\x00\x00|\xB9\x08\x00\x00\x00\xBF.{4})"
    rb"\x96\xF3\xA5\x96\xB8(?P<nonce>.{4})", re.DOTALL)
# GO build: movzx eax, state ; xor al, imm ; cmp al, max ; ja  -> number of C2 slots after slot 0
SLOT_COUNT = re.compile(rb"\x0F\xB6\x05.{4}\x34.\x3C(?P<max>.)\x77", re.DOTALL)
# GO build: shl ecx, 7 ; lea ecx, [ecx + table]  -> fallback table location
TABLE_LEA = re.compile(rb"\xC1\xE1\x07\x8D\x89(?P<va>.{4})", re.DOTALL)
UID = re.compile(rb"(?<![0-9a-f])([0-9a-f]{32,64})\x00")


class ExtractError(Exception):
    pass


def _host(pt):
    s = pt.split(b"\0")[0]
    if len(s) >= 4 and b"." in s and all(33 <= c < 127 for c in s):
        return s.decode()
    return None


def _decrypt_table(pe, key, nonce, table_va, nslots):
    slots = []
    for i in range(nslots):
        try:
            ct = pe.read_va(table_va + SLOT * i, SLOT)
        except PEError:
            break
        pt = chacha20(key, nonce, ct, 2 * i)
        slots.append({"slot": i, "c2": _host(pt), "counter": 2 * i})
    return slots


def _scan_counters(pe, key, nonce, table_va, nslots):
    """Fallback for a table that isn't right after the nonce: try counters per slot."""
    slots = []
    for i in range(nslots):
        try:
            ct = pe.read_va(table_va + SLOT * i, SLOT)
        except PEError:
            break
        hit = None
        for ctr in range(256):
            h = _host(chacha20(key, nonce, ct, ctr))
            if h:
                hit = {"slot": i, "c2": h, "counter": ctr}
                break
        slots.append(hit or {"slot": i, "c2": None, "counter": None})
    return slots


def _candidate_pes(data, layout, base):
    if layout in ("file", "auto"):
        yield PE(data, "file", base)
    if layout in ("mapped", "auto"):
        pe = PE(data, "mapped", base)
        yield pe
        if base is None:
            m = KEY_COPY.search(data)
            if m:  # relocated dump: try every 64 KB-aligned base that puts the key inside the dump
                key_va = struct.unpack("<I", m.group("key"))[0]
                lo = max(0, key_va - len(data)) & ~0xFFFF
                for b in range(lo, key_va + 1, 0x10000):
                    if b != pe.base:
                        yield PE(data, "mapped", b)


def _extract_from(pe, data):
    m = KEY_COPY.search(data)
    if not m:
        raise ExtractError("ChaCha20 key-copy code not found (different Lumma build?)")
    key_va = struct.unpack("<I", m.group("key"))[0]
    nonce_va = struct.unpack("<I", m.group("nonce"))[0]
    key, nonce = pe.read_va(key_va, 32), pe.read_va(nonce_va, 8)

    s = SLOT_COUNT.search(data)
    nslots = s.group("max")[0] + 2 if s else DEFAULT_SLOTS

    table_va, method = nonce_va + 8, "continuous"
    slots = _decrypt_table(pe, key, nonce, table_va, nslots)
    if not any(x["c2"] for x in slots):
        t = TABLE_LEA.search(data)
        if not t:
            raise ExtractError("C2 table did not decrypt and no fallback table reference found")
        table_va, method = struct.unpack("<I", t.group("va"))[0], "counter-scan"
        slots = _scan_counters(pe, key, nonce, table_va, nslots)
        if not any(x["c2"] for x in slots):
            raise ExtractError("C2 table did not decrypt")

    uids = sorted({u.decode() for u in UID.findall(data)})
    cid = None
    if len(uids) == 1:  # cid is the string the config struct points to right after uid (GO build)
        try:
            ptr = data.find(struct.pack("<I", pe.va_of(data.find(uids[0].encode() + b"\0"))))
            if ptr >= 0:
                cid = pe.read_va(struct.unpack_from("<I", data, ptr + 4)[0], 256).split(b"\0")[0].decode("latin-1")
        except (PEError, struct.error, UnicodeDecodeError):
            cid = None

    c2 = []
    for x in slots:
        if x["c2"] and x["c2"] not in c2:
            c2.append(x["c2"])
    return {
        "layout": pe.layout,
        "image_base": hex(pe.base),
        "chacha20_key": key.hex(),
        "chacha20_nonce": nonce.hex(),
        "key_va": hex(key_va),
        "nonce_va": hex(nonce_va),
        "table_va": hex(table_va),
        "table_method": method,
        "slots": slots,
        "c2": c2,
        "uid": uids[0] if len(uids) == 1 else (uids or None),
        "cid": cid,
    }


def extract(data, layout="auto", base=None):
    """Return the config dict. `data` may be the payload, the GO loader, or a memory dump."""
    first = PE(data, "file")
    if first.machine == MACHINE_AMD64:
        import go_loader
        data, _ = go_loader.unpack(data)
        layout = "file"
    elif first.machine != MACHINE_I386:
        raise ExtractError("expected the x86 Lumma payload or the x64 GO loader")

    errors = []
    for pe in _candidate_pes(data, layout, base):
        try:
            cfg = _extract_from(pe, data)
            cfg["sha256"] = hashlib.sha256(data).hexdigest()
            return cfg
        except (ExtractError, PEError) as e:
            errors.append(f"{pe.layout}@{pe.base:#x}: {e}")
    raise ExtractError("; ".join(dict.fromkeys(errors)) or "no layout matched")


def defang(cfg):
    out = json.loads(json.dumps(cfg))
    out["c2"] = [c.replace(".", "[.]") for c in out["c2"]]
    for s in out["slots"]:
        if s["c2"]:
            s["c2"] = s["c2"].replace(".", "[.]")
    return out


def main():
    p = argparse.ArgumentParser(description="Extract the C2 config from a Lumma payload (GO or AIO build)")
    p.add_argument("sample", help="payload, GO loader, or memory dump of the hollowed image")
    p.add_argument("--layout", choices=["auto", "file", "mapped"], default="auto",
                   help="'mapped' for memory dumps (default: try file, then mapped)")
    p.add_argument("--base", type=lambda x: int(x, 0), help="image base of a memory dump, if relocated")
    p.add_argument("--defang", action="store_true")
    a = p.parse_args()
    try:
        cfg = extract(open(a.sample, "rb").read(), a.layout, a.base)
    except (OSError, ExtractError, PEError) as e:
        sys.exit(f"error: {e}")
    print(json.dumps(defang(cfg) if a.defang else cfg, indent=2))


if __name__ == "__main__":
    main()

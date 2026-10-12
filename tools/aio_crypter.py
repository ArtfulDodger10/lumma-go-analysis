"""Static unpacker for the AIO Checker chain (chain 2). Never executes anything.

    outer x64 crypter   --RC4(.jss, K1)-->  x86 dropper
    x86 dropper (.cSs)  --RC4(blob, K2)-->  A: .NET clipper, B: x64 crypter (same build as outer)
    B                   --RC4(.jss, K1)-->  Lumma payload

K1 (10 bytes) is built as stack immediates in the crypter (outer: 0x14000D6E7).
The first section named .jss holds the encrypted inner PE.
K2 is the first 40 bytes of the dropper's .cSs section. The blobs sit at fixed
offsets in the known build; if those don't decrypt, every 16-byte-aligned
offset in .cSs is tried (one RC4 keystream, so this is fast).
"""
import argparse
import hashlib
import json
import os
import struct
import sys

from crypto import rc4, rc4_keystream
from pe import PE, PEError, MACHINE_AMD64, MACHINE_I386

KNOWN_K1 = [bytes.fromhex("925467564211364dbb01")]
K2_LEN = 0x28
KNOWN_BLOBS = [(0x60, 0xFA000), (0xFA060, 0x2C00)]  # (offset in .cSs, size): crypter B, clipper A


class UnpackError(Exception):
    pass


def is_crypter(data):
    try:
        pe = PE(data)
    except PEError:
        return False
    return pe.machine == MACHINE_AMD64 and pe.section(b".jss") is not None


def is_dropper(data):
    try:
        pe = PE(data)
    except PEError:
        return False
    return pe.machine == MACHINE_I386 and pe.section(b".cSs") is not None


def _valid_pe(buf):
    try:
        PE(buf)
        return True
    except (PEError, struct.error):
        return False


def _trim(buf):
    try:
        return buf[:PE(buf).file_end()]
    except PEError:
        return buf


def unwrap_crypter(data, keys=None):
    """Crypter (.jss) -> inner PE. Returns (payload, info)."""
    try:
        sec = PE(data).section_data(b".jss")
    except PEError as e:
        raise UnpackError(str(e))
    for k in (keys or []) + KNOWN_K1:
        out = rc4(k, sec)
        if out[:2] == b"MZ" and _valid_pe(out):
            return _trim(out), {"rc4_key": k.hex(), "jss_size": len(sec)}
    raise UnpackError("no known RC4 key decrypts .jss (new crypter build? pass --key)")


def split_dropper(data):
    """Dropper (.cSs) -> list of (payload, info) for every embedded PE."""
    try:
        css = PE(data).section_data(b".cSs")
    except PEError as e:
        raise UnpackError(str(e))
    k2 = css[:K2_LEN]
    found = []
    for off, size in KNOWN_BLOBS:
        blob = css[off:off + size]
        if len(blob) == size:
            out = rc4(k2, blob)
            if out[:2] == b"MZ" and _valid_pe(out):
                found.append((out, {"cSs_offset": hex(off), "size": size, "method": "known-offset"}))
    if len(found) == len(KNOWN_BLOBS):
        return found

    found = []
    ks = rc4_keystream(k2, 0x400)
    for off in range(K2_LEN, len(css) - 0x40, 0x10):
        if css[off] ^ ks[0] != 0x4D or css[off + 1] ^ ks[1] != 0x5A:
            continue
        out = rc4(k2, css[off:])
        if _valid_pe(out):
            out = _trim(out)
            found.append((out, {"cSs_offset": hex(off), "size": len(out), "method": "scan"}))
    if not found:
        raise UnpackError("no embedded PE found in .cSs (new dropper build?)")
    return found


def unwrap_chain(data, keys=None):
    """Outer crypter -> every stage. Returns a list of (name, payload, info)."""
    layer2, info = unwrap_crypter(data, keys)
    stages = [("dropper", layer2, info)]
    for blob, binfo in split_dropper(layer2):
        pe = PE(blob)
        if pe.is_dotnet:
            stages.append(("clipper", blob, binfo))
        elif is_crypter(blob):
            stages.append(("crypter_b", blob, binfo))
            final, finfo = unwrap_crypter(blob, keys)
            stages.append(("lumma", final, finfo))
        else:
            stages.append(("unknown", blob, binfo))
    return stages


def main():
    p = argparse.ArgumentParser(description="Unpack every stage of the AIO Checker chain")
    p.add_argument("sample", help="outer crypter, second crypter, or dropper")
    p.add_argument("-o", "--out-dir", help="write each stage here (default: don't write)")
    p.add_argument("--key", action="append", default=[], help="extra RC4 key (hex) for a new crypter build")
    a = p.parse_args()
    keys = [bytes.fromhex(k) for k in a.key]
    try:
        data = open(a.sample, "rb").read()
        if is_crypter(data):
            stages = unwrap_chain(data, keys)
        elif is_dropper(data):
            stages = [("embedded", b, i) for b, i in split_dropper(data)]
        else:
            raise UnpackError("not an AIO crypter (.jss) or dropper (.cSs)")
    except (OSError, UnpackError, PEError) as e:
        sys.exit(f"error: {e}")

    report = []
    for name, buf, info in stages:
        sha = hashlib.sha256(buf).hexdigest()
        entry = {"stage": name, "sha256": sha, "size": len(buf), **info}
        if a.out_dir:
            os.makedirs(a.out_dir, exist_ok=True)
            path = os.path.join(a.out_dir, f"{name}_{sha[:12]}.bin")
            open(path, "wb").write(buf)
            entry["written_to"] = path
        report.append(entry)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

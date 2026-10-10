"""Pulls the Lumma payload out of the Go loader without running it.

The loader builds the payload on the stack from an 8-byte immediate plus a
rep movsq from .rdata, reverses it, then subtracts 0x43 from even bytes and
adds 0x43 to odd ones.
"""
import argparse
import hashlib
import json
import re
import struct
import sys

KEY = 0x43

# mov rdx, imm64 / mov [rsp+x], rdx / lea rdi, [rsp+y] / lea rsi, blob / mov ecx, n / rep movsq
BLOB = re.compile(rb"\x48\xBA(?P<imm>.{8})\x48\x89\x54\x24.\x48\x8D\x7C\x24."
                  rb"\x48\x8D\x35(?P<rel>.{4})\xB9(?P<cnt>.{4})\xF3\x48\xA5", re.DOTALL)


class UnpackError(Exception):
    pass


def decode(data, key=KEY):
    data = data[::-1]
    return bytes(((b - key) if i % 2 == 0 else (b + key)) & 0xFF for i, b in enumerate(data))


def sections(pe):
    if pe[:2] != b"MZ":
        raise UnpackError("not a PE file")
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e:e + 4] != b"PE\0\0":
        raise UnpackError("not a PE file")
    machine, count = struct.unpack_from("<HH", pe, e + 4)
    if machine != 0x8664:
        raise UnpackError("expected the x64 Go loader")
    opt = struct.unpack_from("<H", pe, e + 20)[0]
    base = struct.unpack_from("<Q", pe, e + 48)[0]
    out, off = [], e + 24 + opt
    for _ in range(count):
        vsize, va, rsize, raw = struct.unpack_from("<IIII", pe, off + 8)
        out.append((va, max(vsize, rsize), raw, rsize))
        off += 40
    return base, out


def rva_to_off(secs, rva):
    for va, size, raw, rsize in secs:
        if va <= rva < va + size and rva - va < rsize:
            return raw + rva - va
    raise UnpackError(f"RVA 0x{rva:x} not in the file")


def off_to_rva(secs, off):
    for va, _, raw, rsize in secs:
        if raw <= off < raw + rsize:
            return va + off - raw
    raise UnpackError(f"offset 0x{off:x} not in a section")


def unpack(pe):
    base, secs = sections(pe)
    for m in BLOB.finditer(pe):
        rel = struct.unpack("<i", m.group("rel"))[0]
        cnt = struct.unpack("<I", m.group("cnt"))[0]
        body_rva = off_to_rva(secs, m.end("rel")) + rel
        body_off = rva_to_off(secs, body_rva)
        body = pe[body_off:body_off + cnt * 8]
        if len(body) != cnt * 8:
            continue
        payload = decode(m.group("imm") + body)
        if payload[:2] == b"MZ":
            return payload, {
                "body_va": hex(base + body_rva),
                "body_file_offset": hex(body_off),
                "blob_size": 8 + len(body),
            }
    raise UnpackError("payload blob not found")


def main():
    p = argparse.ArgumentParser(description="Unpack the Lumma payload from the GO campaign loader")
    p.add_argument("sample")
    p.add_argument("-o", "--out", help="output file (default: <sample>.stage2.bin)")
    p.add_argument("--no-write", action="store_true")
    a = p.parse_args()

    try:
        pe = open(a.sample, "rb").read()
        payload, info = unpack(pe)
    except (OSError, UnpackError) as e:
        sys.exit(f"error: {e}")

    info["stage2_sha256"] = hashlib.sha256(payload).hexdigest()
    if not a.no_write:
        out = a.out or a.sample + ".stage2.bin"
        open(out, "wb").write(payload)
        info["written_to"] = out
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()

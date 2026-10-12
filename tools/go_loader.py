"""Static unpacker for the GO loader (chain 1). Never executes the sample.

The loader builds the payload on the stack from an 8-byte immediate plus a
rep movsq from .rdata, reverses it, then subtracts 0x43 from even bytes and
adds 0x43 to odd ones. The code pattern locates the blob, so no fixed offsets.

    mov rdx, imm64 ; mov [rsp+x], rdx ; lea rdi, [rsp+y] ; lea rsi, blob ; mov ecx, n ; rep movsq
"""
import argparse
import hashlib
import json
import re
import struct
import sys

from crypto import go_loader_decode
from pe import PE, PEError, MACHINE_AMD64

BLOB = re.compile(rb"\x48\xBA(?P<imm>.{8})\x48\x89\x54\x24.\x48\x8D\x7C\x24."
                  rb"\x48\x8D\x35(?P<rel>.{4})\xB9(?P<cnt>.{4})\xF3\x48\xA5", re.DOTALL)
GO_MARKERS = (b"\xff Go buildinf:", b"main._RunPE", b"runtime.goexit")


class UnpackError(Exception):
    pass


def is_go_loader(data):
    return data[:2] == b"MZ" and any(m in data for m in GO_MARKERS) and BLOB.search(data) is not None


def unpack(data):
    try:
        pe = PE(data)
    except PEError as e:
        raise UnpackError(str(e))
    if pe.machine != MACHINE_AMD64:
        raise UnpackError("expected the x64 GO loader")
    for m in BLOB.finditer(data):
        rel = struct.unpack("<i", m.group("rel"))[0]
        cnt = struct.unpack("<I", m.group("cnt"))[0]
        try:
            body_rva = pe.off_to_rva(m.end("rel")) + rel
            body_off = pe.rva_to_off(body_rva)
        except PEError:
            continue
        body = data[body_off:body_off + cnt * 8]
        if len(body) != cnt * 8:
            continue
        payload = go_loader_decode(m.group("imm") + body)
        if payload[:2] == b"MZ":
            return payload, {
                "blob_va": hex(pe.base + body_rva),
                "blob_file_offset": hex(body_off),
                "blob_size": 8 + len(body),
            }
    raise UnpackError("payload blob not found (different loader build?)")


def main():
    p = argparse.ArgumentParser(description="Unpack the Lumma payload from the GO loader")
    p.add_argument("sample")
    p.add_argument("-o", "--out", help="output file (default: <sample>.stage2.bin)")
    p.add_argument("--no-write", action="store_true")
    a = p.parse_args()
    try:
        payload, info = unpack(open(a.sample, "rb").read())
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

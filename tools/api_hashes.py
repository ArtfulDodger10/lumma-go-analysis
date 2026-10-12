"""Resolve API hashes from both chains against a DLL's export names.

    Lumma (GO build):     FNV-1a, offset basis 0x69BBE5D1
    AIO crypter/dropper:  MurmurHash2 variant, seed 707 (crypter) / 565 (dropper)

Examples:
    python api_hashes.py hash --algo murmur --seed 707 VirtualAllocEx
    python api_hashes.py scan --algo fnv C:\\Windows\\SysWOW64\\winhttp.dll 0xCF43BDCF
"""
import argparse
import struct
import sys

from crypto import fnv1a, murmur2_variant, FNV_SEED
from pe import PE, PEError


def export_names(data):
    pe = PE(data)
    if not pe.dirs or not pe.dirs[0][0]:
        return []
    e = pe.rva_to_off(pe.dirs[0][0])
    count = struct.unpack_from("<I", data, e + 24)[0]
    names = pe.rva_to_off(struct.unpack_from("<I", data, e + 32)[0])
    out = []
    for j in range(count):
        p = pe.rva_to_off(struct.unpack_from("<I", data, names + 4 * j)[0])
        out.append(data[p:data.index(b"\0", p)].decode("latin-1"))
    return out


def hasher(algo, seed):
    if algo == "fnv":
        return lambda n: fnv1a(n, FNV_SEED if seed is None else seed)
    return lambda n: murmur2_variant(n, 707 if seed is None else seed)


def main():
    p = argparse.ArgumentParser(description="API hash helper for the Lumma campaign")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("hash", "scan"):
        s = sub.add_parser(name)
        s.add_argument("--algo", choices=["fnv", "murmur"], required=True)
        s.add_argument("--seed", type=lambda x: int(x, 0))
    sub.choices["hash"].add_argument("names", nargs="+")
    sub.choices["scan"].add_argument("dll")
    sub.choices["scan"].add_argument("hashes", nargs="+")
    a = p.parse_args()
    h = hasher(a.algo, a.seed)
    try:
        if a.cmd == "hash":
            for n in a.names:
                print(f"{h(n):08X}  {n}")
        else:
            want = {int(x, 16) for x in a.hashes}
            for n in export_names(open(a.dll, "rb").read()):
                if h(n) in want:
                    print(f"{h(n):08X}  {n}")
    except (OSError, PEError, ValueError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()

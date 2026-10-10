"""Crypto helpers for the Lumma payload from the GO campaign."""
import argparse
import struct
import sys

FNV_SEED = 0x69BBE5D1
FNV_PRIME = 0x01000193


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20(key, nonce, data, counter=0):
    """Original ChaCha20: 64-bit counter, 8-byte nonce."""
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("need a 32-byte key and an 8-byte nonce")
    out = bytearray()
    for off in range(0, len(data), 64):
        st = (list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key))
              + [counter & 0xFFFFFFFF, counter >> 32] + list(struct.unpack("<2I", nonce)))
        w = st[:]
        for _ in range(10):
            _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
            _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
        ks = struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
        counter += 1
    return bytes(out)


def rot15(name):
    """Steam display name -> C2 host. Only lowercase letters move."""
    return "".join(chr((ord(c) - 97 + 15) % 26 + 97) if "a" <= c <= "z" else c for c in name)


def fnv1a(name):
    h = FNV_SEED
    for c in name:
        h = ((h ^ c) * FNV_PRIME) & 0xFFFFFFFF
    return h


def main():
    p = argparse.ArgumentParser(description="Lumma (GO campaign) crypto helpers")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("chacha", help="decrypt hex data")
    c.add_argument("--key", required=True)
    c.add_argument("--nonce", required=True)
    c.add_argument("--counter", type=int, default=0)
    c.add_argument("data")
    sub.add_parser("rot15", help="decode a Steam display name").add_argument("name")
    sub.add_parser("fnv1a", help="hash an API name").add_argument("name")
    a = p.parse_args()

    try:
        if a.cmd == "chacha":
            pt = chacha20(bytes.fromhex(a.key), bytes.fromhex(a.nonce), bytes.fromhex(a.data), a.counter)
            print(pt.split(b"\0")[0].decode("latin-1"))
        elif a.cmd == "rot15":
            print(rot15(a.name))
        else:
            print(f"0x{fnv1a(a.name.encode()):08x}")
    except ValueError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()

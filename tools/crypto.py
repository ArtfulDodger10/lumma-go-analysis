"""Crypto and hashing routines recovered from both chains.

| Routine | Where it's used |
|---|---|
| ChaCha20 (original, 64-bit counter, 8-byte nonce) | Lumma C2 table, both builds |
| RC4 | AIO crypter (.jss section), AIO dropper (embedded blobs) |
| Go loader encoding (reverse, -/+0x43) | GO loader payload |
| FNV-1a, offset basis 0x69BBE5D1 | Lumma API hashing (GO build) |
| MurmurHash2 variant (tail * m) | AIO crypter (seed 707) and dropper (seed 565) API hashing |
| ROT15 (lowercase only) | Lumma Steam / Telegram dead-drop host |
"""
import struct

FNV_SEED = 0x69BBE5D1
FNV_PRIME = 0x01000193
MURMUR_M = 0x5BD1E995


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20(key, nonce, data, counter=0):
    """Original (DJB) ChaCha20: 64-bit block counter, 8-byte nonce."""
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("need a 32-byte key and an 8-byte nonce")
    out = bytearray()
    for off in range(0, len(data), 64):
        st = (list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key))
              + [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF] + list(struct.unpack("<2I", nonce)))
        w = st[:]
        for _ in range(10):
            _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
            _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
        ks = struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
        counter += 1
    return bytes(out)


def rc4_keystream(key, n):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(n)
    for k in range(n):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def rc4(key, data):
    ks = rc4_keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def go_loader_decode(data, key=0x43):
    """GO loader: reverse the blob, then even bytes -key, odd bytes +key."""
    data = data[::-1]
    return bytes(((b - key) if i % 2 == 0 else (b + key)) & 0xFF for i, b in enumerate(data))


def fnv1a(name, seed=FNV_SEED):
    if isinstance(name, str):
        name = name.encode()
    h = seed
    for c in name:
        h = ((h ^ c) * FNV_PRIME) & 0xFFFFFFFF
    return h


def murmur2_variant(name, seed=707):
    """MurmurHash2 with a non-standard tail: h ^= tail * m (standard: h ^= tail; h *= m)."""
    if isinstance(name, str):
        name = name.encode("latin-1")
    n = len(name)
    h = (seed ^ n) & 0xFFFFFFFF
    i = 0
    while n - i >= 4:
        k = struct.unpack_from("<I", name, i)[0]
        k = (k * MURMUR_M) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * MURMUR_M) & 0xFFFFFFFF
        h = ((h * MURMUR_M) & 0xFFFFFFFF) ^ k
        i += 4
    if n - i:
        t = 0
        for j, b in enumerate(name[i:]):
            t ^= b << (8 * j)
        h ^= (t * MURMUR_M) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * MURMUR_M) & 0xFFFFFFFF
    h ^= h >> 15
    return h


def rot15(name):
    """Dead-drop display name -> C2 host. Only lowercase letters move."""
    return "".join(chr((ord(c) - 97 + 15) % 26 + 97) if "a" <= c <= "z" else c for c in name)

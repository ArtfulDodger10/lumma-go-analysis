"""Config extractor for the .NET crypto clipper (AIO chain, ShinobuClipper-derived).

The config values (replacement wallets, mutex, autorun name) are plain .NET
user strings. This reads the #US heap directly from the metadata, without
running or decompiling the sample, then labels the wallets. In the known
build each wallet follows its coin label ("btc", "eth", ...); where a label is
missing, the coin is guessed from the address format.
"""
import argparse
import json
import re
import struct
import sys

from pe import PE, PEError

LABELS = {"btc", "btc1", "btc2", "eth", "xmr", "xrp", "trx", "doge", "btccash",
          "ltc", "ltc1", "ltc2", "ltc3", "sol", "bnb", "ton", "usdt"}
B58 = "1-9A-HJ-NP-Za-km-z"
FORMATS = [  # most specific first; sol is last because its format is loose
    ("eth", rf"0x[0-9a-fA-F]{{40}}"),
    ("btc", rf"bc1[02-9ac-hj-np-z]{{25,62}}"),
    ("ltc", rf"ltc1[02-9ac-hj-np-z]{{25,62}}"),
    ("btccash", rf"(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{{41}}"),
    ("xmr", rf"[48][0-9AB][{B58}]{{93}}"),
    ("trx", rf"T[{B58}]{{33}}"),
    ("doge", rf"D[5-9A-HJ-NP-U][{B58}]{{32}}"),
    ("ltc", rf"[LM][{B58}]{{26,33}}"),
    ("btc", rf"[13][{B58}]{{25,34}}"),
    ("xrp", rf"r[{B58}]{{24,34}}"),
    ("sol", rf"[{B58}]{{32,44}}"),
]


class ExtractError(Exception):
    pass


def user_strings(data):
    """All strings in the #US heap, in heap order."""
    pe = PE(data)
    if not pe.is_dotnet:
        raise ExtractError("not a .NET assembly")
    cor = pe.rva_to_off(pe.dirs[14][0])
    md_rva = struct.unpack_from("<I", data, cor + 8)[0]
    md = pe.rva_to_off(md_rva)
    if data[md:md + 4] != b"BSJB":
        raise ExtractError("metadata root not found")
    vlen = struct.unpack_from("<I", data, md + 12)[0]
    p = md + 16 + vlen
    nstreams = struct.unpack_from("<H", data, p + 2)[0]
    p += 4
    us = None
    for _ in range(nstreams):
        off, size = struct.unpack_from("<II", data, p)
        end = data.index(b"\0", p + 8)
        name = data[p + 8:end]
        p = (end + 4) & ~3
        if name == b"#US":
            us = data[md + off:md + off + size]
    if us is None:
        raise ExtractError("#US heap not found")

    out, i = [], 1  # entry 0 is the empty string
    while i < len(us):
        b = us[i]
        if b & 0x80 == 0:
            n, i = b, i + 1
        elif b & 0xC0 == 0x80:
            n, i = ((b & 0x3F) << 8) | us[i + 1], i + 2
        else:
            n, i = ((b & 0x1F) << 24) | (us[i + 1] << 16) | (us[i + 2] << 8) | us[i + 3], i + 4
        if n == 0:
            continue
        raw = us[i:i + n - 1]  # last byte is a flag
        i += n
        try:
            out.append(raw.decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
    return out


def guess_coin(s):
    for coin, rx in FORMATS:
        if re.fullmatch(rx, s):
            return coin
    return None


def extract(data):
    strings = user_strings(data)
    wallets, prev = [], None
    for s in strings:
        coin = guess_coin(s)
        if coin:
            label = prev if prev in LABELS else None
            if coin == "sol" and label is None:
                coin = None  # too loose to call without a label
            if label or coin:
                wallets.append({"label": label, "format": coin, "address": s})
        prev = s.strip().lower()
    mutex = [s for s in strings if len(s) >= 24 and re.fullmatch(r"[a-z]+", s)]
    return {"wallets": wallets, "mutex_candidates": mutex, "user_strings": len(strings)}


def main():
    p = argparse.ArgumentParser(description="Extract wallets and mutex from the AIO .NET clipper")
    p.add_argument("sample")
    p.add_argument("--all-strings", action="store_true", help="also print every #US string")
    a = p.parse_args()
    try:
        data = open(a.sample, "rb").read()
        cfg = extract(data)
        if a.all_strings:
            cfg["strings"] = user_strings(data)
    except (OSError, ExtractError, PEError, struct.error, ValueError) as e:
        sys.exit(f"error: {e}")
    print(json.dumps(cfg, indent=2))


if __name__ == "__main__":
    main()

"""Run every tool over a file or a folder: detect the stage, unpack, extract configs.

    python pipeline.py samples/ --jsonl results.jsonl --csv results.csv [--dump-dir stages/]

Handles the GO loader, the AIO crypters and dropper, the .NET clipper, bare
Lumma payloads, and memory dumps of a hollowed Lumma image (Volatility VAD /
malfind dumps; the base address in the file name is used if needed).
Reads files only. Never executes anything. Run it in the VM or on Kali.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sys

import aio_crypter
import clipper_config
import go_loader
import lumma_config
from pe import PE, PEError, MACHINE_I386

MAX_DEPTH = 4


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def classify(data):
    if data[:2] != b"MZ":
        return "not_pe"
    try:
        pe = PE(data)
    except PEError:
        return "bad_pe"
    if go_loader.is_go_loader(data):
        return "go_loader"
    if aio_crypter.is_crypter(data):
        return "aio_crypter"
    if aio_crypter.is_dropper(data):
        return "aio_dropper"
    if pe.is_dotnet:
        return "dotnet"
    if pe.machine == MACHINE_I386 and lumma_config.KEY_COPY.search(data):
        return "lumma"
    return "unknown"


def _lumma(data, name=""):
    try:
        return lumma_config.extract(data), None
    except Exception as e:  # noqa: BLE001 - every failure is recorded, not raised
        first = str(e)
    m = re.search(r"0x([0-9a-fA-F]{5,16})", os.path.basename(name))
    if m:
        try:
            return lumma_config.extract(data, "mapped", int(m.group(1), 16)), None
        except Exception as e:  # noqa: BLE001
            return None, f"{first}; mapped@0x{m.group(1)}: {e}"
    return None, first


def analyse(data, name="", depth=0, dump_dir=None):
    """Return a list of stage records for one buffer (recursing into unpacked stages)."""
    kind = classify(data)
    rec = {"sha256": _sha(data), "type": kind, "depth": depth}
    out = [rec]
    if dump_dir and depth > 0:
        os.makedirs(dump_dir, exist_ok=True)
        path = os.path.join(dump_dir, f"{kind}_{rec['sha256'][:12]}.bin")
        with open(path, "wb") as f:
            f.write(data)
    if depth >= MAX_DEPTH:
        return out
    try:
        if kind == "go_loader":
            payload, info = go_loader.unpack(data)
            rec["unpack"] = info
            out += analyse(payload, name, depth + 1, dump_dir)
        elif kind == "aio_crypter":
            inner, info = aio_crypter.unwrap_crypter(data)
            rec["unpack"] = info
            out += analyse(inner, name, depth + 1, dump_dir)
        elif kind == "aio_dropper":
            blobs = aio_crypter.split_dropper(data)
            rec["unpack"] = [i for _, i in blobs]
            for blob, _ in blobs:
                out += analyse(blob, name, depth + 1, dump_dir)
        elif kind == "dotnet":
            cfg = clipper_config.extract(data)
            if cfg["wallets"]:
                rec["type"] = "clipper"
                rec["config"] = cfg
        elif kind in ("lumma", "unknown"):
            cfg, err = _lumma(data, name)
            if cfg:
                rec["type"] = "lumma"
                rec["config"] = cfg
            elif kind == "lumma":
                rec["error"] = err
    except Exception as e:  # noqa: BLE001
        rec["error"] = f"{type(e).__name__}: {e}"
    return out


def summarise(path, stages):
    lumma = next((s for s in stages if s["type"] == "lumma" and "config" in s), None)
    clip = next((s for s in stages if s["type"] == "clipper"), None)
    errors = [s["error"] for s in stages if s.get("error")]
    chain = stages[0]["type"]
    if lumma or clip:
        status = "ok"
    elif chain in ("go_loader", "aio_crypter", "aio_dropper", "lumma"):
        status = "failed"
    else:
        status = "not_supported"
    return {
        "file": os.path.basename(path),
        "sha256": stages[0]["sha256"],
        "detected": chain,
        "stages": " > ".join(s["type"] for s in stages),
        "status": status,
        "lumma_sha256": lumma["sha256"] if lumma else "",
        "uid": (lumma["config"]["uid"] if lumma and isinstance(lumma["config"]["uid"], str) else ""),
        "c2_count": len(lumma["config"]["c2"]) if lumma else 0,
        "c2": ";".join(lumma["config"]["c2"]) if lumma else "",
        "layout": lumma["config"]["layout"] if lumma else "",
        "wallets": len(clip["config"]["wallets"]) if clip else 0,
        "error": " | ".join(errors),
    }


def iter_files(target):
    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for f in sorted(files):
                yield os.path.join(root, f)
    else:
        yield target


def main():
    p = argparse.ArgumentParser(description="Unpack and extract configs across many samples")
    p.add_argument("target", help="file or folder")
    p.add_argument("--jsonl", help="full per-sample results (raw C2 values)")
    p.add_argument("--csv", help="one summary row per sample")
    p.add_argument("--dump-dir", help="write every unpacked stage here")
    a = p.parse_args()

    rows, jf = [], open(a.jsonl, "w") if a.jsonl else None
    for path in iter_files(a.target):
        try:
            data = open(path, "rb").read()
        except OSError as e:
            print(f"skip {path}: {e}", file=sys.stderr)
            continue
        stages = analyse(data, path, 0, a.dump_dir)
        row = summarise(path, stages)
        rows.append(row)
        if jf:
            jf.write(json.dumps({"file": path, "summary": row, "stages": stages}) + "\n")
        print(f"{row['status']:<13} {row['sha256'][:12]}  {row['stages']:<45} c2={row['c2_count']} wallets={row['wallets']}")
    if jf:
        jf.close()
    if a.csv and rows:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

    tried = [r for r in rows if r["status"] != "not_supported"]
    ok = sum(r["status"] == "ok" for r in tried)
    print(f"\n{ok}/{len(tried)} supported samples extracted ({len(rows) - len(tried)} files not recognised)")


if __name__ == "__main__":
    main()

# Lumma Stealer: two delivery chains, one config scheme

Static unpackers, config extractors, YARA rules and IOCs from my analysis of two Lumma Stealer delivery chains: a **Go loader** and a **C++ crypter hidden in a fake "AIO Checker" tool**. The two loaders share nothing. The Lumma payloads they deliver store their C2 table the same way, so **one extractor handles both**, from the file on disk or from a memory dump of the hollowed process.

| Write-up | Chain |
|---|---|
| [Lumma GO loader](https://artfuldodger10.github.io/posts/Lumma-GO-Analysis/) | Go loader → Lumma hollowed into `SysWOW64\explorer.exe` |
| [Lumma C++ crypter (AIO Checker)](https://artfuldodger10.github.io/posts/Lumma-crypter-Analysis/) | RAR lure → RC4 crypter → dropper → .NET clipper + second crypter → Lumma in `MSBuild.exe` |

## The two chains

```
GO chain
  Go loader (x64, a78c020b…)
    payload stored in .rdata, reversed and shifted ±0x43
    └─ Lumma (x86, 7c9d4d29…) hollowed into C:\Windows\SysWOW64\explorer.exe

AIO chain
  AIO Checker 8.10.10.rar
    └─ outer crypter (x64, 70ed4132…)       RC4 .jss section → hollows MSBuild.exe
        └─ dropper (x86, eed45ed3…)          RC4 blobs in .cSs → %APPDATA%\<10 chars>.exe x2
            ├─ .NET clipper (ed6731c5…)       13 wallets, Startup\svhost.exe
            └─ second crypter (x64, 1321e9fa…) same build as the outer one → hollows MSBuild.exe
                └─ Lumma (x86, 7584e49b…)
```

## What both Lumma builds share

| | GO build | AIO build |
|---|---|---|
| C2 table | ChaCha20 (original, 8-byte nonce) | ChaCha20 (original, 8-byte nonce) |
| Layout | key (32) \| nonce (8) \| 10 slots × 0x80 | key (32) \| nonce (8) \| 10 slots × 0x80 |
| Keystream | one stream from counter 0, slot *i* = counter 2*i* | same |
| Slot 0 | not a C2 | not a C2 |
| C2s | 9 | 9 entries, 8 unique |
| Build ID (`uid`) | 56 hex chars | 32 hex chars |
| Dead drop | Steam profile | Steam profile |

The key and nonce are found through the code that copies them into the cipher state. The two builds order those instructions differently, and the extractor matches both.

## Contents

| Path | What it is |
|---|---|
| `tools/go_loader.py` | Pulls the Lumma payload out of the Go loader |
| `tools/aio_crypter.py` | Unwraps the AIO chain: outer crypter → dropper → clipper + second crypter → Lumma |
| `tools/lumma_config.py` | C2 config extractor for both Lumma builds: file, Go loader, or memory dump |
| `tools/clipper_config.py` | Wallets and mutex from the .NET clipper's user-string heap |
| `tools/api_hashes.py` | Resolves both API-hash schemes (FNV-1a and the MurmurHash2 variant) against a DLL |
| `tools/pipeline.py` | Runs everything over a folder of samples and writes a JSONL + CSV summary |
| `tools/crypto.py`, `tools/pe.py` | Shared ChaCha20, RC4, hash routines and a small PE reader |
| `detections/yara/` | Go loader, GO payload, AIO crypter, clipper, AIO payload, and a memory rule for both payloads |
| `iocs/iocs.csv` | Hashes, C2s, dead drops, build IDs, host artifacts, clipper wallets |
| `attack/` | ATT&CK techniques per chain |

## Usage

Plain Python 3, no dependencies. Run in an isolated VM. The tools only read files; nothing is executed.

```bash
cd tools

# GO chain
python go_loader.py loader.exe -o payload.bin
python lumma_config.py payload.bin --defang          # or straight from loader.exe

# AIO chain: every stage from the outer crypter
python aio_crypter.py "AIO Checker 8.10.10.exe" -o stages/
python lumma_config.py stages/lumma_7584e49b7ad4.bin --defang
python clipper_config.py stages/clipper_ed6731c5d5de.bin

# memory dump of the hollowed process (Volatility VAD dump)
python lumma_config.py pid.1234.vad.0x400000-0x451fff.dmp --layout mapped

# many samples at once
python pipeline.py samples/ --jsonl results.jsonl --csv results.csv --dump-dir stages/
```

Example output (GO payload, trimmed):

```json
{
  "chacha20_key": "972ce069e3b6756f6de83a46dd2cbb35a0a4d4d5280966145020d6924e31e1da",
  "chacha20_nonce": "cd1fbfdb5c98bb36",
  "slots": [
    {"slot": 0, "c2": null, "counter": 0},
    {"slot": 1, "c2": "convuey[.]cyou", "counter": 2},
    ...
    {"slot": 9, "c2": "vicareu[.]su/bcdf", "counter": 18}
  ],
  "uid": "dc8e5f3081889c0e241b9a0281076771effc3817c5b1cd4ddb43b54f",
  "cid": ""
}
```

Slots are numbered from the start of the table, so slot 1 is the first C2. The GO post numbers the C2s from 0.

## Limitations

- Validated on the two chains above. A run across more campaign samples is in progress, with success rates to be published here.
- The Steam dead-drop URL is a stack string decoded by a per-string routine, so the extractor doesn't output it. Both URLs are in `iocs/iocs.csv`.
- A new crypter build with a different RC4 key needs `aio_crypter.py --key <hex>`. The dropper falls back to scanning `.cSs` if its blob offsets change.
- Memory dumps need the PE header in the dumped region. If the image was relocated, the extractor tries each 64 KB-aligned base, or takes `--base`.

## Note

No samples are stored here. All hashes are on VirusTotal / MalwareBazaar. Network IOCs are raw in `iocs/iocs.csv` and defanged everywhere else.

MIT License

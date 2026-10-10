# lumma_go

Static tools for the GO campaign. Plain Python 3, no dependencies.

| Script | What it does |
|---|---|
| `unpack_stage1.py` | Pulls the Lumma payload out of the Go loader without running it |
| `extract_config.py` | Prints the config (uid, cid, ChaCha20 key and nonce, C2 list) from the payload or straight from the loader |
| `lumma_crypto.py` | ChaCha20 decrypt, ROT15 for the Steam display name, FNV-1a API hash |

## Usage

```bash
python unpack_stage1.py loader.exe -o payload.bin
python extract_config.py payload.bin --defang
python lumma_crypto.py rot15 "<steam display name>"
python lumma_crypto.py fnv1a WinHttpOpen
```

Example output on the known payload:

```json
{
  "uid": "dc8e5f3081889c0e241b9a0281076771effc3817c5b1cd4ddb43b54f",
  "cid": "",
  "chacha20_key": "972ce069e3b6756f6de83a46dd2cbb35a0a4d4d5280966145020d6924e31e1da",
  "chacha20_nonce": "cd1fbfdb5c98bb36",
  "c2": [
    {"slot": 0, "c2": "convuey[.]cyou", "counter": 2},
    {"slot": 1, "c2": "bendavo[.]su/asdsa", "counter": 4},
    ...
    {"slot": 8, "c2": "vicareu[.]su/bcdf", "counter": 18}
  ],
  "dead_drop": "hxxps://steamcommunity[.]com/profiles/76561199880317058"
}
```

The ChaCha20 block counter isn't reset between calls, so each C2 entry decrypts at a different counter (2 + 2 × slot in this build). The extractor tries that first and falls back to scanning counters 0–127.

The Steam dead drop is a stack string, so the extractor only prints it for the known sample.

## Tests

```bash
python -m unittest discover -s tests -v
```

The sample tests are skipped unless you point them at the files (in an isolated VM):

```bash
LUMMA_GO_STAGE1=loader.exe LUMMA_GO_STAGE2=payload.bin python -m unittest discover -s tests -v
```

## Tested samples

| Stage | SHA256 |
|---|---|
| Loader | `a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805` |
| Payload | `7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df` |

Only one sample so far. More from the campaign will be added.

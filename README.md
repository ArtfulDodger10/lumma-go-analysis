# Lumma GO Campaign Analysis

Unpacker, config extractor, YARA rules and IOCs from my analysis of a Lumma Stealer chain delivered by a loader written in Go. The loader carries the payload inside itself, decodes it in memory and hollows a 32-bit `explorer.exe`.

Report: [Lumma GO campaign](https://artfuldodger10.github.io/posts/Lumma-GO-Analysis/)

## Contents

| Path | What it is |
|---|---|
| `tools/lumma_go/` | Static unpacker for the Go loader, config extractor, crypto helpers |
| `detections/lumma_go.yar` | Two YARA rules: the Go loader and the Lumma payload |
| `iocs/iocs.csv` | Hashes, C2s, dead drop, uid |
| `attack/` | ATT&CK techniques with the evidence for each |
| `reports/` | Link to the full write-up |

## Key findings

**Loader.** A 64-bit Go 1.25.2 binary with its symbols intact (`main._RunPE`, `main.LoadFile`, `main.Decode`) and every function padded with junk code. The payload is a 334,344-byte blob in `.rdata`. It's rebuilt on the stack, reversed, and then 0x43 is subtracted from even bytes and added to odd ones. That's encoding, not encryption, so the payload can be pulled out statically.

**Injection.** `SysWOW64\explorer.exe` is created suspended, the payload goes into one RWX region, the PEB image base and thread context are updated with the WOW64 APIs, and the thread is resumed. The injection APIs come from Go `LazyProc` names, not imports, so import-based tools like capa don't see the hollowing.

**Payload.** 32-bit Lumma with around 337 per-string decoders (MBA expressions), FNV-1a API hashing with a custom seed `0x69BBE5D1`, and direct system calls through the WOW64 gate, which is why it dies under a debugger even with ScyllaHide.

**Config.** 9 C2 servers encrypted with ChaCha20 (key and nonce stored in the binary), plus a Steam profile as a fallback, where the C2 is the display name shifted with ROT15. The cipher keeps its block counter between calls, so the entries decrypt at counters 2, 4, 6 … 18, not 0. The values match the any.run config extraction for the same sample.

**C2.** HTTPS POST over WinHTTP with a Chrome 109 User-Agent. A multipart upload sends `uid`, `pid`, `hwid` and the encrypted data, and a check-in sends `uid=…&cid=&hwid=…`.

**Anti-analysis.** Exits if the UI language is Russian (0x0419). Checks the CPUID hypervisor vendor for KVM, QEMU, VMware, VirtualBox and Xen, but that check didn't stop it in a VMware VM.

**Stealing.** The code targets Chromium and Firefox data (including Chrome app-bound keys), wallets, Outlook, Windows Mail, Thunderbird, Steam, Discord and Notepad++. With a fake C2 it only went after Mail, Thunderbird, Notepad++ and Discord; browsers and wallets weren't touched.

## Infection chain

```
Stage 1: Go loader (a78c020b...6805, x64)
  decode embedded blob (reverse, -/+0x43)
    Stage 2: Lumma (7c9d4d29...46df, x86) hollowed into C:\Windows\SysWOW64\explorer.exe
      C2: 9 HTTPS servers, then Steam profile dead drop
```

## Usage

```bash
cd tools/lumma_go
python unpack_stage1.py loader.exe -o payload.bin
python extract_config.py payload.bin --defang
```

## Detection results

Scanned with `yara64` against both stages and `C:\Windows\System32`.

| Rule | Hits | System32 |
|---|---|---|
| Lumma_GO_Loader | 1/1 (loader) | 0 hits |
| Lumma_GO_Payload | 1/1 (payload) | 0 hits |

Only one sample of each stage so far. To scan a running `explorer.exe`, remove the `uint16(0) == 0x5A4D` check from the payload rule, since the injected image isn't at the start of the memory region.

## Note

No live samples are stored here. Both hashes are on VirusTotal, so the samples can be pulled into an isolated lab from there.

MIT License

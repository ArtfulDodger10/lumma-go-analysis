# ATT&CK mapping

"Seen" = observed in the lab run. "Code" = present in the sample but not seen running.

| Tactic | Technique | GO chain | AIO chain |
|---|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | n/a (vector unknown) | Lure archive "AIO Checker" (inferred) |
| Execution | T1047 Windows Management Instrumentation | WMI for GPU, BIOS, AV | n/a |
| Execution | T1106 Native API | Direct syscalls through the WOW64 gate | Direct syscall stub (inferred) |
| Persistence | T1547.001 Startup Folder | None found | Clipper copies itself to `Startup\svhost.exe` (seen) |
| Defense Evasion | T1055.012 Process Hollowing | `SysWOW64\explorer.exe` | `MSBuild.exe`, twice |
| Defense Evasion | T1027 Obfuscated Files or Information | Payload reversed and shifted ±0x43; per-string decoders | RC4-encrypted `.jss` section and dropper blobs; stack strings, flattening |
| Defense Evasion | T1027.007 Dynamic API Resolution | FNV-1a, basis 0x69BBE5D1; Go LazyProc | MurmurHash2 variant, seeds 707 / 565 |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | Loader decodes the payload in memory | Crypters decrypt the next stage in memory |
| Defense Evasion | T1036.005 Masquerading | n/a | `mobsync.exe` version info, `svhost.exe`, `Runtime64.exe` |
| Defense Evasion | T1497.001 System Checks | CPUID hypervisor vendor (code) | CPUID hypervisor vendor (code) |
| Discovery | T1614.001 System Language Discovery | Exits on Russian UI language | n/a |
| Discovery | T1082 System Information Discovery | Host profile (Info.txt) | Host profile (System.txt, code) |
| Discovery | T1518.001 Security Software Discovery | WMI SecurityCenter2 | n/a |
| Collection | T1115 Clipboard Data | Code | Clipper swaps wallet addresses (seen) |
| Collection | T1113 Screen Capture | Code (likely) | Code |
| Collection | T1114.001 Local Email Collection | Mail and Thunderbird probed (seen) | Outlook, Windows Mail (code) |
| Credential Access | T1555.003 Credentials from Web Browsers | Code | Code |
| Credential Access | T1539 Steal Web Session Cookie | Code (likely, task-driven) | n/a |
| Command and Control | T1071.001 Web Protocols | HTTPS POST over WinHTTP (seen) | HTTPS POST (seen) |
| Command and Control | T1102.001 Dead Drop Resolver | Steam profile, ROT15 display name (code) | Steam profile (inferred) |
| Command and Control | T1008 Fallback Channels | 9 C2 slots, then Steam (code) | 9 C2 slots (code) |
| Command and Control | T1105 Ingress Tool Transfer | Drop and run .exe/.dll/.ps1 (code) | n/a |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Multipart upload (seen) | Multipart upload (seen) |

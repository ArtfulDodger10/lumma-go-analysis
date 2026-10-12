# ATT&CK mapping

Same mapping as the two posts. "Seen" = observed in the lab run. "Code" = present in the sample but not seen running.

| Tactic | Technique | GO chain | AIO chain |
|---|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | n/a (vector not determined) | Victim runs `AIO Checker 8.10.10.exe` (inferred) |
| Execution | T1047 Windows Management Instrumentation | WMI queries (GPU, BIOS, AV) | n/a |
| Execution | T1106 Native API | Heaven's Gate stub (code) | n/a |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | n/a (none observed) | Clipper copies itself to `Startup\svhost.exe` (seen) |
| Defense Evasion | T1055.012 Process Hollowing | Stage 1 → SysWOW64 `explorer.exe` | Both crypters → 32-bit `MSBuild.exe` |
| Defense Evasion | T1036 Masquerading | n/a | Version info cloned from `mobsync.exe` |
| Defense Evasion | T1036.005 Match Legitimate Name or Location | n/a | `svhost.exe` in Startup (seen) |
| Defense Evasion | T1027 Obfuscated Files or Information | ±0x43 payload encoding; per-string MBA decoders; ChaCha20 config | RC4-encrypted stages, control-flow flattening, stack strings |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | Loader decodes the payload in memory | RC4 (crypter, dropper), ChaCha20 (C2 list) |
| Defense Evasion | T1027.007 Dynamic API Resolution | FNV-1a export hashing; Go `LazyProc` names | Modified MurmurHash2, seeds 707 / 565 |
| Defense Evasion | T1497.001 System Checks | CPUID hypervisor vendor check (code) | CPUID hypervisor vendor check (code) |
| Discovery | T1614.001 System Language Discovery | Exits on Russian UI language | n/a |
| Discovery | T1082 System Information Discovery | `Info.txt` | `System.txt`, WMI `Win32_BIOS` (code) |
| Discovery | T1518.001 Security Software Discovery | WMI `SecurityCenter2` | n/a |
| Collection | T1114.001 Local Email Collection | Windows Mail / Thunderbird / Outlook targets | n/a |
| Collection | T1115 Clipboard Data | Imports (likely) | Clipper read and replace (seen); Lumma clipboard read (code) |
| Collection | T1113 Screen Capture | Imports (likely) | Lumma GDI capture code |
| Credential Access | T1555.003 Credentials from Web Browsers | Code (task-driven, not observed) | `Login Data`, `Web Data` (code) |
| Credential Access | T1539 Steal Web Session Cookie | Code (task-driven, not observed) | n/a |
| Command and Control | T1071.001 Web Protocols | HTTPS POST (seen) | HTTPS POST to `/xane` (seen) |
| Command and Control | T1102.001 Dead Drop Resolver | Steam profile (code) | Steam profile URL next to the C2 list (use inferred) |
| Command and Control | T1008 Fallback Channels | 9-slot failover (code) | n/a |
| Command and Control | T1105 Ingress Tool Transfer | `%TEMP%` drop + execute (code) | n/a |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Multipart `file` upload (seen) | Multipart upload (seen) |

ATT&CK techniques for the GO campaign. "In code" means the capability is in the sample but wasn't seen running in the lab.

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1055.012 Process Hollowing | Loader starts SysWOW64\explorer.exe suspended and writes the payload into it |
| Defense Evasion | T1027 Obfuscated Files or Information | Payload stored reversed and shifted by ±0x43; per-string decoders; ChaCha20 C2 table |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | Loader decodes the payload in memory |
| Defense Evasion | T1027.007 Dynamic API Resolution | FNV-1a export hashing (seed 0x69BBE5D1); Go LazyProc in the loader |
| Defense Evasion | T1497.001 System Checks | CPUID hypervisor vendor check (in code; didn't stop it in a VM) |
| Discovery | T1614.001 System Language Discovery | Exits on Russian UI language (0x0419) |
| Discovery | T1082 System Information Discovery | Info.txt: CPU, RAM, GPU, screen, user, BIOS |
| Discovery | T1518.001 Security Software Discovery | WMI root\SecurityCenter2 |
| Execution | T1047 Windows Management Instrumentation | WMI queries for GPU, BIOS, AV |
| Execution | T1106 Native API | Direct system calls through the WOW64 gate |
| Collection | T1114.001 Local Email Collection | Windows Mail and Thunderbird paths probed at run time; Outlook in code |
| Collection | T1115 Clipboard Data | Clipboard imports |
| Collection | T1113 Screen Capture | GDI imports |
| Credential Access | T1555.003 Credentials from Web Browsers | In code (Chromium, Firefox) |
| Credential Access | T1539 Steal Web Session Cookie | In code |
| Command and Control | T1071.001 Web Protocols | HTTPS POST over WinHTTP |
| Command and Control | T1102.001 Dead Drop Resolver | Steam profile display name (in code) |
| Command and Control | T1008 Fallback Channels | 9 C2 slots, then Steam (in code) |
| Command and Control | T1105 Ingress Tool Transfer | Drop and run .exe/.dll/.ps1 from %TEMP% (in code) |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Multipart upload of the collected data |

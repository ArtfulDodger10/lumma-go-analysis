
rule Lumma_GO_Loader : loader go
{
    meta:
        description = "Go loader that rebuilds an embedded PE on the stack, decodes it and hollows SysWOW64\\explorer.exe"
        author      = "Artful Dodger"
        date        = "2026-10-10"
        hash        = "a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805"
        status      = "TESTED"

    strings:
        // mov rdx, imm64 / mov [rsp+X], rdx / lea rdi, [rsp+Y] / lea rsi, blob / mov ecx, count / rep movsq
        $blob_builder = { 48 BA ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 ?? 48 8D 7C 24 ?? 48 8D 35 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 48 A5 }

        // Go symbol names kept in the binary (not stripped)
        $go1 = "main._RunPE" ascii
        $go2 = "main.RedirectToPayload" ascii
        $go3 = "main.GetImgBasePebOffset" ascii
        $go4 = "main.Wow64Set_ThreadContext" ascii
        $go5 = "main.SectionsRawToVirtual" ascii
        $go6 = "main._LoadPEModule" ascii

        // APIs reached 
        $api1 = "Wow64SetThreadContext" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "ResumeThread" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (
            ($blob_builder and 2 of ($go*)) or
            (4 of ($go*) and all of ($api*))
        )
}

rule Lumma_GO_Payload : stealer lumma
{
    meta:
        description = "Lumma Stealer payload: ChaCha20 C2-table setup, C2 slot selection and FNV-1a (seed 0x69BBE5D1) API-hash pushes"
        author      = "Artful Dodger"
        date        = "2026-10-10"
        hash        = "7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df"
        status      = "TESTED"

    strings:
        // ChaCha20 context init: mov eax, key / mov edi, ctx+0x10 / mov ecx, 8 / xchg / rep movsd / xchg / mov eax, nonce
        $chacha_init = { B8 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 08 00 00 00 96 F3 A5 96 B8 }

        // slot = byte ^ 0xF6 ; cmp 8 ; ja   (9 C2 slots, then Steam dead drop)
        $slot_select = { 0F B6 05 ?? ?? ?? ?? 34 F6 3C 08 77 }
        // shl ecx, 7 ; lea ecx, [ecx + table]   (128-byte encrypted C2 entries)
        $slot_lea    = { C1 E1 07 8D 89 }

        
        $h_settimeouts = { 68 CF BD 43 CF }   // WinHttpSetTimeouts
        $h_writedata   = { 68 AC 79 84 A7 }   // WinHttpWriteData
        $h_addheaders  = { 68 B9 1B BD 58 }   // WinHttpAddRequestHeaders

        // stack constants
        $k_uilang  = { 15 66 ED 8C }          // hash of GetUserDefaultUILanguage 
        $k_fnvseed = { 38 D5 20 53 }          // encoded FNV-1a seed (decodes to 0x69BBE5D1)

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        (
            ($chacha_init and $slot_select and $slot_lea) or
            (2 of ($h_*) and 1 of ($k_*) and ($chacha_init or $slot_select))
        )
}


rule Lumma_GO_Loader
{
    meta:
        description = "Go loader that decodes an embedded Lumma payload and hollows SysWOW64\\explorer.exe"
        author = "Artful Dodger"
        date = "2026-10-10"
        hash = "a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805"

    strings:
        // builds the payload on the stack: mov rdx, imm64 ... rep movsq
        $blob = { 48 BA ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 ?? 48 8D 7C 24 ?? 48 8D 35 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 48 A5 }

        $go1 = "main._RunPE" ascii
        $go2 = "main.RedirectToPayload" ascii
        $go3 = "main.GetImgBasePebOffset" ascii
        $go4 = "main.Wow64Set_ThreadContext" ascii
        $go5 = "main.SectionsRawToVirtual" ascii
        $go6 = "main._LoadPEModule" ascii

        $api1 = "Wow64SetThreadContext" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "ResumeThread" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (($blob and 2 of ($go*)) or (4 of ($go*) and all of ($api*)))
}

rule Lumma_GO_Payload
{
    meta:
        description = "Lumma payload from the GO campaign: ChaCha20 C2 table and FNV-1a API hashing"
        author = "Artful Dodger"
        date = "2026-10-10"
        hash = "7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df"

    strings:
        $chacha_init = { B8 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 08 00 00 00 96 F3 A5 96 B8 }
        $slot_select = { 0F B6 05 ?? ?? ?? ?? 34 F6 3C 08 77 }
        $slot_lea = { C1 E1 07 8D 89 }

        // WinHttpSetTimeouts, WinHttpWriteData, WinHttpAddRequestHeaders
        $h1 = { 68 CF BD 43 CF }
        $h2 = { 68 AC 79 84 A7 }
        $h3 = { 68 B9 1B BD 58 }

        // GetUserDefaultUILanguage hash, encoded FNV seed
        $k1 = { 15 66 ED 8C }
        $k2 = { 38 D5 20 53 }

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        (($chacha_init and $slot_select and $slot_lea) or
         (2 of ($h*) and 1 of ($k*) and ($chacha_init or $slot_select)))
}

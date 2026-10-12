import "pe"

rule AIOChecker_Crypter_x64_jss
{
    meta:
        description = "x64 crypter from the AIO Checker chain: two .jss sections, mobsync.exe version info clone, RC4 key built as stack immediate"
        author      = "Artful Dodger"
        date        = "2026-10-07"
        hash1       = "70ed41327068060f68a7272cc705ba1eecfa11430e308023eb82d7964f42ed1d"
        hash2       = "1321e9fa6893b6fd3137f01b77b54eee6bd39144813d06e6f92bf8c58f3a3008"

    strings:
        // low 8 bytes of the 10-byte RC4 key, as the imm64 of the stack build at 0x14000D6E7
        $rc4_key_imm = { 92 54 67 56 42 11 36 4D }

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        for 2 i in (0 .. pe.number_of_sections - 1) : ( pe.sections[i].name == ".jss" ) and
        (
            $rc4_key_imm or
            (
                pe.version_info["OriginalFilename"] == "mobsync.exe" and
                pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0x2628 and
                pe.number_of_signatures == 0
            )
        )
}

rule AIOChecker_ShinobuClipper_variant
{
    meta:
        description = ".NET crypto clipper built from a 'ShinobuClipper-master' project (Runtime64.exe, Startup\\svhost.exe)"
        author      = "Artful Dodger"
        date        = "2026-10-07"
        hash1       = "ed6731c5d5de872e56816984faf9bb056e4d3e3282862f2f626d2df75b38d6da"

    strings:
        $pdb    = "ShinobuClipper-master" ascii
        $pdb2   = "Runtime64.pdb" ascii
        $m1     = "attribute_hidden" ascii
        $m2     = "attribute_system" ascii
        $m3     = "autorun_name" ascii
        $m4     = "startup_directory" ascii
        $odd    = "sodfksdkfalksdasgpkprgasdgrrkgwhrterheegwsdfwef" ascii wide
        $wallet = "1Cs4gSW7qZiZnmUtYAJY6SNNL9RkGvqxk5" wide

    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and
        // .NET check via the CLR (COM descriptor) directory; avoids the 1-argument pe.imports() form
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
        ( $pdb or $odd or $wallet or ($pdb2 and 2 of ($m*)) or all of ($m*) )
}

rule AIOChecker_Lumma_build_37d7c3a0
{
    meta:
        description = "Lumma Stealer payload from the AIO Checker chain (this build only): plaintext uid and ChaCha20 key+nonce of the C2 table"
        author      = "Artful Dodger"
        date        = "2026-10-07"
        hash1       = "7584e49b7ad4e44f405dc64a391abe2f619253b2396d357b9ed7c4ffc867ada9"

    strings:
        $uid       = "37d7c3a0bc391b79b770bb89c2e2e1a3" ascii
        // key @0x450238 (32 B) immediately followed by nonce @0x450258 (8 B)
        $key_nonce = { 51 C6 7B C3 9E D4 76 74 A8 7A A1 BC DA 25 4E 39
                       20 93 46 3C 3E A9 5C E6 16 E4 5E 2A F7 46 01 5D
                       E2 AF CF C4 B7 A7 1E 71 }

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        ( $uid or $key_nonce )
}

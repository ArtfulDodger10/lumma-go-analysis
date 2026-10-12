rule Lumma_Campaign_Payload_Memory
{
    meta:
        description = "Lumma payload of both chains (GO and AIO) in memory: the code that copies the ChaCha20 key and nonce of the C2 table. No MZ check, for Volatility yarascan / vadyarascan over hollowed explorer.exe or MSBuild.exe"
        author = "Artful Dodger"
        date = "2026-10-12"
        hash1 = "7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df"
        hash2 = "7584e49b7ad4e44f405dc64a391abe2f619253b2396d357b9ed7c4ffc867ada9"

    strings:
        // GO build:  mov eax, key ; mov edi, dst ; mov ecx, 8 ; xchg ; rep movsd ; xchg ; mov eax, nonce
        $copy_go  = { B8 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 08 00 00 00 96 F3 A5 96 B8 }
        // AIO build: mov eax, key ; mov ecx, 8 ; mov edi, dst ; xchg ; rep movsd ; xchg ; mov eax, nonce
        $copy_aio = { B8 ?? ?? ?? ?? B9 08 00 00 00 BF ?? ?? ?? ?? 96 F3 A5 96 B8 }
        // ChaCha20 constant 0x61707865 ("expa"), as a string or as an immediate
        $chacha   = { 65 78 70 61 }
        $uid_go   = "dc8e5f3081889c0e241b9a0281076771effc3817c5b1cd4ddb43b54f" ascii
        $uid_aio  = "37d7c3a0bc391b79b770bb89c2e2e1a3" ascii

    condition:
        ($copy_go or $copy_aio) and ($chacha or $uid_go or $uid_aio)
}

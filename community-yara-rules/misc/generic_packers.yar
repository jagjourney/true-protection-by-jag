/*
    True Protection by Jag - Generic Packer Detection Rules
    Detects common executable packers used to obfuscate malware.
*/

import "pe"

rule TPJ_Packer_UPX
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects executables packed with UPX (Ultimate Packer for eXecutables)"
        severity    = "medium"
        category    = "packer"
        created     = "2026-03-27"
        reference   = "https://upx.github.io/"

    strings:
        $upx_magic    = "UPX!" ascii
        $upx_section0 = "UPX0" ascii
        $upx_section1 = "UPX1" ascii
        $upx_section2 = "UPX2" ascii
        $upx_header   = { 55 50 58 21 0D 0A 1A 0A }

    condition:
        uint16(0) == 0x5A4D and
        (
            ($upx_magic and ($upx_section0 or $upx_section1)) or
            $upx_header or
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == "UPX0" or
                    pe.sections[i].name == "UPX1"
                )
            )
        )
}

rule TPJ_Packer_ASPack
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects executables packed with ASPack"
        severity    = "medium"
        category    = "packer"
        created     = "2026-03-27"
        reference   = "http://www.aspack.com/"

    strings:
        $aspack_section = ".aspack" ascii
        $adata_section  = ".adata" ascii
        // ASPack v2.12 entry point signature
        $aspack_ep_212 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB }
        // ASPack v2.24+ entry point signature
        $aspack_ep_224 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }

    condition:
        uint16(0) == 0x5A4D and
        (
            ($aspack_section and $adata_section) or
            $aspack_ep_212 at pe.entry_point or
            $aspack_ep_224 at pe.entry_point or
            for any i in (0..pe.number_of_sections - 1) : (
                pe.sections[i].name == ".aspack"
            )
        )
}

rule TPJ_Packer_Themida
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects executables protected with Themida/WinLicense"
        severity    = "high"
        category    = "packer"
        created     = "2026-03-27"
        reference   = "https://www.oreans.com/Themida.php"

    strings:
        $themida_section1 = ".Themida" ascii
        $themida_section2 = ".Winlice" ascii
        $themida_section3 = "WinLicen" ascii
        // Themida VM entry stub
        $themida_vm = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B }
        // Oreans signature
        $oreans_str = "Oreans Technologies" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $themida_section1 or
            $themida_section2 or
            $themida_section3 or
            $oreans_str or
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == ".Themida" or
                    pe.sections[i].name == ".Winlice"
                )
            )
        )
}

rule TPJ_Packer_VMProtect
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects executables protected with VMProtect"
        severity    = "high"
        category    = "packer"
        created     = "2026-03-27"
        reference   = "https://vmpsoft.com/"

    strings:
        $vmp_section0 = ".vmp0" ascii
        $vmp_section1 = ".vmp1" ascii
        $vmp_section2 = ".vmp2" ascii
        // VMProtect stub patterns
        $vmp_push_pattern = { 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 00 00 00 00 00 }
        $vmp_signature    = "VMProtect" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $vmp_section0 or
            $vmp_section1 or
            $vmp_section2 or
            $vmp_signature or
            (
                for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == ".vmp0" or
                    pe.sections[i].name == ".vmp1" or
                    pe.sections[i].name == ".vmp2"
                )
            )
        )
}

rule TPJ_Packer_PECompact
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects executables packed with PECompact"
        severity    = "medium"
        category    = "packer"
        created     = "2026-03-27"

    strings:
        $pec_section1 = "PEC2" ascii
        $pec_section2 = "pec1" ascii
        $pec_section3 = "pec2" ascii
        $pec_signature = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 }

    condition:
        uint16(0) == 0x5A4D and
        (
            $pec_section1 or $pec_section2 or $pec_section3 or
            $pec_signature at pe.entry_point or
            for any i in (0..pe.number_of_sections - 1) : (
                pe.sections[i].name == "PEC2" or
                pe.sections[i].name == "pec2"
            )
        )
}

rule TPJ_Packer_MPRESS
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects executables packed with MPRESS"
        severity    = "medium"
        category    = "packer"
        created     = "2026-03-27"

    strings:
        $mpress_section1 = ".MPRESS1" ascii
        $mpress_section2 = ".MPRESS2" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            $mpress_section1 or
            $mpress_section2 or
            for any i in (0..pe.number_of_sections - 1) : (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2"
            )
        )
}

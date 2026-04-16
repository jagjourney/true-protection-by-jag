/*
    True Protection by Jag - Suspicious PE Characteristics
    Detects PE files with anomalous or suspicious structural properties.
*/

import "pe"
import "math"

rule TPJ_Suspicious_PE_NoImports
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file with no import table -- may indicate packing or shellcode loader"
        severity    = "medium"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_imports == 0 and
        filesize > 4KB
}

rule TPJ_Suspicious_PE_FewImports
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file with suspiciously few imports (1-3), common in packed or loader malware"
        severity    = "low"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_imports > 0 and
        pe.number_of_imports <= 3 and
        filesize > 10KB
}

rule TPJ_Suspicious_PE_SectionNames
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file with suspicious or nonstandard section names"
        severity    = "medium"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".evil" or
            pe.sections[i].name == ".mal" or
            pe.sections[i].name == ".hide" or
            pe.sections[i].name == ".pack" or
            pe.sections[i].name == ".crypt" or
            pe.sections[i].name == ".stub" or
            pe.sections[i].name == ".boom" or
            pe.sections[i].name == "" or
            pe.sections[i].name matches /^[\x00-\x1f]/
        )
}

rule TPJ_Suspicious_PE_HighEntropy
{
    meta:
        author      = "True Protection by Jag"
        description = "PE section with very high entropy (>7.2), indicating encryption or compression"
        severity    = "medium"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2 and
            pe.sections[i].raw_data_size > 1024
        )
}

rule TPJ_Suspicious_PE_ExecutableWritableSection
{
    meta:
        author      = "True Protection by Jag"
        description = "PE section that is both writable and executable -- common in self-modifying malware"
        severity    = "medium"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            (pe.sections[i].characteristics & 0x20000000) != 0 and  // IMAGE_SCN_MEM_EXECUTE
            (pe.sections[i].characteristics & 0x80000000) != 0 and  // IMAGE_SCN_MEM_WRITE
            pe.sections[i].name != ".text"
        )
}

rule TPJ_Suspicious_PE_InvalidTimestamp
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file with timestamp in the future or set to zero/epoch"
        severity    = "low"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        (
            pe.timestamp == 0 or
            pe.timestamp > 1900000000  // Far future
        )
}

rule TPJ_Suspicious_PE_ResourceAnomaly
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file where resources make up over 80% of the file -- may contain embedded payloads"
        severity    = "medium"
        category    = "suspicious"
        created     = "2026-03-27"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".rsrc" and
            pe.sections[i].raw_data_size > (filesize * 80 / 100) and
            filesize > 50KB
        )
}

rule TPJ_Suspicious_PE_DoubleExtension
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file containing double-extension strings used for social engineering"
        severity    = "high"
        category    = "suspicious"
        created     = "2026-03-27"

    strings:
        $dblext1 = ".pdf.exe" ascii wide nocase
        $dblext2 = ".doc.exe" ascii wide nocase
        $dblext3 = ".jpg.exe" ascii wide nocase
        $dblext4 = ".png.exe" ascii wide nocase
        $dblext5 = ".txt.exe" ascii wide nocase
        $dblext6 = ".xlsx.exe" ascii wide nocase
        $dblext7 = ".mp3.exe" ascii wide nocase
        $dblext8 = ".mp4.scr" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        any of ($dblext*)
}

rule TPJ_Suspicious_PE_AntiDebug
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file importing anti-debugging APIs"
        severity    = "medium"
        category    = "suspicious"
        created     = "2026-03-27"

    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugStringA" ascii
        $api5 = "GetTickCount" ascii
        $api6 = "QueryPerformanceCounter" ascii
        $int2d = { CD 2D }  // INT 2D anti-debug
        $int3  = { CC }     // INT 3 breakpoint

    condition:
        uint16(0) == 0x5A4D and
        (
            3 of ($api*) or
            ($int2d and 2 of ($api*))
        )
}

rule TPJ_Suspicious_PE_SelfDeletion
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file containing self-deletion command patterns"
        severity    = "high"
        category    = "suspicious"
        created     = "2026-03-27"

    strings:
        $del1 = "cmd /c del" ascii wide nocase
        $del2 = "cmd.exe /c del" ascii wide nocase
        $del3 = "/c ping 127.0.0.1" ascii wide nocase
        $del4 = "MoveFileEx" ascii
        $del5 = "MOVEFILE_DELAY_UNTIL_REBOOT" ascii
        $del6 = "DeleteFileA" ascii
        $del7 = "DeleteFileW" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($del1 or $del2) and ($del3) or
            ($del4 and $del5)
        )
}

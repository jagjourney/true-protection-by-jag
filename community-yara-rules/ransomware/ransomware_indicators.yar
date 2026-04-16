/*
    True Protection by Jag - Ransomware Indicator Rules
    Detects ransomware behaviors, ransom notes, and encrypted file indicators.
*/

import "pe"

rule TPJ_Ransomware_RansomNote_Filenames
{
    meta:
        author      = "True Protection by Jag"
        description = "Contains strings matching common ransom note filenames"
        severity    = "critical"
        category    = "ransomware"
        created     = "2026-03-27"

    strings:
        // Common ransom note filenames
        $note1  = "README_TO_DECRYPT" ascii wide nocase
        $note2  = "HOW_TO_DECRYPT" ascii wide nocase
        $note3  = "HOW_TO_RECOVER" ascii wide nocase
        $note4  = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $note5  = "RECOVERY_INSTRUCTIONS" ascii wide nocase
        $note6  = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $note7  = "HELP_DECRYPT" ascii wide nocase
        $note8  = "RANSOM_NOTE" ascii wide nocase
        $note9  = "_readme.txt" ascii wide nocase
        $note10 = "RESTORE_FILES" ascii wide nocase
        $note11 = "!!! READ ME !!!" ascii wide nocase
        $note12 = "ATTENTION!!!" ascii wide nocase
        $note13 = "DECRYPT_YOUR_FILES" ascii wide nocase
        $note14 = "FILES_ENCRYPTED" ascii wide nocase
        $note15 = "RECOVER_YOUR_DATA" ascii wide nocase

    condition:
        2 of ($note*)
}

rule TPJ_Ransomware_FileExtensions
{
    meta:
        author      = "True Protection by Jag"
        description = "Contains strings matching known ransomware encrypted file extensions"
        severity    = "high"
        category    = "ransomware"
        created     = "2026-03-27"

    strings:
        $ext1  = ".encrypted" ascii wide nocase
        $ext2  = ".locked" ascii wide nocase
        $ext3  = ".crypt" ascii wide nocase
        $ext4  = ".enc" ascii wide nocase
        $ext5  = ".locky" ascii wide nocase
        $ext6  = ".cerber" ascii wide nocase
        $ext7  = ".zepto" ascii wide nocase
        $ext8  = ".wcry" ascii wide nocase
        $ext9  = ".wncry" ascii wide nocase
        $ext10 = ".wncryt" ascii wide nocase
        $ext11 = ".crinf" ascii wide nocase
        $ext12 = ".r5a" ascii wide nocase
        $ext13 = ".XRNT" ascii wide nocase
        $ext14 = ".XTBL" ascii wide nocase
        $ext15 = ".dharma" ascii wide nocase
        $ext16 = ".phobos" ascii wide nocase
        $ext17 = ".conti" ascii wide nocase
        $ext18 = ".ryuk" ascii wide nocase
        $ext19 = ".hive" ascii wide nocase
        $ext20 = ".blackcat" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        3 of ($ext*)
}

rule TPJ_Ransomware_CryptoAPIs
{
    meta:
        author      = "True Protection by Jag"
        description = "PE file importing Windows Crypto APIs commonly used by ransomware"
        severity    = "high"
        category    = "ransomware"
        created     = "2026-03-27"

    strings:
        // Windows CryptoAPI
        $api1  = "CryptEncrypt" ascii
        $api2  = "CryptGenKey" ascii
        $api3  = "CryptAcquireContext" ascii
        $api4  = "CryptImportKey" ascii
        $api5  = "CryptExportKey" ascii
        $api6  = "CryptDestroyKey" ascii
        // CNG (Cryptography Next Generation)
        $api7  = "BCryptEncrypt" ascii
        $api8  = "BCryptGenerateSymmetricKey" ascii
        $api9  = "BCryptImportKeyPair" ascii
        // File enumeration (needed for mass encryption)
        $enum1 = "FindFirstFileW" ascii
        $enum2 = "FindNextFileW" ascii
        $enum3 = "GetLogicalDriveStringsW" ascii
        // Ransom note dropping
        $note  = "WriteFile" ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of ($api*) and
        ($enum1 and $enum2) and
        $note
}

rule TPJ_Ransomware_ShadowCopyDeletion
{
    meta:
        author      = "True Protection by Jag"
        description = "Contains commands to delete Volume Shadow Copies -- strong ransomware indicator"
        severity    = "critical"
        category    = "ransomware"
        created     = "2026-03-27"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase
        $vss4 = "wmic.exe shadowcopy delete" ascii wide nocase
        // PowerShell variants
        $vss5 = "Get-WmiObject Win32_ShadowCopy" ascii wide nocase
        $vss6 = "Win32_ShadowCopy" ascii wide nocase
        // bcdedit recovery disable
        $bcd1 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $bcd2 = "bcdedit.exe /set" ascii wide nocase
        // Disable Windows Defender
        $def1 = "DisableRealtimeMonitoring" ascii wide nocase
        $def2 = "Set-MpPreference" ascii wide nocase

    condition:
        any of ($vss*) or
        ($bcd1 or ($bcd2 and any of ($def*)))
}

rule TPJ_Ransomware_BehaviorPattern
{
    meta:
        author      = "True Protection by Jag"
        description = "Combination of file enumeration, crypto operations, and ransom note indicators"
        severity    = "critical"
        category    = "ransomware"
        created     = "2026-03-27"

    strings:
        // File enumeration
        $enum1     = "FindFirstFile" ascii
        $enum2     = "FindNextFile" ascii
        // Crypto
        $crypto1   = "CryptEncrypt" ascii
        $crypto2   = "AES" ascii wide
        $crypto3   = "RSA" ascii wide
        // Ransom indicators
        $ransom1   = "bitcoin" ascii wide nocase
        $ransom2   = "wallet" ascii wide nocase
        $ransom3   = "decrypt" ascii wide nocase
        $ransom4   = "recover" ascii wide nocase
        $ransom5   = "payment" ascii wide nocase
        $ransom6   = "tor" ascii wide nocase
        $ransom7   = ".onion" ascii wide nocase
        // File write
        $write     = "WriteFile" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($enum1 and $enum2) and
        any of ($crypto*) and
        2 of ($ransom*) and
        $write
}

rule TPJ_Ransomware_WannaCry_Indicators
{
    meta:
        author      = "True Protection by Jag"
        description = "Indicators specific to WannaCry / WanaCrypt0r ransomware family"
        severity    = "critical"
        category    = "ransomware"
        created     = "2026-03-27"
        reference   = "CVE-2017-0144"

    strings:
        $wc1 = "WanaCrypt0r" ascii wide nocase
        $wc2 = "WannaCry" ascii wide nocase
        $wc3 = "WANACRY!" ascii wide
        $wc4 = "!WannaDecryptor!" ascii wide
        $wc5 = "!Please Read Me!.txt" ascii wide
        $wc6 = "@WanaDecryptor@" ascii wide
        $wc7 = ".wnry" ascii wide
        $wc8 = ".wncry" ascii wide

    condition:
        2 of ($wc*)
}

rule TPJ_Ransomware_StopDjvu_Indicators
{
    meta:
        author      = "True Protection by Jag"
        description = "Indicators specific to STOP/Djvu ransomware family"
        severity    = "critical"
        category    = "ransomware"
        created     = "2026-03-27"

    strings:
        $stop1 = "_readme.txt" ascii wide
        $stop2 = "ATTENTION!" ascii wide
        $stop3 = "restorealldata@firemail" ascii wide nocase
        $stop4 = "golooman@tutanota" ascii wide nocase
        $stop5 = "support@sysmail" ascii wide nocase
        $stop6 = "$980" ascii wide
        $stop7 = "$490" ascii wide
        $stop8 = "personal ID" ascii wide nocase

    condition:
        $stop1 and 2 of ($stop*)
}

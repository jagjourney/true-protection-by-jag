rule TPJ_Ransomware_CryptoIndicators : ransomware
{
    meta:
        author = "True Protection Community"
        description = "Detects common ransomware encryption indicators"
        date = "2026-03-28"
        severity = "critical"
        reference = "https://tpjsecurity.com/threats/ransomware"

    strings:
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "BCryptEncrypt" ascii
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crypto" ascii
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "bitcoin" ascii nocase
        $note3 = "ransom" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($api*)) and
        (1 of ($ext*) or 2 of ($note*))
}

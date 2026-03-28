rule TPJ_Trojan_GenericDownloader : trojan downloader
{
    meta:
        author = "True Protection Community"
        description = "Detects generic trojan downloader patterns"
        date = "2026-03-28"
        severity = "high"
        reference = "https://tpjsecurity.com/threats/trojan-downloader"

    strings:
        $url1 = "URLDownloadToFile" ascii
        $url2 = "InternetOpenUrl" ascii
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "powershell -e" ascii nocase
        $drop1 = "%TEMP%" ascii nocase
        $drop2 = "%APPDATA%" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (1 of ($url*)) and
        (1 of ($cmd*)) and
        (1 of ($drop*))
}

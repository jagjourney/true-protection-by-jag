/*
    True Protection by Jag - Information Stealer Detection Rules
    Detects credential harvesters, keyloggers, browser data stealers,
    clipboard hijackers, and screenshot capture malware.
    Copyright (C) 2026 Jag Journey, LLC
    Powered by JagAI
*/

import "pe"

// ============================================================================
// Browser Credential Theft
// ============================================================================

rule TPJ_InfoStealer_Browser_PasswordDB
{
    meta:
        author      = "True Protection by Jag"
        description = "PE accessing browser password database files for credential theft"
        severity    = "critical"
        category    = "info_stealer"
        mitre_att   = "T1555.003"
        date        = "2026-04-13"

    strings:
        // Chrome / Chromium credential stores
        $db1 = "Login Data" ascii wide
        $db2 = "\\Google\\Chrome\\User Data" ascii wide
        $db3 = "\\Microsoft\\Edge\\User Data" ascii wide
        $db4 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide
        $db5 = "\\Opera Software\\Opera Stable" ascii wide

        // Firefox credential stores
        $ff1 = "logins.json" ascii wide
        $ff2 = "key4.db" ascii wide
        $ff3 = "key3.db" ascii wide
        $ff4 = "signons.sqlite" ascii wide
        $ff5 = "\\Mozilla\\Firefox\\Profiles" ascii wide

        // SQLite operations on credential databases
        $sql1 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql2 = "SELECT host, name, encrypted_value FROM cookies" ascii wide nocase
        $sql3 = "SELECT url, title FROM urls" ascii wide nocase

        // Decryption APIs
        $dec1 = "CryptUnprotectData" ascii
        $dec2 = "BCryptDecrypt" ascii
        $dec3 = "sqlite3_open" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($db*) and 1 of ($dec*)) or
            (2 of ($ff*) and 1 of ($dec*)) or
            (1 of ($sql*) and 1 of ($dec*)) or
            (1 of ($db*) and 1 of ($ff*) and 1 of ($sql*))
        )
}

rule TPJ_InfoStealer_Browser_Cookies
{
    meta:
        author      = "True Protection by Jag"
        description = "PE targeting browser cookie databases for session hijacking"
        severity    = "high"
        category    = "info_stealer"
        mitre_att   = "T1539"
        date        = "2026-04-13"

    strings:
        // Cookie database paths
        $ck1 = "\\Cookies" ascii wide
        $ck2 = "cookies.sqlite" ascii wide
        $ck3 = "Network\\Cookies" ascii wide

        // Cookie query patterns
        $q1 = "encrypted_value" ascii wide
        $q2 = "host_key" ascii wide
        $q3 = "creation_utc" ascii wide
        $q4 = "expires_utc" ascii wide
        $q5 = "is_httponly" ascii wide

        // Data exfil indicators
        $ex1 = "POST" ascii
        $ex2 = "Content-Type" ascii
        $ex3 = "multipart/form-data" ascii wide
        $ex4 = "application/json" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($ck*) and 2 of ($q*)) or
        (1 of ($ck*) and 3 of ($q*) and 1 of ($ex*))
}

// ============================================================================
// Windows Credential Manager / DPAPI Theft
// ============================================================================

rule TPJ_InfoStealer_Windows_CredManager
{
    meta:
        author      = "True Protection by Jag"
        description = "PE accessing Windows Credential Manager and DPAPI protected data"
        severity    = "critical"
        category    = "info_stealer"
        mitre_att   = "T1555.004"
        date        = "2026-04-13"

    strings:
        // Credential Manager API
        $cm1 = "CredEnumerateA" ascii
        $cm2 = "CredEnumerateW" ascii
        $cm3 = "CredReadA" ascii
        $cm4 = "CredReadW" ascii
        $cm5 = "CredFree" ascii

        // DPAPI functions
        $dp1 = "CryptUnprotectData" ascii
        $dp2 = "CryptProtectData" ascii

        // Vault access
        $v1 = "VaultEnumerateVaults" ascii
        $v2 = "VaultOpenVault" ascii
        $v3 = "VaultEnumerateItems" ascii
        $v4 = "VaultGetItem" ascii
        $v5 = "vaultcli.dll" ascii wide nocase

        // Credential file paths
        $fp1 = "\\Microsoft\\Credentials\\" ascii wide
        $fp2 = "\\Microsoft\\Protect\\" ascii wide
        $fp3 = "\\Microsoft\\Vault\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($cm*) and $dp1) or
            (2 of ($v*)) or
            (1 of ($cm*) and 1 of ($v*) and $dp1) or
            (2 of ($fp*) and $dp1)
        )
}

// ============================================================================
// Keyloggers
// ============================================================================

rule TPJ_InfoStealer_Keylogger_APIs
{
    meta:
        author      = "True Protection by Jag"
        description = "PE using keyboard hooking and keystroke capture APIs"
        severity    = "high"
        category    = "info_stealer"
        mitre_att   = "T1056.001"
        date        = "2026-04-13"

    strings:
        // Keyboard hook APIs
        $hook1 = "SetWindowsHookExA" ascii
        $hook2 = "SetWindowsHookExW" ascii
        $hook3 = "WH_KEYBOARD_LL" ascii wide
        $hook4 = "WH_KEYBOARD" ascii wide
        $hook5 = "CallNextHookEx" ascii

        // Raw input keyboard capture
        $raw1 = "GetRawInputData" ascii
        $raw2 = "RegisterRawInputDevices" ascii
        $raw3 = "RAWINPUTDEVICE" ascii
        $raw4 = "RIM_TYPEKEYBOARD" ascii wide

        // Key state polling
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyState" ascii
        $key3 = "GetKeyboardState" ascii
        $key4 = "MapVirtualKeyA" ascii
        $key5 = "GetKeyNameTextA" ascii

        // Foreground window tracking (to label captured keystrokes)
        $fg1 = "GetForegroundWindow" ascii
        $fg2 = "GetWindowTextA" ascii
        $fg3 = "GetWindowTextW" ascii

        // File write (for logging keystrokes)
        $log1 = "WriteFile" ascii
        $log2 = "fwrite" ascii
        $log3 = "fprintf" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($hook1, $hook2) and $hook5 and 1 of ($fg*)) or
            (2 of ($raw*) and 1 of ($fg*)) or
            (2 of ($key*) and 1 of ($fg*) and 1 of ($log*))
        )
}

// ============================================================================
// Clipboard Hijacking
// ============================================================================

rule TPJ_InfoStealer_Clipboard_Hijacker
{
    meta:
        author      = "True Protection by Jag"
        description = "PE monitoring and modifying clipboard data - cryptocurrency address swapping"
        severity    = "high"
        category    = "info_stealer"
        mitre_att   = "T1115"
        date        = "2026-04-13"

    strings:
        // Clipboard monitoring APIs
        $clip1 = "AddClipboardFormatListener" ascii
        $clip2 = "SetClipboardViewer" ascii
        $clip3 = "GetClipboardData" ascii
        $clip4 = "SetClipboardData" ascii
        $clip5 = "OpenClipboard" ascii
        $clip6 = "EmptyClipboard" ascii
        $clip7 = "CloseClipboard" ascii

        // Crypto address regex patterns (compiled or as strings)
        $btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $eth1 = /0x[0-9a-fA-F]{40}/ ascii

        // Clipboard change notification
        $notify1 = "WM_CLIPBOARDUPDATE" ascii wide
        $notify2 = "WM_DRAWCLIPBOARD" ascii wide
        $notify3 = "WM_CHANGECBCHAIN" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($clip3 and $clip4 and ($clip5 or $clip1 or $clip2)) or
            (2 of ($clip*) and 1 of ($notify*)) or
            (($clip3 or $clip4) and 1 of ($btc1, $eth1) and 1 of ($notify*))
        )
}

// ============================================================================
// Screenshot Capture
// ============================================================================

rule TPJ_InfoStealer_Screenshot_Capture
{
    meta:
        author      = "True Protection by Jag"
        description = "PE with screenshot capture capabilities using GDI/desktop APIs"
        severity    = "medium"
        category    = "info_stealer"
        mitre_att   = "T1113"
        date        = "2026-04-13"

    strings:
        // GDI screenshot APIs
        $gdi1 = "CreateCompatibleDC" ascii
        $gdi2 = "CreateCompatibleBitmap" ascii
        $gdi3 = "BitBlt" ascii
        $gdi4 = "GetDC" ascii
        $gdi5 = "GetDesktopWindow" ascii
        $gdi6 = "SelectObject" ascii
        $gdi7 = "GetDIBits" ascii

        // Image encoding
        $img1 = "GdipSaveImageToFile" ascii
        $img2 = "image/png" ascii wide
        $img3 = "image/jpeg" ascii wide
        $img4 = ".bmp" ascii wide
        $img5 = ".png" ascii wide
        $img6 = ".jpg" ascii wide

        // PrintWindow (alternative capture method)
        $pw1 = "PrintWindow" ascii

        // Timer-based capture
        $tmr1 = "SetTimer" ascii
        $tmr2 = "Sleep" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($gdi5 and $gdi4 and $gdi3 and $gdi2 and 1 of ($img*)) or
            ($pw1 and 1 of ($gdi*) and 1 of ($img*)) or
            ($gdi3 and $gdi7 and 1 of ($img*) and 1 of ($tmr*))
        )
}

// ============================================================================
// Known Stealer Families
// ============================================================================

rule TPJ_InfoStealer_RedLine
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects RedLine Stealer malware family indicators"
        severity    = "critical"
        category    = "info_stealer"
        family      = "redline"
        date        = "2026-04-13"

    strings:
        $r1 = "RedLine" ascii wide nocase
        $r2 = "Yandex\\YandexBrowser" ascii wide
        $r3 = "Opera\\Opera GX Stable" ascii wide
        $r4 = "Chromium\\User Data" ascii wide

        // RedLine-specific method names / strings
        $m1 = "ScanPasswords" ascii wide
        $m2 = "ScanCookies" ascii wide
        $m3 = "ScanFTP" ascii wide
        $m4 = "ScanWallets" ascii wide
        $m5 = "ScanScreen" ascii wide
        $m6 = "ScanTelegram" ascii wide
        $m7 = "ScanDiscord" ascii wide
        $m8 = "ScanSteam" ascii wide

        // Hardware fingerprinting
        $hw1 = "GraphicCardName" ascii wide
        $hw2 = "AvailablePhysicalMemory" ascii wide
        $hw3 = "ProcessorName" ascii wide
        $hw4 = "MachineGuid" ascii wide

    condition:
        (2 of ($m*)) or
        ($r1 and 2 of ($r*)) or
        (1 of ($r*) and 3 of ($m*)) or
        (3 of ($hw*) and 2 of ($m*))
}

rule TPJ_InfoStealer_Raccoon
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Raccoon Stealer malware family indicators"
        severity    = "critical"
        category    = "info_stealer"
        family      = "raccoon"
        date        = "2026-04-13"

    strings:
        $s1 = "Raccoon" ascii wide nocase
        $s2 = "ews_" ascii wide
        $s3 = "sstmnfo_" ascii wide
        $s4 = "grbr_" ascii wide
        $s5 = "scrnsht_" ascii wide
        $s6 = "tlgrm_" ascii wide
        $s7 = "dscrd_" ascii wide

        // Raccoon C2 patterns
        $c2_1 = "machineId=" ascii wide
        $c2_2 = "configId=" ascii wide
        $c2_3 = "&token=" ascii wide

        // DLL loading pattern
        $dll1 = "sqlite3.dll" ascii wide nocase
        $dll2 = "nss3.dll" ascii wide nocase
        $dll3 = "msvcp140.dll" ascii wide nocase
        $dll4 = "vcruntime140.dll" ascii wide nocase
        $dll5 = "mozglue.dll" ascii wide nocase
        $dll6 = "freebl3.dll" ascii wide nocase
        $dll7 = "softokn3.dll" ascii wide nocase

    condition:
        (3 of ($s*)) or
        (2 of ($c2_*) and 1 of ($s*)) or
        (1 of ($s1, $s2) and 3 of ($dll*)) or
        (4 of ($dll*) and 1 of ($c2_*))
}

rule TPJ_InfoStealer_Vidar
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Vidar Stealer malware family indicators"
        severity    = "critical"
        category    = "info_stealer"
        family      = "vidar"
        date        = "2026-04-13"

    strings:
        $v1 = "Vidar" ascii wide nocase
        $v2 = "vidar" ascii wide

        // Vidar data collection markers
        $d1 = "passwords.txt" ascii wide
        $d2 = "cookies.txt" ascii wide
        $d3 = "autofill.txt" ascii wide
        $d4 = "CC.txt" ascii wide
        $d5 = "history.txt" ascii wide
        $d6 = "downloads.txt" ascii wide
        $d7 = "screenshot.jpg" ascii wide
        $d8 = "information.txt" ascii wide

        // Wallet targeting
        $w1 = "Electrum" ascii wide
        $w2 = "Ethereum" ascii wide
        $w3 = "Exodus" ascii wide
        $w4 = "Jaxx" ascii wide
        $w5 = "Atomic" ascii wide
        $w6 = "wallet.dat" ascii wide

    condition:
        (1 of ($v*) and 3 of ($d*)) or
        (4 of ($d*) and 2 of ($w*)) or
        (1 of ($v*) and 2 of ($d*) and 1 of ($w*))
}

// ============================================================================
// Email and FTP Credential Theft
// ============================================================================

rule TPJ_InfoStealer_Email_FTP_Creds
{
    meta:
        author      = "True Protection by Jag"
        description = "PE targeting email client and FTP client stored credentials"
        severity    = "high"
        category    = "info_stealer"
        mitre_att   = "T1555"
        date        = "2026-04-13"

    strings:
        // Email client credential files
        $em1 = "\\Thunderbird\\Profiles\\" ascii wide
        $em2 = "\\Microsoft\\Outlook\\" ascii wide
        $em3 = "\\The Bat!\\" ascii wide
        $em4 = "\\Foxmail\\" ascii wide
        $em5 = "\\eM Client\\" ascii wide

        // FTP client credential files
        $ftp1 = "\\FileZilla\\recentservers.xml" ascii wide
        $ftp2 = "\\FileZilla\\sitemanager.xml" ascii wide
        $ftp3 = "\\WinSCP\\WinSCP.ini" ascii wide
        $ftp4 = "\\FlashFXP\\" ascii wide
        $ftp5 = "\\SmartFTP\\" ascii wide

        // Registry locations for stored creds
        $reg1 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles" ascii wide
        $reg2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging" ascii wide
        $reg3 = "Software\\Martin Prikryl\\WinSCP" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($em*) and 1 of ($ftp*)) or
            (3 of ($em*)) or
            (2 of ($ftp*)) or
            (1 of ($reg*) and 1 of ($em*, $ftp*))
        )
}

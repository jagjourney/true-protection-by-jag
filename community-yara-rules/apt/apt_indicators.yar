/*
    True Protection by Jag - APT Group Indicator Rules
    Detects tools and indicators commonly associated with Advanced Persistent
    Threat groups: Cobalt Strike, Mimikatz, BloodHound/SharpHound,
    Metasploit, and common C2 framework patterns.
    Copyright (C) 2026 Jag Journey, LLC - GPLv3
    Powered by JagAI
*/

import "pe"

// ============================================================================
// Cobalt Strike Beacon
// ============================================================================

rule TPJ_APT_CobaltStrike_Beacon_Strings
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Cobalt Strike beacon by characteristic strings"
        severity    = "critical"
        category    = "apt"
        tool        = "cobalt_strike"
        mitre_att   = "S0154"
        created     = "2026-03-27"

    strings:
        $s1 = "beacon.dll" ascii wide nocase
        $s2 = "beacon.exe" ascii wide nocase
        $s3 = "beacon_x64.dll" ascii wide nocase
        $s4 = "ReflectiveLoader" ascii wide
        $s5 = "%s.4444" ascii
        $s6 = "%s as %s\\%s: %d" ascii
        $s7 = "could not spawn %s: %d" ascii
        $s8 = "Could not connect to pipe" ascii
        $s9 = "%s (admin)" ascii
        $s10 = "IEX (New-Object Net.Webclient).DownloadString" ascii wide

        // Named pipe patterns
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $pipe4 = "\\\\.\\pipe\\postex_ssh_" ascii wide
        $pipe5 = "\\\\.\\pipe\\status_" ascii wide

    condition:
        3 of ($s*) or
        2 of ($pipe*) or
        (1 of ($pipe*) and 2 of ($s*))
}

rule TPJ_APT_CobaltStrike_Beacon_Config
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Cobalt Strike beacon configuration block"
        severity    = "critical"
        category    = "apt"
        tool        = "cobalt_strike"
        created     = "2026-03-27"

    strings:
        // Beacon config magic bytes (encrypted config starts after this)
        $cfg_magic1 = { 00 01 00 01 00 02 }
        $cfg_magic2 = { 00 01 00 01 00 02 00 01 00 02 }

        // Config field indicators (after decryption)
        $cf1 = "sleeptime" ascii
        $cf2 = "jitter" ascii
        $cf3 = "maxdns" ascii
        $cf4 = "publickey" ascii
        $cf5 = "server,get-uri" ascii
        $cf6 = "watermark" ascii

        // Malleable C2 profile indicators
        $mc1 = "Content-Type: application/octet-stream" ascii
        $mc2 = ".http-get." ascii
        $mc3 = ".http-post." ascii
        $mc4 = "spawnto_x86" ascii
        $mc5 = "spawnto_x64" ascii

    condition:
        (1 of ($cfg_magic*) and pe.is_pe) or
        (4 of ($cf*)) or
        (3 of ($mc*))
}

rule TPJ_APT_CobaltStrike_Shellcode
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Cobalt Strike stager/shellcode patterns"
        severity    = "critical"
        category    = "apt"
        tool        = "cobalt_strike"
        created     = "2026-03-27"

    strings:
        // x86 stager shellcode pattern
        $sc_x86 = { FC E8 ?? 00 00 00 [0-6] EB 27 5? 8B ?? 83 C? 04 }

        // x64 stager
        $sc_x64 = { FC 48 83 E4 F0 E8 [4-8] 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 60 }

        // Beacon sleep mask (x64)
        $sleep = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 }

        // Reflective DLL injection pattern
        $refl1 = { 56 57 53 55 8B EC 8B 74 24 }
        $refl2 = "ReflectiveLoader" ascii

    condition:
        any of ($sc_*) or
        ($sleep) or
        ($refl1 and $refl2)
}

// ============================================================================
// Mimikatz
// ============================================================================

rule TPJ_APT_Mimikatz_Strings
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Mimikatz credential dumping tool"
        severity    = "critical"
        category    = "apt"
        tool        = "mimikatz"
        mitre_att   = "S0002"
        created     = "2026-03-27"

    strings:
        $m1  = "mimikatz" ascii wide nocase
        $m2  = "gentilkiwi" ascii wide nocase
        $m3  = "Benjamin DELPY" ascii wide
        $m4  = "mimilib" ascii wide nocase
        $m5  = "mimidrv" ascii wide nocase
        $m6  = "mimispool" ascii wide nocase

        // Module names
        $mod1  = "sekurlsa" ascii wide
        $mod2  = "kerberos" ascii wide
        $mod3  = "lsadump" ascii wide
        $mod4  = "dpapi" ascii wide
        $mod5  = "privilege::debug" ascii wide
        $mod6  = "sekurlsa::logonpasswords" ascii wide
        $mod7  = "sekurlsa::wdigest" ascii wide
        $mod8  = "sekurlsa::kerberos" ascii wide
        $mod9  = "lsadump::sam" ascii wide
        $mod10 = "lsadump::dcsync" ascii wide
        $mod11 = "lsadump::lsa" ascii wide
        $mod12 = "token::elevate" ascii wide
        $mod13 = "vault::cred" ascii wide
        $mod14 = "crypto::capi" ascii wide

        // Mimikatz output patterns
        $out1 = "* Username : " ascii wide
        $out2 = "* Domain   : " ascii wide
        $out3 = "* Password : " ascii wide
        $out4 = "* NTLM     : " ascii wide
        $out5 = "wdigest :" ascii wide
        $out6 = "tspkg :" ascii wide
        $out7 = "kerberos :" ascii wide

    condition:
        (2 of ($m*)) or
        (3 of ($mod*)) or
        (1 of ($m*) and 2 of ($mod*)) or
        (4 of ($out*))
}

rule TPJ_APT_Mimikatz_PE
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Mimikatz PE binary by exports and characteristics"
        severity    = "critical"
        category    = "apt"
        tool        = "mimikatz"
        created     = "2026-03-27"

    strings:
        $e1 = "powershell_reflective_mimikatz" ascii wide nocase
        $e2 = "Invoke-Mimikatz" ascii wide nocase
        $e3 = "SamQueryInformationUser" ascii
        $e4 = "SamIConnect" ascii
        $e5 = "LsaICancelNotification" ascii
        $e6 = "kuhl_m" ascii

        // Specific API usage pattern
        $api1 = "OpenProcessToken" ascii
        $api2 = "LookupPrivilegeValue" ascii
        $api3 = "AdjustTokenPrivileges" ascii
        $api4 = "LsaQueryInformationPolicy" ascii

    condition:
        pe.is_pe and (
            (2 of ($e*)) or
            ($e6 and 2 of ($api*))
        )
}

// ============================================================================
// BloodHound / SharpHound
// ============================================================================

rule TPJ_APT_BloodHound_SharpHound
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects BloodHound/SharpHound Active Directory enumeration tool"
        severity    = "critical"
        category    = "apt"
        tool        = "bloodhound"
        mitre_att   = "S0521"
        created     = "2026-03-27"

    strings:
        $s1 = "SharpHound" ascii wide nocase
        $s2 = "BloodHound" ascii wide nocase
        $s3 = "Invoke-BloodHound" ascii wide nocase
        $s4 = "Get-BloodHoundData" ascii wide nocase

        // SharpHound collector methods
        $col1 = "CollectionMethod" ascii wide
        $col2 = "DcOnly" ascii wide
        $col3 = "Session" ascii wide
        $col4 = "LoggedOn" ascii wide
        $col5 = "Trusts" ascii wide
        $col6 = "ACL" ascii wide
        $col7 = "ObjectProps" ascii wide
        $col8 = "Container" ascii wide
        $col9 = "GPOLocalGroup" ascii wide

        // LDAP query patterns used by BloodHound
        $ldap1 = "(&(samAccountType=805306368)" ascii wide
        $ldap2 = "(userAccountControl:1.2.840.113556.1.4.803:=" ascii wide
        $ldap3 = "memberOf" ascii wide
        $ldap4 = "servicePrincipalName" ascii wide
        $ldap5 = "msDS-AllowedToDelegateTo" ascii wide
        $ldap6 = "msDS-AllowedToActOnBehalfOfOtherIdentity" ascii wide

        // Output file patterns
        $out1 = "_BloodHound.zip" ascii wide nocase
        $out2 = "bloodhound.zip" ascii wide nocase
        $out3 = "computers.json" ascii wide
        $out4 = "domains.json" ascii wide
        $out5 = "users.json" ascii wide
        $out6 = "groups.json" ascii wide

    condition:
        (2 of ($s*)) or
        (1 of ($s*) and 3 of ($col*)) or
        (1 of ($s*) and 2 of ($ldap*)) or
        (4 of ($ldap*)) or
        (1 of ($s*) and 2 of ($out*))
}

rule TPJ_APT_ADExploration_Tools
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects AD enumeration tools (ADRecon, PowerView, etc.)"
        severity    = "high"
        category    = "apt"
        tool        = "ad_recon"
        created     = "2026-03-27"

    strings:
        // PowerView
        $pv1 = "Invoke-ShareFinder" ascii wide nocase
        $pv2 = "Invoke-FileFinder" ascii wide nocase
        $pv3 = "Get-NetDomain" ascii wide nocase
        $pv4 = "Get-NetForest" ascii wide nocase
        $pv5 = "Get-NetComputer" ascii wide nocase
        $pv6 = "Get-NetUser" ascii wide nocase
        $pv7 = "Get-NetGroup" ascii wide nocase
        $pv8 = "Get-DomainPolicy" ascii wide nocase
        $pv9 = "Find-LocalAdminAccess" ascii wide nocase
        $pv10 = "Invoke-Kerberoast" ascii wide nocase

        // ADRecon
        $adr1 = "ADRecon" ascii wide nocase
        $adr2 = "Get-ADRExcelComObj" ascii wide nocase

        // Rubeus
        $rub1 = "Rubeus" ascii wide nocase
        $rub2 = "asktgt" ascii wide
        $rub3 = "asktgs" ascii wide
        $rub4 = "kerberoast" ascii wide nocase
        $rub5 = "asreproast" ascii wide nocase

    condition:
        (3 of ($pv*)) or
        (2 of ($adr*)) or
        (1 of ($rub1) and 2 of ($rub2, $rub3, $rub4, $rub5))
}

// ============================================================================
// Metasploit
// ============================================================================

rule TPJ_APT_Metasploit_Payload
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Metasploit payload patterns"
        severity    = "critical"
        category    = "apt"
        tool        = "metasploit"
        mitre_att   = "S0103"
        created     = "2026-03-27"

    strings:
        // Meterpreter strings
        $met1 = "meterpreter" ascii wide nocase
        $met2 = "metasploit" ascii wide nocase
        $met3 = "metsrv" ascii wide nocase
        $met4 = "ext_server" ascii wide

        // Meterpreter DLL export names
        $exp1 = "Init" ascii
        $exp2 = "ServerThread" ascii
        $exp3 = "ReflectiveLoader" ascii

        // Meterpreter transport strings
        $tr1 = "reverse_tcp" ascii
        $tr2 = "reverse_http" ascii
        $tr3 = "reverse_https" ascii
        $tr4 = "bind_tcp" ascii
        $tr5 = "reverse_named_pipe" ascii

        // Metasploit stage patterns
        $stg1 = { 6A 40 68 00 10 00 00 68 00 00 40 00 6A 00 FF 15 }
        $stg2 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $stg3 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }

        // Msfvenom markers
        $msf1 = "windows/meterpreter" ascii
        $msf2 = "linux/meterpreter" ascii
        $msf3 = "payload/multi" ascii

    condition:
        (2 of ($met*)) or
        ($exp3 and 1 of ($met*)) or
        (2 of ($tr*) and 1 of ($met*)) or
        (1 of ($stg*)) or
        (2 of ($msf*))
}

rule TPJ_APT_Metasploit_Shellcode
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects common Metasploit shellcode patterns"
        severity    = "critical"
        category    = "apt"
        tool        = "metasploit"
        created     = "2026-03-27"

    strings:
        // windows/shell_reverse_tcp (x86)
        $wsr = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 }

        // windows/exec (x86) - calc.exe pattern
        $wexec = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF }

        // linux/x86/shell_reverse_tcp
        $lsr = { 6A 66 58 6A 01 5B 99 52 53 6A 02 89 E1 CD 80 }

        // windows/x64/meterpreter/reverse_tcp (PEB walking)
        $w64met = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }

        // Hash-based API resolution (common in MSF payloads)
        $api_hash = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 }

        // block_api.asm pattern
        $block_api = { 56 57 53 55 8B EC 8B 74 24 14 8B 7C 24 }

    condition:
        any of them
}

// ============================================================================
// Common C2 Framework Indicators
// ============================================================================

rule TPJ_APT_C2_Framework_Strings
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects common C2 framework indicators (Covenant, Sliver, PoshC2, etc.)"
        severity    = "critical"
        category    = "apt"
        tool        = "c2_framework"
        created     = "2026-03-27"

    strings:
        // Covenant / Grunt
        $cov1 = "Covenant" ascii wide nocase
        $cov2 = "GruntHTTP" ascii wide
        $cov3 = "GruntSMB" ascii wide
        $cov4 = "GruntStager" ascii wide
        $cov5 = "CovenantTask" ascii wide

        // Sliver
        $slv1 = "sliver" ascii wide nocase
        $slv2 = "sliverpb" ascii wide
        $slv3 = "SliverHTTPC2" ascii wide
        $slv4 = "SliverDNS" ascii wide
        $slv5 = "bishopfox" ascii wide nocase

        // PoshC2
        $pc2_1 = "PoshC2" ascii wide nocase
        $pc2_2 = "posh-server" ascii wide nocase
        $pc2_3 = "Invoke-DaisyChain" ascii wide nocase
        $pc2_4 = "SharpPoshC2" ascii wide nocase

        // Brute Ratel
        $br1 = "BruteRatel" ascii wide nocase
        $br2 = "badger" ascii wide
        $br3 = "brc4" ascii wide nocase

        // Havoc
        $hav1 = "HavocFramework" ascii wide nocase
        $hav2 = "havoc" ascii wide nocase
        $hav3 = "Demon" ascii wide

        // Empire
        $emp1 = "Invoke-Empire" ascii wide nocase
        $emp2 = "Empire" ascii wide
        $emp3 = "starkiller" ascii wide nocase

        // Mythic
        $myth1 = "MythicC2" ascii wide nocase
        $myth2 = "mythic" ascii wide nocase
        $myth3 = "Apfell" ascii wide nocase

    condition:
        (2 of ($cov*)) or
        (2 of ($slv*)) or
        (2 of ($pc2_*)) or
        (2 of ($br*)) or
        (2 of ($hav*)) or
        (2 of ($emp*)) or
        (2 of ($myth*))
}

rule TPJ_APT_C2_Communication_Patterns
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects C2 communication patterns (beaconing, DNS tunneling, etc.)"
        severity    = "high"
        category    = "apt"
        tool        = "c2_generic"
        created     = "2026-03-27"

    strings:
        // HTTP C2 user-agent patterns
        $ua1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0" ascii
        $ua2 = "Mozilla/4.0 (compatible; MSIE 8.0" ascii

        // Common C2 URI patterns
        $uri1 = "/login/process.php" ascii wide
        $uri2 = "/admin/get.php" ascii wide
        $uri3 = "/updates/check" ascii wide
        $uri4 = "/__utm.gif" ascii wide
        $uri5 = "/pixel.gif" ascii wide
        $uri6 = "/ca" ascii
        $uri7 = "/dpixel" ascii

        // C2 data encoding patterns
        $enc1 = "base64_decode" ascii wide
        $enc2 = "base64_encode" ascii wide
        $enc3 = "FromBase64String" ascii wide
        $enc4 = "ToBase64String" ascii wide

        // DNS tunneling indicators
        $dns1 = "nslookup" ascii wide
        $dns2 = "TXT" ascii
        $dns3 = "dnscat" ascii wide nocase
        $dns4 = "iodine" ascii wide nocase

        // Named pipe C2
        $np1 = "\\\\.\\pipe\\" ascii wide
        $np2 = "CreateNamedPipe" ascii
        $np3 = "ConnectNamedPipe" ascii

    condition:
        (2 of ($uri*) and 1 of ($enc*)) or
        (2 of ($dns*)) or
        ($np1 and $np2 and $np3 and 1 of ($enc*))
}

rule TPJ_APT_Lateral_Movement_Tools
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects tools used for lateral movement in APT campaigns"
        severity    = "critical"
        category    = "apt"
        tool        = "lateral_movement"
        created     = "2026-03-27"

    strings:
        // PsExec variants
        $pse1 = "PsExec" ascii wide nocase
        $pse2 = "PSEXESVC" ascii wide
        $pse3 = "\\ADMIN$\\system32" ascii wide

        // WMIExec
        $wmi1 = "Invoke-WMIExec" ascii wide nocase
        $wmi2 = "Win32_Process" ascii wide
        $wmi3 = "Win32_ScheduledJob" ascii wide

        // SMBExec
        $smb1 = "Invoke-SMBExec" ascii wide nocase
        $smb2 = "smbexec" ascii wide nocase

        // DCOMExec
        $dcom1 = "Invoke-DCOM" ascii wide nocase
        $dcom2 = "MMC20.Application" ascii wide
        $dcom3 = "ShellBrowserWindow" ascii wide
        $dcom4 = "ShellWindows" ascii wide

        // Evil-WinRM
        $ewrm1 = "evil-winrm" ascii wide nocase
        $ewrm2 = "Evil-WinRM" ascii wide

        // Impacket tools
        $imp1 = "impacket" ascii wide nocase
        $imp2 = "secretsdump" ascii wide nocase
        $imp3 = "smbclient" ascii wide nocase
        $imp4 = "wmiexec" ascii wide nocase
        $imp5 = "atexec" ascii wide nocase
        $imp6 = "dcomexec" ascii wide nocase
        $imp7 = "psexec" ascii wide nocase

    condition:
        (2 of ($pse*)) or
        (2 of ($wmi*)) or
        (2 of ($smb*)) or
        (2 of ($dcom*)) or
        (2 of ($ewrm*)) or
        (3 of ($imp*))
}

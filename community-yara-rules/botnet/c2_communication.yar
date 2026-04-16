/*
    True Protection by Jag - Command & Control Communication Detection Rules
    Detects C2 traffic patterns including DNS tunneling, HTTP beaconing,
    and protocol-level indicators for known C2 frameworks.
    Note: Framework name-based detection is in apt_indicators.yar.
    This file focuses on network-level and protocol-level patterns.
    Copyright (C) 2026 Jag Journey, LLC
    Powered by JagAI
*/

import "pe"

// ============================================================================
// DNS Tunneling Detection
// ============================================================================

rule TPJ_C2_DNS_Tunneling_Tools
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects DNS tunneling tool binaries (dnscat2, iodine, dns2tcp)"
        severity    = "critical"
        category    = "c2_communication"
        mitre_att   = "T1071.004"
        date        = "2026-04-13"

    strings:
        // dnscat2
        $dc1 = "dnscat" ascii wide nocase
        $dc2 = "dnscat2" ascii wide nocase
        $dc3 = "DNSCAT_DOMAIN" ascii wide
        $dc4 = "SESSION_ESTABLISHED" ascii wide
        $dc5 = "COMMAND_SHELL" ascii wide

        // iodine DNS tunnel
        $io1 = "iodine" ascii wide
        $io2 = "iodined" ascii wide
        $io3 = "Setting IP of dns" ascii wide
        $io4 = "tun_open" ascii wide
        $io5 = "tunnel started" ascii wide nocase

        // dns2tcp
        $dt1 = "dns2tcp" ascii wide nocase
        $dt2 = "dns2tcpd" ascii wide nocase
        $dt3 = "dns2tcpc" ascii wide nocase

        // Cobalt Strike DNS beacon
        $cs_dns1 = "mode dns" ascii wide
        $cs_dns2 = "mode dns-txt" ascii wide
        $cs_dns3 = "mode dns6" ascii wide

    condition:
        (2 of ($dc*)) or
        (2 of ($io*)) or
        (1 of ($dt*)) or
        (1 of ($cs_dns*))
}

rule TPJ_C2_DNS_Tunneling_Patterns
{
    meta:
        author      = "True Protection by Jag"
        description = "PE with DNS query functions and encoding patterns used for DNS tunneling"
        severity    = "high"
        category    = "c2_communication"
        mitre_att   = "T1071.004"
        date        = "2026-04-13"

    strings:
        // DNS query APIs
        $dns1 = "DnsQuery_A" ascii
        $dns2 = "DnsQuery_W" ascii
        $dns3 = "DnsQueryEx" ascii
        $dns4 = "DnsRecordListFree" ascii
        $dns5 = "getaddrinfo" ascii
        $dns6 = "gethostbyname" ascii
        $dns7 = "res_query" ascii
        $dns8 = "nslookup" ascii wide

        // TXT record types (used for data exfil via DNS)
        $txt1 = "DNS_TYPE_TEXT" ascii wide
        $txt2 = "DNS_TYPE_TXT" ascii wide
        $txt3 = "DNS_TYPE_NULL" ascii wide
        $txt4 = "DNS_TYPE_CNAME" ascii wide

        // Base32/Base64 encoding (data encoding for DNS labels)
        $enc1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $enc2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" ascii

        // Long subdomain construction (DNS tunneling indicator)
        $sub1 = "sprintf" ascii
        $sub2 = ".%s.%s" ascii
        $sub3 = "%s.%s.%s" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($dns*) and 1 of ($txt*) and 1 of ($enc*)) or
            (2 of ($dns*) and 1 of ($enc*) and 1 of ($sub*)) or
            (1 of ($dns*) and 1 of ($txt*) and 1 of ($enc*) and 1 of ($sub*))
        )
}

// ============================================================================
// HTTP C2 Beaconing Patterns
// ============================================================================

rule TPJ_C2_HTTP_Beacon_APIs
{
    meta:
        author      = "True Protection by Jag"
        description = "PE with HTTP request APIs combined with sleep/timer patterns for beaconing"
        severity    = "high"
        category    = "c2_communication"
        mitre_att   = "T1071.001"
        date        = "2026-04-13"

    strings:
        // WinHTTP APIs
        $http1 = "WinHttpOpen" ascii
        $http2 = "WinHttpConnect" ascii
        $http3 = "WinHttpOpenRequest" ascii
        $http4 = "WinHttpSendRequest" ascii
        $http5 = "WinHttpReceiveResponse" ascii
        $http6 = "WinHttpReadData" ascii

        // WinInet APIs
        $inet1 = "InternetOpenA" ascii
        $inet2 = "InternetOpenW" ascii
        $inet3 = "InternetConnectA" ascii
        $inet4 = "InternetConnectW" ascii
        $inet5 = "HttpOpenRequestA" ascii
        $inet6 = "HttpSendRequestA" ascii
        $inet7 = "InternetReadFile" ascii

        // Beacon timing / sleep
        $sleep1 = "Sleep" ascii
        $sleep2 = "WaitForSingleObject" ascii
        $sleep3 = "SetTimer" ascii
        $sleep4 = "CreateTimerQueueTimer" ascii

        // Data encoding for C2
        $code1 = "CryptBinaryToStringA" ascii
        $code2 = "CryptStringToBinaryA" ascii
        $code3 = "Base64" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($http*) and 1 of ($sleep*) and 1 of ($code*)) or
            (3 of ($inet*) and 1 of ($sleep*) and 1 of ($code*)) or
            (2 of ($http*) and 2 of ($inet*) and 1 of ($sleep*))
        )
}

rule TPJ_C2_HTTP_Malleable_Profile
{
    meta:
        author      = "True Protection by Jag"
        description = "HTTP traffic patterns matching Cobalt Strike malleable C2 profile indicators"
        severity    = "critical"
        category    = "c2_communication"
        date        = "2026-04-13"

    strings:
        // Common malleable profile URI patterns
        $uri1  = "/api/v1/" ascii wide
        $uri2  = "/updates/" ascii wide
        $uri3  = "/status/" ascii wide
        $uri4  = "/submit.php" ascii wide
        $uri5  = "/__utm.gif" ascii wide
        $uri6  = "/pixel" ascii wide
        $uri7  = "/ga.js" ascii wide
        $uri8  = "/fwlink" ascii wide
        $uri9  = "/consent" ascii wide
        $uri10 = "/results" ascii wide

        // Specific header manipulation strings
        $hdr1 = "Accept: application/octet-stream" ascii wide
        $hdr2 = "Content-Type: application/octet-stream" ascii wide
        $hdr3 = "X-Requested-With: XMLHttpRequest" ascii wide

        // Cookie-based data embedding
        $ck1 = "SESSIONID=" ascii wide
        $ck2 = "JSESSIONID=" ascii wide
        $ck3 = "__cfduid=" ascii wide
        $ck4 = "PHPSESSID=" ascii wide

        // Jitter and sleep config strings
        $cfg1 = "sleeptime" ascii wide
        $cfg2 = "jitter" ascii wide
        $cfg3 = "spawnto" ascii wide

    condition:
        (3 of ($uri*) and 1 of ($hdr*)) or
        (2 of ($ck*) and 2 of ($uri*) and 1 of ($hdr*)) or
        (2 of ($cfg*) and 2 of ($uri*))
}

// ============================================================================
// Cobalt Strike Protocol-Level Indicators
// ============================================================================

rule TPJ_C2_CobaltStrike_Watermark
{
    meta:
        author      = "True Protection by Jag"
        description = "Cobalt Strike beacon config with watermark and protocol settings"
        severity    = "critical"
        category    = "c2_communication"
        date        = "2026-04-13"

    strings:
        // Beacon config fields (after XOR decoding)
        $f1 = { 00 01 00 01 00 02 }  // Config start marker
        $f2 = { 00 02 00 01 00 02 }  // Alternate marker

        // Common watermark values (as 4-byte integers in config)
        // These appear at known offsets in decoded beacon config
        $wm1 = "watermark" ascii wide
        $wm2 = "publickey" ascii wide
        $wm3 = "proxy_type" ascii wide
        $wm4 = "killdate" ascii wide
        $wm5 = "pipename" ascii wide

        // Post-exploitation job strings
        $job1 = "post.ex.job" ascii wide
        $job2 = "process-inject" ascii wide
        $job3 = "stage.cleanup" ascii wide

    condition:
        (1 of ($f*) and 3 of ($wm*)) or
        (2 of ($wm*) and 2 of ($job*)) or
        (1 of ($f*) and 1 of ($wm*) and 1 of ($job*))
}

// ============================================================================
// Sliver C2 Protocol Indicators
// ============================================================================

rule TPJ_C2_Sliver_Implant
{
    meta:
        author      = "True Protection by Jag"
        description = "Sliver C2 framework implant binary patterns"
        severity    = "critical"
        category    = "c2_communication"
        date        = "2026-04-13"

    strings:
        // Go binary strings from Sliver implant
        $go1 = "github.com/bishopfox/sliver" ascii
        $go2 = "sliverpb" ascii
        $go3 = "sliver/protobuf" ascii
        $go4 = "sliver/transports" ascii

        // Sliver implant function names
        $fn1 = "RunSliver" ascii
        $fn2 = "StartBeaconLoop" ascii
        $fn3 = "ActiveC2" ascii
        $fn4 = "GetBeaconJitter" ascii

        // Sliver transport indicators
        $tr1 = "mtls" ascii
        $tr2 = "wg" ascii
        $tr3 = "StartHTTPSListener" ascii
        $tr4 = "StartDNSListener" ascii
        $tr5 = "StartMTLSListener" ascii

        // Sliver protobuf message types
        $pb1 = "Envelope" ascii
        $pb2 = "ImplantConfig" ascii
        $pb3 = "BeaconTask" ascii

    condition:
        (2 of ($go*)) or
        (2 of ($fn*)) or
        (1 of ($go*) and 1 of ($fn*) and 1 of ($tr*)) or
        (1 of ($go*) and 2 of ($pb*))
}

// ============================================================================
// Havoc C2 Protocol Indicators
// ============================================================================

rule TPJ_C2_Havoc_Demon
{
    meta:
        author      = "True Protection by Jag"
        description = "Havoc C2 framework Demon agent patterns"
        severity    = "critical"
        category    = "c2_communication"
        date        = "2026-04-13"

    strings:
        // Havoc Demon agent strings
        $h1 = "HavocFramework" ascii wide nocase
        $h2 = "Demon" ascii wide
        $h3 = "DemonMain" ascii
        $h4 = "demon.x64" ascii wide
        $h5 = "demon.x86" ascii wide

        // Havoc internal command IDs
        $cmd1 = "DEMON_COMMAND" ascii wide
        $cmd2 = "DEMON_INIT" ascii wide
        $cmd3 = "CALLBACK_OUTPUT" ascii wide

        // Havoc transport
        $tr1 = "Listener" ascii wide
        $tr2 = "teamserver" ascii wide nocase

        // Havoc specific DLL names
        $dll1 = "demon.dll" ascii wide
        $dll2 = "HavocLoader" ascii wide

    condition:
        (2 of ($h*)) or
        (1 of ($h*) and 1 of ($cmd*)) or
        (1 of ($dll*) and 1 of ($cmd*)) or
        (2 of ($cmd*) and 1 of ($tr*))
}

// ============================================================================
// Brute Ratel C4 Protocol Indicators
// ============================================================================

rule TPJ_C2_BruteRatel_Badger
{
    meta:
        author      = "True Protection by Jag"
        description = "Brute Ratel C4 framework Badger agent patterns"
        severity    = "critical"
        category    = "c2_communication"
        date        = "2026-04-13"

    strings:
        // Brute Ratel identifiers
        $br1 = "BruteRatel" ascii wide nocase
        $br2 = "BRc4" ascii wide nocase
        $br3 = "badger" ascii wide
        $br4 = "brc4_client" ascii wide

        // Brute Ratel shellcode patterns
        $sc1 = { 4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 57 48 83 EC 70 }
        $sc2 = "badger_data" ascii wide

        // Brute Ratel config strings
        $cfg1 = "listeners" ascii wide
        $cfg2 = "auth_key" ascii wide
        $cfg3 = "rportfwd" ascii wide
        $cfg4 = "socks_proxy" ascii wide

        // OPSEC features
        $op1 = "sleep_mask" ascii wide
        $op2 = "syscall" ascii wide
        $op3 = "unhook" ascii wide
        $op4 = "stack_spoof" ascii wide

    condition:
        (2 of ($br*)) or
        (1 of ($br*) and 2 of ($cfg*)) or
        (1 of ($br*) and 2 of ($op*)) or
        (1 of ($sc*) and 1 of ($br*))
}

// ============================================================================
// Generic C2 Encrypted Channel Detection
// ============================================================================

rule TPJ_C2_Encrypted_Channel
{
    meta:
        author      = "True Protection by Jag"
        description = "PE using custom encrypted channels with key exchange for C2"
        severity    = "high"
        category    = "c2_communication"
        mitre_att   = "T1573"
        date        = "2026-04-13"

    strings:
        // Custom crypto for C2 channels
        $cry1 = "AES-256-CBC" ascii wide
        $cry2 = "ChaCha20" ascii wide
        $cry3 = "RC4" ascii wide
        $cry4 = "XOR" ascii wide

        // Key exchange indicators
        $kx1 = "Diffie-Hellman" ascii wide
        $kx2 = "ECDH" ascii wide
        $kx3 = "RSA" ascii wide
        $kx4 = "curve25519" ascii wide nocase

        // Session management
        $ses1 = "session_id" ascii wide
        $ses2 = "session_key" ascii wide
        $ses3 = "handshake" ascii wide
        $ses4 = "heartbeat" ascii wide

        // Network APIs
        $net1 = "WSAStartup" ascii
        $net2 = "socket" ascii
        $net3 = "connect" ascii
        $net4 = "send" ascii
        $net5 = "recv" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($cry*) and 1 of ($kx*) and 2 of ($net*) and 1 of ($ses*)) or
            (2 of ($cry*) and 2 of ($ses*) and 1 of ($net*)) or
            (1 of ($kx*) and 2 of ($ses*) and 2 of ($net*))
        )
}

// ============================================================================
// Named Pipe C2 (SMB-Based Lateral Movement C2)
// ============================================================================

rule TPJ_C2_NamedPipe_Beacon
{
    meta:
        author      = "True Protection by Jag"
        description = "PE using named pipes for C2 communication within a network"
        severity    = "high"
        category    = "c2_communication"
        mitre_att   = "T1071"
        date        = "2026-04-13"

    strings:
        // Named pipe APIs
        $np1 = "CreateNamedPipeA" ascii
        $np2 = "CreateNamedPipeW" ascii
        $np3 = "ConnectNamedPipe" ascii
        $np4 = "WaitNamedPipeA" ascii
        $np5 = "WaitNamedPipeW" ascii
        $np6 = "TransactNamedPipe" ascii
        $np7 = "PeekNamedPipe" ascii

        // Known C2 pipe name patterns
        $pn1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pn2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pn3 = "\\\\.\\pipe\\postex_" ascii wide
        $pn4 = "\\\\.\\pipe\\status_" ascii wide
        $pn5 = "\\\\.\\pipe\\mojo_" ascii wide
        $pn6 = "\\\\.\\pipe\\win_svc" ascii wide
        $pn7 = "\\\\.\\pipe\\ntsvcs" ascii wide
        $pn8 = "\\\\.\\pipe\\scerpc" ascii wide

        // Impersonation after pipe connection
        $imp1 = "ImpersonateNamedPipeClient" ascii
        $imp2 = "RevertToSelf" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($pn*)) or
            (1 of ($np1, $np2) and $np3 and 1 of ($imp*)) or
            (1 of ($pn*) and 2 of ($np*) and 1 of ($imp*))
        )
}

/*
    True Protection by Jag - EICAR Test File Detection
    Detects the EICAR Anti-Malware Test File (standard test string used to
    verify antivirus functionality without using actual malware).

    The EICAR test string is:
    X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

    Reference: https://www.eicar.org/download-anti-malware-testfile/
*/

rule TPJ_Test_EICAR
{
    meta:
        author      = "True Protection by Jag"
        description = "EICAR anti-malware test file"
        severity    = "info"
        category    = "test"
        created     = "2026-03-27"
        reference   = "https://www.eicar.org/"

    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar_string at 0 and
        filesize < 200
}

rule TPJ_Test_EICAR_Anywhere
{
    meta:
        author      = "True Protection by Jag"
        description = "EICAR test string found anywhere in file (may be embedded in archive or container)"
        severity    = "info"
        category    = "test"
        created     = "2026-03-27"
        reference   = "https://www.eicar.org/"

    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar_string and
        not $eicar_string at 0
}

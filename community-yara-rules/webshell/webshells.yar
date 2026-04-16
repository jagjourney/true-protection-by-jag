/*
    True Protection by Jag - Web Shell Detection Rules
    Detects common web shell patterns in PHP, ASP, ASPX, and JSP files.
*/

rule TPJ_Webshell_PHP_Eval
{
    meta:
        author      = "True Protection by Jag"
        description = "PHP web shell using eval/assert with dynamic input"
        severity    = "critical"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        $php_tag    = "<?php" ascii nocase
        // Direct eval of user input
        $eval1      = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        $eval2      = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        // eval with base64 decode
        $eval3      = /eval\s*\(\s*base64_decode\s*\(/ ascii nocase
        $eval4      = /eval\s*\(\s*gzinflate\s*\(/ ascii nocase
        $eval5      = /eval\s*\(\s*gzuncompress\s*\(/ ascii nocase
        $eval6      = /eval\s*\(\s*str_rot13\s*\(/ ascii nocase
        // preg_replace with /e modifier (code execution)
        $preg_e     = /preg_replace\s*\(\s*['"]\/.+\/e['"]/ ascii nocase

    condition:
        $php_tag and
        any of ($eval*, $preg_e)
}

rule TPJ_Webshell_PHP_System
{
    meta:
        author      = "True Protection by Jag"
        description = "PHP web shell executing system commands from user input"
        severity    = "critical"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        $php_tag    = "<?php" ascii nocase
        $input1     = "$_GET" ascii nocase
        $input2     = "$_POST" ascii nocase
        $input3     = "$_REQUEST" ascii nocase
        // Command execution functions
        $cmd1       = "system(" ascii nocase
        $cmd2       = "exec(" ascii nocase
        $cmd3       = "passthru(" ascii nocase
        $cmd4       = "shell_exec(" ascii nocase
        $cmd5       = "popen(" ascii nocase
        $cmd6       = "proc_open(" ascii nocase
        $cmd7       = "`$_" ascii  // backtick execution

    condition:
        $php_tag and
        any of ($input*) and
        any of ($cmd*)
}

rule TPJ_Webshell_PHP_FileOperation
{
    meta:
        author      = "True Protection by Jag"
        description = "PHP web shell with file upload/write capabilities from user input"
        severity    = "high"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        $php_tag      = "<?php" ascii nocase
        $input        = /\$_(GET|POST|REQUEST|FILES)/ ascii nocase
        // File operations
        $file_put     = "file_put_contents" ascii nocase
        $fwrite       = "fwrite(" ascii nocase
        $move_upload  = "move_uploaded_file" ascii nocase
        $file_upload  = "$_FILES" ascii nocase
        // Combined with command execution
        $cmd          = /(system|exec|passthru|shell_exec)\s*\(/ ascii nocase

    condition:
        $php_tag and
        $input and
        (
            ($file_put or $fwrite) and $cmd or
            ($move_upload or $file_upload) and $cmd
        )
}

rule TPJ_Webshell_PHP_Obfuscated
{
    meta:
        author      = "True Protection by Jag"
        description = "Obfuscated PHP web shell using variable function calls or encoding"
        severity    = "critical"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        $php_tag     = "<?php" ascii nocase
        // Variable function patterns
        $var_func1   = /\$\w+\s*\(\s*\$_(GET|POST|REQUEST)/ ascii nocase
        $var_func2   = /\$\{\s*['"]\\x/ ascii nocase
        // String construction obfuscation
        $chr_build   = /chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/ ascii nocase
        // Common obfuscation chains
        $obf_chain   = /base64_decode\s*\(\s*str_rot13/ ascii nocase
        $obf_chain2  = /gzinflate\s*\(\s*base64_decode/ ascii nocase
        // Hex-encoded function names
        $hex_func    = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/ ascii nocase
        // create_function (deprecated but used in webshells)
        $create_func = "create_function" ascii nocase

    condition:
        $php_tag and
        2 of ($var_func*, $chr_build, $obf_chain, $obf_chain2, $hex_func, $create_func)
}

rule TPJ_Webshell_ASP_Execute
{
    meta:
        author      = "True Protection by Jag"
        description = "ASP/ASPX web shell with code execution capabilities"
        severity    = "critical"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        // Classic ASP
        $asp_tag1    = "<%" ascii nocase
        // ASP.NET
        $asp_tag2    = "<%@ Page" ascii nocase
        $asp_tag3    = "<%@ WebHandler" ascii nocase
        // Code execution
        $execute1    = "Execute(" ascii nocase
        $execute2    = "ExecuteGlobal" ascii nocase
        $eval_asp    = "Eval(" ascii nocase
        // Process execution
        $process1    = "Process.Start" ascii nocase
        $process2    = "WScript.Shell" ascii nocase
        $process3    = "cmd.exe" ascii wide nocase
        // Request input
        $request1    = "Request(" ascii nocase
        $request2    = "Request.Form" ascii nocase
        $request3    = "Request.QueryString" ascii nocase
        $request4    = "Request.Item" ascii nocase

    condition:
        ($asp_tag1 or $asp_tag2 or $asp_tag3) and
        any of ($request*) and
        any of ($execute*, $eval_asp, $process*)
}

rule TPJ_Webshell_JSP_Runtime
{
    meta:
        author      = "True Protection by Jag"
        description = "JSP web shell using Runtime.exec() with request parameters"
        severity    = "critical"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        $jsp_tag     = "<%@" ascii nocase
        $jsp_page    = "<%@ page" ascii nocase
        // Runtime execution
        $runtime1    = "Runtime.getRuntime()" ascii nocase
        $runtime2    = "ProcessBuilder" ascii nocase
        // Request parameters
        $request1    = "request.getParameter" ascii nocase
        $request2    = "request.getInputStream" ascii nocase
        // Reflection-based execution
        $reflect1    = "Class.forName" ascii nocase
        $reflect2    = "getMethod" ascii nocase
        $reflect3    = "invoke(" ascii nocase

    condition:
        ($jsp_tag or $jsp_page) and
        any of ($request*) and
        (
            any of ($runtime*) or
            (2 of ($reflect*))
        )
}

rule TPJ_Webshell_Generic_Indicators
{
    meta:
        author      = "True Protection by Jag"
        description = "Generic web shell indicators: password protection, file management, DB access"
        severity    = "high"
        category    = "webshell"
        created     = "2026-03-27"

    strings:
        // Common web shell names/titles
        $title1      = "c99shell" ascii wide nocase
        $title2      = "r57shell" ascii wide nocase
        $title3      = "b374k" ascii wide nocase
        $title4      = "WSO " ascii wide nocase
        $title5      = "FilesMan" ascii wide nocase
        $title6      = "phpspy" ascii wide nocase
        $title7      = "webadmin" ascii wide nocase
        $title8      = "phpremoteview" ascii wide nocase
        $title9      = "Network Shell" ascii wide nocase
        $title10     = "China Chopper" ascii wide nocase
        // Password checks common in web shells
        $auth1       = "md5($_POST[" ascii nocase
        $auth2       = "md5($_GET[" ascii nocase
        $auth3       = /if\s*\(\s*\$_POST\[.{1,20}\]\s*==\s*['"]/ ascii nocase

    condition:
        any of ($title*) or
        any of ($auth*)
}

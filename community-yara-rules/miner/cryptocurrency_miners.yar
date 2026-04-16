/*
    True Protection by Jag - Cryptocurrency Miner Detection Rules
    Detects known crypto miners, mining protocols, GPU mining indicators,
    and browser-based mining scripts.
    Copyright (C) 2026 Jag Journey, LLC - GPLv3
    Powered by JagAI
*/

import "pe"

// ============================================================================
// XMRig and Variants
// ============================================================================

rule TPJ_Miner_XMRig_Strings
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects XMRig miner by characteristic strings"
        severity    = "high"
        category    = "cryptominer"
        family      = "xmrig"
        created     = "2026-03-27"

    strings:
        $x1 = "xmrig" ascii wide nocase
        $x2 = "XMRig" ascii wide
        $x3 = "xmrig-proxy" ascii wide nocase
        $x4 = "xmrig-nvidia" ascii wide nocase
        $x5 = "xmrig-amd" ascii wide nocase

        // XMRig configuration keys
        $cfg1 = "\"algo\"" ascii
        $cfg2 = "\"coin\"" ascii
        $cfg3 = "\"url\"" ascii
        $cfg4 = "\"user\"" ascii
        $cfg5 = "\"pass\"" ascii
        $cfg6 = "\"rig-id\"" ascii
        $cfg7 = "\"donate-level\"" ascii
        $cfg8 = "\"randomx\"" ascii

        // XMRig internal identifiers
        $int1 = "cryptonight" ascii nocase
        $int2 = "randomx" ascii nocase
        $int3 = "argon2" ascii nocase
        $int4 = "rx/0" ascii
        $int5 = "cn/r" ascii
        $int6 = "cn-heavy" ascii
        $int7 = "rx/wow" ascii
        $int8 = "cn/fast" ascii
        $int9 = "kawpow" ascii nocase
        $int10 = "ghostrider" ascii nocase

    condition:
        (2 of ($x*)) or
        (1 of ($x*) and 3 of ($cfg*)) or
        (1 of ($x*) and 2 of ($int*)) or
        (4 of ($cfg*) and 2 of ($int*))
}

rule TPJ_Miner_XMRig_PE
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects XMRig miner as a PE executable"
        severity    = "high"
        category    = "cryptominer"
        family      = "xmrig"
        created     = "2026-03-27"

    strings:
        $s1 = "xmrig" ascii wide nocase
        $s2 = "stratum+tcp://" ascii wide
        $s3 = "stratum+ssl://" ascii wide
        $s4 = "donate.v2.xmrig.com" ascii wide
        $s5 = "randomx_vm" ascii
        $s6 = "cn_gpu" ascii
        $s7 = "\"donate-over-proxy\"" ascii
        $s8 = "hwloc" ascii
        $s9 = "MSR mod" ascii

    condition:
        pe.is_pe and
        (2 of ($s*)) and
        pe.number_of_sections >= 3
}

// ============================================================================
// CoinHive and Browser Miners
// ============================================================================

rule TPJ_Miner_CoinHive
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects CoinHive browser-based cryptocurrency miner"
        severity    = "high"
        category    = "cryptominer"
        family      = "coinhive"
        created     = "2026-03-27"

    strings:
        $s1 = "coinhive" ascii wide nocase
        $s2 = "CoinHive.Anonymous" ascii wide
        $s3 = "CoinHive.Token" ascii wide
        $s4 = "CoinHive.User" ascii wide
        $s5 = "coinhive.min.js" ascii wide nocase
        $s6 = "coin-hive.com" ascii wide nocase
        $s7 = "authedmine.com" ascii wide nocase
        $s8 = "new CoinHive.Anonymous" ascii wide
        $s9 = "CoinHive.CONFIG" ascii wide

        // CoinHive API patterns
        $api1 = ".start()" ascii
        $api2 = ".setThrottle(" ascii
        $api3 = "setNumThreads" ascii
        $api4 = "getMinerData" ascii

    condition:
        2 of ($s*) or
        (1 of ($s*) and 2 of ($api*))
}

rule TPJ_Miner_CryptoLoot
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects CryptoLoot browser miner"
        severity    = "high"
        category    = "cryptominer"
        family      = "cryptoloot"
        created     = "2026-03-27"

    strings:
        $s1 = "cryptoloot" ascii wide nocase
        $s2 = "crypto-loot.com" ascii wide nocase
        $s3 = "CryptoLoot.Anonymous" ascii wide
        $s4 = "CRLT.Anonymous" ascii wide
        $s5 = "crlt.js" ascii wide nocase
        $s6 = "cryptoloot.pro" ascii wide nocase
        $s7 = "webmine.cz" ascii wide nocase

    condition:
        2 of ($s*)
}

rule TPJ_Miner_JSEcoin
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects JSEcoin browser-based miner"
        severity    = "high"
        category    = "cryptominer"
        family      = "jsecoin"
        created     = "2026-03-27"

    strings:
        $s1 = "jsecoin" ascii wide nocase
        $s2 = "JSEcoin" ascii wide
        $s3 = "load.jsecoin.com" ascii wide nocase
        $s4 = "server.jsecoin.com" ascii wide nocase
        $s5 = "jsecoin.min.js" ascii wide nocase
        $s6 = "startMining" ascii
        $s7 = "platform.jsecoin.com" ascii wide nocase

    condition:
        2 of ($s*)
}

rule TPJ_Miner_BrowserMiner_Generic
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects generic browser-based miners and WebAssembly mining"
        severity    = "high"
        category    = "cryptominer"
        family      = "browser_miner"
        created     = "2026-03-27"

    strings:
        // Common browser miner domains and scripts
        $dom1 = "deepminer" ascii wide nocase
        $dom2 = "webminepool.com" ascii wide nocase
        $dom3 = "papoto.com" ascii wide nocase
        $dom4 = "coinlab.biz" ascii wide nocase
        $dom5 = "monerominer" ascii wide nocase
        $dom6 = "perfekt.cc" ascii wide nocase
        $dom7 = "minero.cc" ascii wide nocase
        $dom8 = "coin-have.com" ascii wide nocase
        $dom9 = "ppoi.org" ascii wide nocase
        $dom10 = "cryptonight.wasm" ascii wide nocase

        // WebAssembly mining patterns
        $wasm1 = "WebAssembly.instantiate" ascii
        $wasm2 = "WebAssembly.compile" ascii
        $wasm3 = ".wasm" ascii

        // Mining-specific JavaScript patterns
        $js1 = "startMining" ascii
        $js2 = "stopMining" ascii
        $js3 = "throttleMiner" ascii
        $js4 = "CryptoNight" ascii
        $js5 = "hashesPerSecond" ascii
        $js6 = "getTotalHashes" ascii
        $js7 = "getHashesPerSecond" ascii
        $js8 = "miner.start" ascii

        // Worker-based mining
        $wkr1 = "Worker(" ascii
        $wkr2 = "postMessage" ascii
        $wkr3 = "onmessage" ascii

    condition:
        (2 of ($dom*)) or
        (1 of ($dom*) and 2 of ($js*)) or
        (1 of ($wasm*) and $wasm3 and 3 of ($js*)) or
        (3 of ($js*) and 2 of ($wkr*) and 1 of ($dom*, $wasm*))
}

// ============================================================================
// Stratum Mining Protocol
// ============================================================================

rule TPJ_Miner_Stratum_Protocol
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Stratum mining protocol strings"
        severity    = "high"
        category    = "cryptominer"
        family      = "stratum"
        created     = "2026-03-27"

    strings:
        // Stratum protocol methods (JSON-RPC)
        $m1 = "mining.subscribe" ascii wide
        $m2 = "mining.authorize" ascii wide
        $m3 = "mining.submit" ascii wide
        $m4 = "mining.notify" ascii wide
        $m5 = "mining.set_difficulty" ascii wide
        $m6 = "mining.set_extranonce" ascii wide
        $m7 = "mining.set_target" ascii wide
        $m8 = "mining.get_transactions" ascii wide

        // Stratum V2 patterns
        $sv2_1 = "mining.configure" ascii wide
        $sv2_2 = "mining.set_version_mask" ascii wide

        // Stratum connection strings
        $url1 = "stratum+tcp://" ascii wide
        $url2 = "stratum+ssl://" ascii wide
        $url3 = "stratum+udp://" ascii wide
        $url4 = "stratum2+tcp://" ascii wide

        // Common mining pool ports in strings
        $port1 = ":3333" ascii wide
        $port2 = ":4444" ascii wide
        $port3 = ":5555" ascii wide
        $port4 = ":7777" ascii wide
        $port5 = ":8888" ascii wide
        $port6 = ":9999" ascii wide
        $port7 = ":14444" ascii wide
        $port8 = ":45700" ascii wide

    condition:
        (2 of ($m*)) or
        (1 of ($url*) and 1 of ($m*)) or
        (1 of ($url*) and 1 of ($port*) and 1 of ($m*, $sv2_*))
}

rule TPJ_Miner_Pool_Domains
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects connections to known mining pool domains"
        severity    = "medium"
        category    = "cryptominer"
        family      = "mining_pool"
        created     = "2026-03-27"

    strings:
        // Major Monero pools
        $pool1  = "pool.minexmr.com" ascii wide nocase
        $pool2  = "pool.supportxmr.com" ascii wide nocase
        $pool3  = "xmr.nanopool.org" ascii wide nocase
        $pool4  = "monerohash.com" ascii wide nocase
        $pool5  = "xmrpool.eu" ascii wide nocase
        $pool6  = "moneroocean.stream" ascii wide nocase

        // Multi-coin pools
        $pool7  = "pool.hashvault.pro" ascii wide nocase
        $pool8  = "mining.pool" ascii wide nocase
        $pool9  = "pool.minergate.com" ascii wide nocase
        $pool10 = "minergate.com" ascii wide nocase
        $pool11 = "nicehash.com" ascii wide nocase
        $pool12 = "f2pool.com" ascii wide nocase
        $pool13 = "antpool.com" ascii wide nocase
        $pool14 = "viabtc.com" ascii wide nocase
        $pool15 = "2miners.com" ascii wide nocase
        $pool16 = "ethermine.org" ascii wide nocase
        $pool17 = "unmineable.com" ascii wide nocase

        // Wallet address patterns (Monero addresses start with 4)
        $wallet1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        // Ethereum addresses
        $wallet2 = /0x[0-9a-fA-F]{40}/ ascii

    condition:
        2 of ($pool*) or
        (1 of ($pool*) and 1 of ($wallet*))
}

// ============================================================================
// GPU Mining Indicators (OpenCL / CUDA)
// ============================================================================

rule TPJ_Miner_GPU_OpenCL
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects GPU mining via OpenCL patterns"
        severity    = "high"
        category    = "cryptominer"
        family      = "gpu_miner"
        created     = "2026-03-27"

    strings:
        // OpenCL API calls associated with mining
        $ocl1 = "clCreateContext" ascii
        $ocl2 = "clCreateCommandQueue" ascii
        $ocl3 = "clCreateBuffer" ascii
        $ocl4 = "clBuildProgram" ascii
        $ocl5 = "clCreateKernel" ascii
        $ocl6 = "clEnqueueNDRangeKernel" ascii
        $ocl7 = "clGetPlatformIDs" ascii
        $ocl8 = "clGetDeviceIDs" ascii
        $ocl9 = "CL_DEVICE_TYPE_GPU" ascii

        // Mining-specific OpenCL kernels
        $kern1 = "cryptonight" ascii nocase
        $kern2 = "ethash" ascii nocase
        $kern3 = "equihash" ascii nocase
        $kern4 = "blake2b" ascii nocase
        $kern5 = "sha256d" ascii nocase
        $kern6 = "scrypt" ascii nocase
        $kern7 = "__kernel" ascii
        $kern8 = "__global" ascii

        // Mining algorithm identifiers alongside GPU code
        $algo1 = "RandomX" ascii
        $algo2 = "KawPow" ascii
        $algo3 = "ProgPoW" ascii
        $algo4 = "Autolykos" ascii

    condition:
        (4 of ($ocl*) and 1 of ($kern1, $kern2, $kern3, $algo*)) or
        (3 of ($ocl*) and 2 of ($kern*) and 1 of ($algo*))
}

rule TPJ_Miner_GPU_CUDA
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects GPU mining via CUDA patterns"
        severity    = "high"
        category    = "cryptominer"
        family      = "gpu_miner"
        created     = "2026-03-27"

    strings:
        // CUDA API calls
        $cuda1 = "cudaMalloc" ascii
        $cuda2 = "cudaMemcpy" ascii
        $cuda3 = "cudaDeviceSynchronize" ascii
        $cuda4 = "cudaSetDevice" ascii
        $cuda5 = "cudaGetDeviceCount" ascii
        $cuda6 = "cudaGetDeviceProperties" ascii
        $cuda7 = "cudaFree" ascii
        $cuda8 = "cuLaunchKernel" ascii

        // CUDA mining kernel patterns
        $ckern1 = "__global__" ascii
        $ckern2 = "<<<" ascii       // CUDA kernel launch syntax
        $ckern3 = "threadIdx" ascii
        $ckern4 = "blockIdx" ascii
        $ckern5 = "blockDim" ascii

        // Mining algorithm names alongside CUDA
        $malgo1 = "cryptonight" ascii nocase
        $malgo2 = "ethash" ascii nocase
        $malgo3 = "randomx" ascii nocase
        $malgo4 = "kawpow" ascii nocase
        $malgo5 = "equihash" ascii nocase

        // NVML GPU management (used by miners to control fans, clocks)
        $nvml1 = "nvmlDeviceGetHandleByIndex" ascii
        $nvml2 = "nvmlDeviceGetTemperature" ascii
        $nvml3 = "nvmlDeviceGetFanSpeed" ascii

    condition:
        (3 of ($cuda*) and 1 of ($malgo*)) or
        (2 of ($cuda*) and 2 of ($ckern*) and 1 of ($malgo*)) or
        (2 of ($nvml*) and 1 of ($malgo*) and 1 of ($cuda*))
}

// ============================================================================
// Embedded Miner Detection (dropper / loader patterns)
// ============================================================================

rule TPJ_Miner_Embedded_Config
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects embedded mining configuration (JSON config in binary)"
        severity    = "high"
        category    = "cryptominer"
        family      = "embedded_miner"
        created     = "2026-03-27"

    strings:
        // JSON configuration patterns typical of miners
        $j1 = "\"pools\"" ascii
        $j2 = "\"algo\"" ascii
        $j3 = "\"coin\"" ascii
        $j4 = "\"url\"" ascii
        $j5 = "\"user\"" ascii
        $j6 = "\"pass\"" ascii
        $j7 = "\"threads\"" ascii
        $j8 = "\"donate-level\"" ascii
        $j9 = "\"max-cpu-usage\"" ascii
        $j10 = "\"cpu-priority\"" ascii
        $j11 = "\"background\"" ascii
        $j12 = "\"huge-pages\"" ascii

        // Pool URL in the config
        $pool_url = /stratum\+[a-z]{3}:\/\/[a-zA-Z0-9\.\-]+:[0-9]+/ ascii

    condition:
        ($pool_url and 3 of ($j*)) or
        (5 of ($j*) and ($j1 or $j2))
}

rule TPJ_Miner_WannaMine
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects WannaMine cryptomining worm"
        severity    = "critical"
        category    = "cryptominer"
        family      = "wannamine"
        created     = "2026-03-27"

    strings:
        $s1 = "WannaMine" ascii wide nocase
        $s2 = "EternalBlue" ascii wide nocase
        $s3 = "ms17-010" ascii wide nocase
        $s4 = "DoublePulsar" ascii wide nocase
        $s5 = "mimikatz" ascii wide nocase
        $s6 = "stratum" ascii wide
        $s7 = "monero" ascii wide nocase

        // PowerShell spreading patterns
        $ps1 = "Invoke-SMBClient" ascii wide nocase
        $ps2 = "Invoke-TheHash" ascii wide nocase
        $ps3 = "Invoke-WMIExec" ascii wide nocase

    condition:
        (3 of ($s*)) or
        (2 of ($ps*) and 1 of ($s6, $s7))
}

// ============================================================================
// Linux-Specific Miner Indicators
// ============================================================================

rule TPJ_Miner_Linux_Dropper
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects Linux crypto miner dropper scripts"
        severity    = "high"
        category    = "cryptominer"
        family      = "linux_miner"
        created     = "2026-03-27"

    strings:
        // Common bash patterns used by miner droppers
        $sh1 = "#!/bin/bash" ascii
        $sh2 = "#!/bin/sh" ascii

        // Kill competing miners
        $kill1 = "pkill -f" ascii
        $kill2 = "killall" ascii
        $kill3 = "xmrig" ascii nocase
        $kill4 = "minerd" ascii nocase
        $kill5 = "kdevtmpfsi" ascii

        // Persistence mechanisms
        $pers1 = "crontab" ascii
        $pers2 = "/etc/cron" ascii
        $pers3 = "systemctl" ascii
        $pers4 = ".service" ascii

        // Download and execute
        $dl1 = "wget" ascii
        $dl2 = "curl" ascii
        $dl3 = "chmod +x" ascii
        $dl4 = "chmod 777" ascii

        // Mining indicators
        $mine1 = "stratum" ascii
        $mine2 = "pool" ascii
        $mine3 = "xmr" ascii nocase
        $mine4 = "monero" ascii nocase

    condition:
        (1 of ($sh*)) and
        (1 of ($kill*) and $kill3) and
        (1 of ($dl*)) and
        (1 of ($mine*))
}

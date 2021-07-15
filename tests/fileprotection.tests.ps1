#Requires -Modules @{'ModuleName' = 'Pester'; 'ModuleVersion' = '5.2.2';}

describe 'CATEncryptor - File Protection' {
    BeforeAll {
        $moduleName = 'CATEncryptor'

        $root = if ([string]::IsNullOrEmpty($env:Build_SourcesDirectory)) {
            "$PSScriptRoot\.."
        }
        else {
            $env:Build_SourcesDirectory
        }
        Import-Module "$root\src\bin\Debug\netstandard2.0\$moduleName.dll" -Force

        $controlPlaintextPath = "$root\tests\data.csv"
        $plaintextPath = "TestDrive:\data.csv"
        $controlImagePath = "$root\tests\catfacts.png"
        $imagePath = "TestDrive:\catfacts.png"

        $defaultEncryptedPlaintext = "TestDrive:\data.csv.encrypted"
        $defaultDecryptedPlaintext = "TestDrive:\decrypted_data.csv"
        $specificEncryptedPlaintext = "TestDrive:\data.csv.enc"
        $specificDecryptedPlaintext = "TestDrive:\decryptedfile.csv"
        $defaultEncryptedImage = "TestDrive:\catfacts.png.encrypted"
        $defaultDecryptedImage = "TestDrive:\decrypted_catfacts.png"
        $specificEncryptedImage = "TestDrive:\catfacts.png.enc"
        $specificDecryptedImage = "TestDrive:\decryptedimg.png"

        $certLocation = 'Cert:\CurrentUser\My'
        $testCertificate = New-SelfSignedCertificate -DnsName 'FileProtection' -CertStoreLocation $certLocation -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy Exportable -KeyProtection None -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'

        Copy-Item $controlPlaintextPath $plaintextPath
        Copy-Item $controlImagePath $imagePath
    }

    AfterAll {        
        Remove-Module $moduleName -Force
        Remove-Item $(Join-Path $certLocation $testCertificate.Thumbprint)
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
        BeforeAll {
            Protect-File -Path $plaintextPath -Certificate $testCertificate
            Protect-File -Path $plaintextPath -Certificate $testCertificate -OutFile $specificEncryptedPlaintext
        }

        it 'decrypts file with default OutFile value' {
            Protect-File -Path $plaintextPath -Certificate $testCertificate
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
        BeforeAll {
            Protect-File -Path $imagePath -Certificate $testCertificate
            Protect-File -Path $imagePath -Certificate $testCertificate -OutFile $specificEncryptedImage
        }

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

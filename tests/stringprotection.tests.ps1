#Requires -Modules @{'ModuleName' = 'Pester'; 'ModuleVersion' = '5.2.2';}

describe 'CATEncryptor - String Protection' {
    BeforeAll {
        $moduleName = 'CATEncryptor'

        $root = if ([string]::IsNullOrEmpty($env:Build_SourcesDirectory)) {
            $PSScriptRoot
        }
        else {
            $env:Build_SourcesDirectory
        }
        Import-Module "$root\..\src\bin\Debug\netstandard2.0\$moduleName.dll" -Force

        $plainText = 'this is a big ol secret'
        $unicodePlaintext = 'this Π symbol means pi'

        $certLocation = 'Cert:\CurrentUser\My'
        $testCertificate = New-SelfSignedCertificate -DnsName 'StringProtection' -CertStoreLocation $certLocation -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy Exportable -KeyProtection None -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'
    }

    AfterAll {        
        Remove-Module $moduleName -Force
        Remove-Item $(Join-Path $certLocation $testCertificate.Thumbprint)
    }

    context 'Protect and Unprotect-String - normal chars' {
        it 'encrypts a string' {
            $encryptedText = Protect-String -Plaintext $plainText -Certificate $testCertificate
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encryptedText))

            $decoded -NotMatch 'big' | Should -Be $true
            $encryptedText -NotMatch 'big' | Should -Be $true
        }

        it 'decrypts a string' {
            $encryptedText = Protect-String -Plaintext $plainText -Certificate $testCertificate
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encryptedText))
            $decoded -NotMatch 'big' | Should -Be $true

            $decryptedText = Unprotect-String -Ciphertext $encryptedText -Certificate $testCertificate
            $decryptedText | Should -Be $plainText
        }
    }

    context 'Protect and Unprotect-String - including odd unicode chars' {
        it 'encrypts when there are non-standard unicode characters present' {
            $encryptedText = Protect-String -Plaintext $unicodePlaintext -Certificate $testCertificate
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encryptedText))

            $decoded -NotMatch 'symbol' | Should -Be $true
            $encryptedText -NotMatch 'symbol' | Should -Be $true
        }

        it 'decrypt preserves non-standard unicode characters' {
            $encryptedText = Protect-String -Plaintext $unicodePlaintext -Certificate $testCertificate
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encryptedText))
            $decoded -NotMatch 'symbol' | Should -Be $true

            $decryptedText = Unprotect-String -Ciphertext $encryptedText -Certificate $testCertificate
            $decryptedText | Should -Be $unicodePlaintext
        }
    }
}

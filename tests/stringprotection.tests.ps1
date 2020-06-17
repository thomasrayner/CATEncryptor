#Requires -Modules @{'ModuleName' = 'Pester'; 'ModuleVersion' = '5.0.1';}

describe 'CATEncryptor' {
    BeforeAll {
        $moduleName = 'CATEncryptor'

        Import-Module "$PSScriptRoot\..\src\bin\Debug\netstandard2.0\$moduleName.dll" -Force

        $plainText = 'this is a big ol secret'

        $certLocation = 'Cert:\CurrentUser\My'
        $testCertificate = New-SelfSignedCertificate -DnsName 'FileProtection' -CertStoreLocation $certLocation -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy Exportable -KeyProtection None -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'
    }

    AfterAll {        
        Remove-Module $moduleName -Force
        Remove-Item $(Join-Path $certLocation $testCertificate.Thumbprint)
    }

    context 'Protect and Unprotect-String' {
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
}

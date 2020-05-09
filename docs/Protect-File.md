---
external help file: CATEncryptor.dll-Help.xml
Module Name: CATEncryptor
online version:
schema: 2.0.0
---

# Protect-File

## SYNOPSIS
Encrypts a given file using an installed certificate chosen by the user.

## SYNTAX

```
Protect-File [-Path] <String> [[-OutFile] <String>] [-Certificate] <X509Certificate2> [<CommonParameters>]
```

## DESCRIPTION
Uses RSA encryption and a user-specified certificate to encrypt a file.

## EXAMPLES

### Example 1

```powershell
PS C:\> $cert = New-SelfSignedCertificate -DnsName $CertName -CertStoreLocation $CertificateStoreLocation  -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy Exportable -KeyProtection None -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'

PS C:\> Protect-File -Path 'C:\Temp\CatFacts.png' -Certificate $cert
```

Encrypt the file "C:\Temp\CatFacts.png" with the certificate created and stored in $cert. The encrypted file is created at "C:\Temp\CatFacts.png.encrypted".

### Example 2

```powershell
PS C:\> $cert = Get-Item "Cert:\CurrentUser\My\$thumbprint"

PS C:\> Protect-File -Path 'C:\Temp\CatFacts.png' -OutFile 'C:\Temp\cat.enc' -Certificate $cert
```

Encrypt the file "C:\Temp\CatFacts.png" with the certificate whose thumbprint is $thumpbrint, and in the CurrentUser personal store, and stored in $cert. The encrypted file is created at "C:\Temp\cat.enc".

## PARAMETERS

### -Certificate

The X509Certificate2 object (a certificate) that will be used to perform the file encryption.

```yaml
Type: X509Certificate2
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutFile

The path to where the encrypted file will be output. If blank, it defaults to the name of the unencrypted file with ".encrypted" appended.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Path

The path to the unencrypted file that is to be encrypted.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String

## OUTPUTS

### System.Object

## NOTES

## RELATED LINKS

---
external help file: CATEncryptor.dll-Help.xml
Module Name: CATEncryptor
online version:
schema: 2.0.0
---

# Protect-String

## SYNOPSIS

Encrypts a given string using an installed certificate chosen by the user.

## SYNTAX

```
Protect-String [-Plaintext] <String> [-Certificate] <X509Certificate2> [<CommonParameters>]
```

## DESCRIPTION
Uses RSA encryption and a user-specified certificate to encrypt a string, returns it after base64 encoding to prevent issues rendering the encrypted ciphertext in a console.

## EXAMPLES

### Example 1

```powershell
PS C:\> $cert = New-SelfSignedCertificate -DnsName $CertName -CertStoreLocation $CertificateStoreLocation  -KeyAlgorithm RSA -KeyLength 4096 -KeyExportPolicy Exportable -KeyProtection None -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'

PS C:\> Protect-String -Plaintext 'hello world' -Certificate $cert
```

Encrypt the text "hello world" with the certificate created and stored in $cert. The encrypted text is then base64 encoded before it is returned in order to prevent issues rendering odd characters in a console.

## PARAMETERS

### -Certificate

The X509Certificate2 object (a certificate) that will be used to perform the file encryption.


```yaml
Type: X509Certificate2
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Plaintext

The plaintext string to be encrypted.

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

---
external help file: CATEncryptor.dll-Help.xml
Module Name: CATEncryptor
online version:
schema: 2.0.0
---

# Unprotect-String

## SYNOPSIS

Decrypts a string that was encrypted with Protect-String, using an installed certificate chosen by the user.

## SYNTAX

```powershell
Unprotect-String [-CiphertextBase64] <String> [-Certificate] <X509Certificate2> [<CommonParameters>]
```

## DESCRIPTION

Uses RSA encryption and a user-specified certificate to decrypt a file that was encrypted with Protect-File.

## EXAMPLES

### Example 1

```powershell
PS C:\> $cert = Get-Item "Cert:\CurrentUser\My\$thumbprint"

PS C:\> Unprotect-String -CivertextBase64 $encryptedString -Certificate $cert
```

The encrypted (and base64 encoded) string stored in $encryptedString (which was encrypted with Protect-String) will be decrypted with the certificate it was encrypted with (stored in $cert) and written to the output stream as plaintext.

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

### -CiphertextBase64

The base64 encoded string which was encrypted with Protect-String to be decrypted.


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

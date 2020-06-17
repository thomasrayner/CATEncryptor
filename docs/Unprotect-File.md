---
external help file: CATEncryptor.dll-Help.xml
Module Name: CATEncryptor
online version:
schema: 2.0.0
---

# Unprotect-File

## SYNOPSIS

Decrypts a file that was encrypted with Protect-File, using an installed certificate chosen by the user.

## SYNTAX

```powershell
Unprotect-File [-Path] <String> [[-OutFile] <String>] [-Certificate] <X509Certificate2> [<CommonParameters>]
```

## DESCRIPTION

Uses RSA encryption and a user-specified certificate to decrypt a file that was encrypted with Protect-File.

## EXAMPLES

### Example 1

```powershell
PS C:\> $cert = Get-Item "Cert:\CurrentUser\My\$thumbprint"

PS C:\> Unprotect-File -Path 'C:\Temp\CatFacts.png.encrypted' -Certificate $cert
```

The encrypted file "C:\Temp\CatFacts.png.encrypted" will be decrypted with the certificate it was encrypted with (stored in $cert). The decrypted file will be stored at "C:\Temp\decrypted_CatFacts.png".

### Example 2

```powershell
PS C:\> $cert = Get-Item "Cert:\CurrentUser\My\$thumbprint"

PS C:\> Protect-File -Path 'C:\Temp\CatFacts.png' -OutFile 'C:\Temp\cat.enc' -Certificate $cert
```

The encrypted file "C:\Temp\CatFacts.png.encrypted" will be decrypted with the certificate it was encrypted with (stored in $cert). The decrypted file will be stored at "C:\Temp\cat.png".

## PARAMETERS

### -Certificate

The X509Certificate2 object (a certificate) that will be used to perform the file decryption.

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

The path to where the decrypted file will be output. If blank, it defaults to the name of the encrypted file with "decrypted_" prepended, and any ".encrypted" extension removed.

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

The path to the encrypted file to be decrypted.

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

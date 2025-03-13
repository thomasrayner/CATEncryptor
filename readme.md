# CATEncryptor

CATEncryptor is a PowerShell module that enables encryption and decryption of strings and files using arbitrary X.509 certificates. This approach leverages the robust security features inherent in X.509 certificates, providing a flexible and secure method for data protection within PowerShell environments.

## Features

- **String Encryption/Decryption**: Securely encrypt and decrypt strings using specified X.509 certificates.
- **File Encryption/Decryption**: Protect file contents through encryption and decryption operations with X.509 certificates.
- **Certificate-Based Security**: Utilize any arbitrary X.509 certificate for encryption processes, enhancing security and flexibility.

## Encryption Approach

CATEncryptor employs a hybrid encryption strategy, combining asymmetric and symmetric encryption methods to securely protect data in a way that's similar to SSL/TLS (the cryptography behind HTTPS). Here's an overview of the process:

1. **Symmetric Encryption with AES**: Initially, CATEncryptor utilizes the Advanced Encryption Standard (AES) algorithm to encrypt the actual data. AES is a symmetric encryption algorithm, meaning it uses the same key for both encryption and decryption. It is renowned for its efficiency and security, making it suitable for encrypting large datasets.

2. **Asymmetric Encryption of the AES Key with RSA**: To securely share the AES key, CATEncryptor employs RSA, an asymmetric encryption algorithm that uses a pair of keys — a public key for encryption and a private key for decryption. The AES key is encrypted using the recipient's RSA public key, ensuring that only the holder of the corresponding RSA private key can decrypt and access the AES key. **This public/private key pair is where your provided X.509 certificate comes into play.**

3. **Packaging Encrypted Data**: The encrypted AES key, along with the AES initialization vector (IV), is prepended to the AES-encrypted data. This packaging allows the recipient to retrieve the necessary components to decrypt the data.

4. **Decryption Process**: Upon receiving the encrypted package, the recipient uses their RSA private key to decrypt the AES key. With the decrypted AES key and IV, they can then decrypt the data using AES, restoring it to its original form.

This method leverages the strengths of both encryption types: the speed and efficiency of symmetric encryption for data processing, and the secure key distribution capabilities of asymmetric encryption. This is effectively how HTTPS works, but applied to local data like strings and files instead of HTTP connections.

## Requirements

- **PowerShell**: Ensure that PowerShell is installed on your system.
- **X.509 Certificate**: An X.509 certificate is required for encryption and decryption operations. This can be a self-signed certificate or one issued by a trusted certificate authority.

## Installation

Install CATEncryptor from the [PowerShell Gallery](https://www.powershellgallery.com/packages/CATEncryptor) using this command:

```powershell
Install-Module -Name CATEncryptor
```

## Usage

For information on using the CATEncryptor module to encrypt and decrypt strings and files, refer to the [module's documentation](./docs/).

### Providing a Certificate

To use CATEncryptor, you need to provide an X.590 certificate. You can do this by using the PowerShell `Get-Item` command. For example:

```powershell
$cert = Get-Item Cert:\CurrentUser\My\<Thumbprint>
```

Replace `<Thumbprint>` with the actual thumbprint of your X.509 certificate.

Then, you can use the `$cert` variable in your encryption and decryption commands. For example:

```powershell
# Encrypt a file
Protect-File -Path 'c:\temp\catfacts.png' -OutFile 'c:\temp\catfacts.png.enc' -Certificate $cert
```

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests to enhance the functionality of this module. Be advised, however, that this project was originally created in a few days during a hackathon by one dev, and it's not a full-time project. As such, it may not be actively maintained or updated. However, any contributions to improve the module are appreciated.


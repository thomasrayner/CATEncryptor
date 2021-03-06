using System;
using System.Management.Automation;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Linq;

namespace CATEncryptor
{
    [Cmdlet(VerbsSecurity.Protect, "File")]
    public class ProtectFile : PSCmdlet
    {
        private string fullPath;

        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0)]
        public string Path
        {
            get => fullPath;
            set
            {
                var resolvedPaths = SessionState.Path.GetResolvedPSPathFromPSPath(value);
                if (resolvedPaths.Count > 1)
                {
                    throw new ArgumentException(string.Format(
                        "Unable to resolve argument for parameter {0} to a single file path.", nameof(Path)));
                }

                fullPath = resolvedPaths[0].Path;
            }
        }

        [Parameter(
            ValueFromPipelineByPropertyName = true,
            Position = 1)]
        public string OutFile { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 2)]
        public X509Certificate2 Certificate { get; set; }

        protected override void ProcessRecord()
        {
            string outPath = string.IsNullOrEmpty(OutFile) ? fullPath + ".encrypted" : OutFile;
            WriteVerbose($"Encrypting file at {fullPath}, output at {outPath}");

            var resolvedFullPathInfo = this.SessionState.Path.GetResolvedPSPathFromPSPath(fullPath).First();
            string resolvedFullPath = resolvedFullPathInfo.ProviderPath;

            if (resolvedFullPathInfo.Provider.ImplementingType.Name != "FileSystemProvider")
            {
                throw new FileNotFoundException($"The file {fullPath} is not located on a FileSystemProvider type of PSProvider");
            }

            ProviderInfo resolvedOutProviderInfo;
            PSDriveInfo resolvedOutDriveInfo;
            string resolvedOutPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(outPath, out resolvedOutProviderInfo, out resolvedOutDriveInfo);

            if (resolvedOutProviderInfo.ImplementingType.Name != "FileSystemProvider")
            {
                throw new FileNotFoundException($"The file {outPath} is not located on a FileSystemProvoder type of PSProvider");
            }

            CATEncryptor cat = new CATEncryptor();
            cat.Encrypt(resolvedFullPath, resolvedOutPath, Certificate.PublicKey.Key);
        }
    }

    [Cmdlet(VerbsSecurity.Unprotect, "File")]
    public class UnprotectFile : PSCmdlet
    {
        private string fullPath;

        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0)]
        public string Path
        {
            get => fullPath;
            set
            {
                var resolvedPaths = SessionState.Path.GetResolvedPSPathFromPSPath(value);
                if (resolvedPaths.Count > 1)
                {
                    throw new ArgumentException(string.Format(
                        "Unable to resolve argument for parameter {0} to a single file path.", nameof(Path)));
                }

                fullPath = resolvedPaths[0].Path;
            }
        }

        [Parameter(
            ValueFromPipelineByPropertyName = true,
            Position = 1)]
        public string OutFile { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 2)]
        public X509Certificate2 Certificate { get; set; }

        protected override void ProcessRecord()
        {
            var resolvedFullPathInfo = this.SessionState.Path.GetResolvedPSPathFromPSPath(fullPath).First();
            string resolvedFullPath = resolvedFullPathInfo.ProviderPath;

            if (resolvedFullPathInfo.Provider.ImplementingType.Name != "FileSystemProvider")
            {
                throw new FileNotFoundException($"The file {fullPath} is not located on a FileSystemProvider type of PSProvider");
            }

            string outPath = OutFile;

            if (string.IsNullOrEmpty(OutFile))
            {
                string fileName = System.IO.Path.GetFileName(resolvedFullPath);
                string dirName = System.IO.Path.GetDirectoryName(resolvedFullPath);
                outPath = System.IO.Path.Combine(dirName, "decrypted_" + Regex.Replace(fileName, @"\.encrypted", string.Empty, RegexOptions.IgnoreCase));
            }

            WriteVerbose($"Decrypting file at {fullPath}, output at {outPath}");

            ProviderInfo resolvedOutProviderInfo;
            PSDriveInfo resolvedOutDriveInfo;
            string resolvedOutPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(outPath, out resolvedOutProviderInfo, out resolvedOutDriveInfo);

            if (resolvedOutProviderInfo.ImplementingType.Name != "FileSystemProvider")
            {
                throw new FileNotFoundException($"The file {outPath} is not located on a FileSystemProvider type of PSProvider");
            }

            CATEncryptor cat = new CATEncryptor();
            cat.Decrypt(resolvedFullPath, resolvedOutPath, Certificate.PrivateKey);
        }
    }

    class CATEncryptor
    {
        public void Encrypt(string inFile, string outFile, AsymmetricAlgorithm rsaPublicKey)
        {
            using (AesManaged aesManaged = new AesManaged())
            {
                // Create instance of AesManaged for symetric encryption of the data.
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;
                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(rsaPublicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    // Create byte arrays to contain the length values of the key and IV.
                    byte[] LenK = new byte[4];
                    byte[] LenIV = new byte[4];

                    int lKey = keyEncrypted.Length;
                    LenK = BitConverter.GetBytes(lKey);
                    int lIV = aesManaged.IV.Length;
                    LenIV = BitConverter.GetBytes(lIV);

                    // Write the following to the FileStream for the encrypted file (outFs):
                    // - length of the key
                    // - length of the IV
                    // - ecrypted key
                    // - the IV
                    // - the encrypted cipher content

                    using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                    {
                        outFs.Write(LenK, 0, 4);
                        outFs.Write(LenIV, 0, 4);
                        outFs.Write(keyEncrypted, 0, lKey);
                        outFs.Write(aesManaged.IV, 0, lIV);

                        // Now write the cipher text using a CryptoStream for encrypting.
                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                        {
                            using (var inFs = File.OpenRead(inFile))
                            {
                                int bytesRead = 0;
                                int blockSizeBytes = aesManaged.BlockSize / 8;
                                byte[] data = new byte[blockSizeBytes];

                                while ((bytesRead = inFs.Read(data, 0, blockSizeBytes)) > 0)
                                {
                                    outStreamEncrypted.Write(data, 0, bytesRead);
                                }

                                inFs.Close();
                            }

                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }

                        outFs.Close();
                    }
                }
            }
        }

        public void Decrypt(string inFile, string outFile, AsymmetricAlgorithm rsaPrivateKey)
        {
            // Create instance of AesManaged for symetric decryption of the data.
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                // Create byte arrays to get the length of the encrypted key and IV.
                // These values were stored as 4 bytes each at the beginning of the encrypted package.
                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];

                // Use FileStream objects to read the encrypted file (inFs) and save the decrypted file (outFs).
                using (FileStream inFs = new FileStream(inFile, FileMode.Open))
                {
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(LenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(LenIV, 0, 3);

                    // Convert the lengths to integer values.
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);

                    // Determine the start postition of the ciphter text (startC) and its length (lenC).
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inFs.Length - startC;

                    // Create the byte arrays for the encrypted AesManaged key, the IV, and the cipher text.
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];

                    // Extract the key and IV starting from index 8 after the length values.
                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(KeyEncrypted, 0, lenK);
                    inFs.Seek(8 + lenK, SeekOrigin.Begin);
                    inFs.Read(IV, 0, lenIV);

                    // Use RSACryptoServiceProvider to decrypt the AesManaged key.
                    RSA r = rsaPrivateKey as RSA;
                    byte[] KeyDecrypted = r.Decrypt(KeyEncrypted, RSAEncryptionPadding.Pkcs1);

                    // Decrypt the key.
                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(KeyDecrypted, IV))
                    {
                        // Decrypt the cipher text from from the FileSteam of the encrypted ile (inFs) 
                        // into the FileStream for the decrypted file (outFs).
                        using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                        {
                            // Start at the beginning of the cipher text.
                            inFs.Seek(startC, SeekOrigin.Begin);
                            using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                            {
                                int count = 0;
                                int blockSizeBytes = aesManaged.BlockSize / 8;
                                byte[] data = new byte[blockSizeBytes];

                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    outStreamDecrypted.Write(data, 0, count);
                                }
                                while (count > 0);

                                outStreamDecrypted.FlushFinalBlock();
                                outStreamDecrypted.Close();
                            }

                            outFs.Close();
                        }

                        inFs.Close();
                    }
                }
            }
        }
    }
}

using System;
using System.Management.Automation;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Runtime.Serialization.Formatters.Binary;

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
            CATEncryptor cat = new CATEncryptor();
            cat.Encrypt(fullPath, outPath, Certificate.PublicKey.Key, this);
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
            string fullPath = File.Exists(Path) ? Path : System.IO.Path.Combine(Environment.CurrentDirectory, Path);
            string outPath = OutFile;

            if (string.IsNullOrEmpty(OutFile))
            {
                string fileName = System.IO.Path.GetFileName(fullPath);
                string dirName = System.IO.Path.GetDirectoryName(fullPath);
                outPath = System.IO.Path.Combine(dirName, "decrypted_" + Regex.Replace(fileName, @"\.encrypted", string.Empty, RegexOptions.IgnoreCase));
            }

            WriteVerbose($"Encrypting file at {fullPath}, output at {outPath}");
            CATEncryptor cat = new CATEncryptor();
            cat.Decrypt(fullPath, outPath, Certificate.PrivateKey);
        }
    }

    class CATEncryptor
    {
        public void Encrypt(string inFile, string outFile, AsymmetricAlgorithm rsaPublicKey, PSCmdlet ps)
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

                    //using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                    using (MemoryStream outMem = new MemoryStream())
                    {
                        var outPs = ps.InvokeProvider.Content.GetWriter(outFile).First();

                        outMem.Write(LenK, 0, 4);
                        outMem.Write(LenIV, 0, 4);
                        outMem.Write(keyEncrypted, 0, lKey);
                        outMem.Write(aesManaged.IV, 0, lIV);
                        int bytesInMem = lKey = lIV + 8;

                        // Now write the cipher text using a CryptoStream for encrypting.
                        using (CryptoStream outStreamEncrypted = new CryptoStream(outMem, transform, CryptoStreamMode.Write))
                        {
                            //using (var inFs = File.OpenRead(inFile))
                            using (var inFs = ps.InvokeProvider.Content.GetReader(inFile).First())
                            {
                                int bytesRead = 0;
                                int blocksRead = 0;
                                int blockSizeBytes = aesManaged.BlockSize / 8;
                                inFs.Seek(0, SeekOrigin.Begin);

                                do
                                {
                                    IList inContentList = inFs.Read(blockSizeBytes);
                                    blocksRead = inContentList.Count;
                                    IList dataList = new List<byte>();

                                    foreach (var item in inContentList)
                                    {
                                        if (item == null)
                                        {
                                            continue;
                                        }

                                        BinaryFormatter bf = new BinaryFormatter();
                                        using (MemoryStream ms = new MemoryStream())
                                        {
                                            bf.Serialize(ms, item);
                                            foreach (byte b in ms.ToArray())
                                            {
                                                dataList.Add(b);
                                            }
                                        }
                                    }

                                    bytesRead = dataList.Count;
                                    bytesInMem += bytesRead;
                                    byte[] data = new byte[bytesRead];
                                    dataList.CopyTo(data, 0);
                                    outStreamEncrypted.Write(data, 0, bytesRead);

                                    if ((bytesInMem > 500000 || blocksRead < blockSizeBytes) && blocksRead > 0)
                                    {
                                        // We either got to the end of the file, or have enough data that we should dump
                                        // it out of the memorystream

                                        outMem.Seek(0, SeekOrigin.Begin);
                                        byte[] memContents = new byte[bytesInMem];
                                        int memRead = outMem.Read(memContents, 0, bytesInMem);
                                        IList write = new List<string>();
                                        write.Add(Encoding.Default.GetString(memContents));
                                        outPs.Write(write);


                                        outMem.Flush();
                                        bytesInMem = 0;
                                    }
                                }
                                while (blocksRead > 0);

                                inFs.Close();
                            }

                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }

                        outPs.Close();
                        outMem.Close();
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

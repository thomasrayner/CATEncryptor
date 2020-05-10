using System;
using System.IO;
using System.Security.Cryptography;

namespace CATEncryptor
{
    class CATEncryptor
    {
        public void Encrypt(Stream inStream, Stream outStream, AsymmetricAlgorithm rsaPublicKey)
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

                    outStream.Write(LenK, 0, 4);
                    outStream.Write(LenIV, 0, 4);
                    outStream.Write(keyEncrypted, 0, lKey);
                    outStream.Write(aesManaged.IV, 0, lIV);

                    // Now write the cipher text using a CryptoStream for encrypting.
                    using (CryptoStream outStreamEncrypted = new CryptoStream(outStream, transform, CryptoStreamMode.Write))
                    {
                        {
                            int bytesRead = 0;
                            int blockSizeBytes = aesManaged.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];

                            while ((bytesRead = inStream.Read(data, 0, blockSizeBytes)) > 0)
                            {
                                outStreamEncrypted.Write(data, 0, bytesRead);
                            }
                        }

                        outStreamEncrypted.FlushFinalBlock();
                        outStreamEncrypted.Close();
                    }
                }
            }
        }

        public void Decrypt(Stream inStream, Stream outStream, AsymmetricAlgorithm rsaPrivateKey)
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
                using (inStream)
                {
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Seek(0, SeekOrigin.Begin);
                    inStream.Read(LenK, 0, 3);
                    inStream.Seek(4, SeekOrigin.Begin);
                    inStream.Read(LenIV, 0, 3);

                    // Convert the lengths to integer values.
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);

                    // Determine the start postition of the ciphter text (startC) and its length (lenC).
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inStream.Length - startC;

                    // Create the byte arrays for the encrypted AesManaged key, the IV, and the cipher text.
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];

                    // Extract the key and IV starting from index 8 after the length values.
                    inStream.Seek(8, SeekOrigin.Begin);
                    inStream.Read(KeyEncrypted, 0, lenK);
                    inStream.Seek(8 + lenK, SeekOrigin.Begin);
                    inStream.Read(IV, 0, lenIV);

                    // Use RSACryptoServiceProvider to decrypt the AesManaged key.
                    RSA r = rsaPrivateKey as RSA;
                    byte[] KeyDecrypted = r.Decrypt(KeyEncrypted, RSAEncryptionPadding.Pkcs1);

                    // Decrypt the key.
                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(KeyDecrypted, IV))
                    {
                        // Decrypt the cipher text from from the FileSteam of the encrypted ile (inFs) 
                        // into the FileStream for the decrypted file (outFs).
                        using (outStream)
                        {
                            // Start at the beginning of the cipher text.
                            inStream.Seek(startC, SeekOrigin.Begin);
                            using (CryptoStream outStreamDecrypted = new CryptoStream(outStream, transform, CryptoStreamMode.Write))
                            {
                                int count = 0;
                                int blockSizeBytes = aesManaged.BlockSize / 8;
                                byte[] data = new byte[blockSizeBytes];

                                do
                                {
                                    count = inStream.Read(data, 0, blockSizeBytes);
                                    outStreamDecrypted.Write(data, 0, count);
                                }
                                while (count > 0);

                                outStreamDecrypted.FlushFinalBlock();
                                outStreamDecrypted.Close();
                            }

                            outStream.Close();
                        }

                        inStream.Close();
                    }
                }
            }
        }
    }
}

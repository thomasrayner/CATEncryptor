using System;
using System.Management.Automation;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Linq;
using System.Text;
using System.Collections.Generic;

namespace CATEncryptor
{
    [Cmdlet(VerbsSecurity.Protect, "String")]
    public class ProtectString : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0)]
        public string String { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 1)]
        public X509Certificate2 Certificate { get; set; }

        protected override void ProcessRecord()
        {
            CATEncryptor cat = new CATEncryptor();
            using (MemoryStream memIn = new MemoryStream(Encoding.Default.GetBytes(String ?? "")))
            {
                using (MemoryStream memOut = new MemoryStream())
                {
                    cat.Encrypt(memIn, memOut, Certificate.PublicKey.Key);
                    byte[] memOutBytes = new byte[memOut.Length];
                    memOut.Seek(0, SeekOrigin.Begin);
                    int read = memOut.Read(memOutBytes, 0, memOutBytes.Length);
                    string enc = Encoding.Default.GetString(memOutBytes);
                    WriteObject(enc);
                    memOut.Close();
                }
                memIn.Close();
            }
        }
    }

    [Cmdlet(VerbsSecurity.Unprotect, "String")]
    public class UnprotectString : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0)]
        public string String { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 1)]
        public X509Certificate2 Certificate { get; set; }

        protected override void ProcessRecord()
        {
            CATEncryptor cat = new CATEncryptor();
            using (MemoryStream memIn = new MemoryStream(Encoding.Default.GetBytes(String ?? "")))
            {
                using (MemoryStream memOut = new MemoryStream())
                {
                    cat.Decrypt(memIn, memOut, Certificate.PrivateKey);
                    byte[] memOutBytes = new byte[memOut.Length];
                    memOut.Seek(0, SeekOrigin.Begin);
                    int read = memOut.Read(memOutBytes, 0, memOutBytes.Length);
                    string enc = Encoding.Default.GetString(memOutBytes);
                    WriteObject(enc);
                    memOut.Close();
                }
                memIn.Close();
            }
        }
    }
}

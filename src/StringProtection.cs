using System.Management.Automation;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
        public string Plaintext { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 1)]
        public X509Certificate2 Certificate { get; set; }

        protected override void ProcessRecord()
        {
            CATEncryptor cat = new CATEncryptor();
            using (MemoryStream memIn = new MemoryStream(Encoding.UTF8.GetBytes(Plaintext ?? "")))
            {
                using (MemoryStream memOut = new MemoryStream())
                {
                    cat.Encrypt(memIn, memOut, Certificate.PublicKey.Key);
                    byte[] buffer = memOut.ToArray();
                    string ciphertextb64 = System.Convert.ToBase64String(buffer);
                    WriteObject(ciphertextb64);
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
        public string CiphertextBase64 { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 1)]
        public X509Certificate2 Certificate { get; set; }

        protected override void ProcessRecord()
        {
            CATEncryptor cat = new CATEncryptor();
            byte[] ciphertextBytes = System.Convert.FromBase64String(CiphertextBase64);

            using (MemoryStream memIn = new MemoryStream(ciphertextBytes))
            {
                using (MemoryStream memOut = new MemoryStream())
                {
                    cat.Decrypt(memIn, memOut, Certificate.PrivateKey);
                    byte[] buffer = memOut.ToArray();
                    string plaintext = Encoding.UTF8.GetString(buffer, 0, buffer.Length);
                    WriteObject(plaintext);
                    memOut.Close();
                }
                memIn.Close();
            }
        }
    }
}

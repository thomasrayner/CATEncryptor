using System;
using System.Management.Automation;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Linq;

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
            using (FileStream inFs = File.OpenRead(resolvedFullPath))
            {
                using (MemoryStream memOut = new MemoryStream())
                {
                    cat.Encrypt(inFs, memOut, Certificate.PublicKey.Key);
                    memOut.Close();
                }
                inFs.Close();
            }
        }
    }


    [Cmdlet(VerbsSecurity.Unprotect, "String")]
    public class UnprotectString : PSCmdlet
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
                string fileName = System.IO.Path.GetFileName(fullPath);
                string dirName = System.IO.Path.GetDirectoryName(fullPath);
                outPath = System.IO.Path.Combine(dirName, "decrypted_" + Regex.Replace(fileName, @"\.encrypted", string.Empty, RegexOptions.IgnoreCase));
            }

            WriteVerbose($"Decrypting file at {fullPath}, output at {outPath}");

            string resolvedOutPath = string.Empty;
            try
            {
                var resolvedOutPathInfo = this.SessionState.Path.GetResolvedPSPathFromPSPath(outPath).First();
                if (resolvedOutPathInfo.Provider.ImplementingType.Name != "FileSystemProvider")
                {
                    throw new FileNotFoundException($"The file {outPath} is not located on a FileSystemProvider type of PSProvider");
                }
                resolvedOutPath = resolvedOutPathInfo.ProviderPath;
            }
            catch (ItemNotFoundException)
            {
                // It's alright to create a new file
                string outParent = this.SessionState.Path.ParseParent(outPath, System.IO.Path.GetDirectoryName(outPath));
                var resolvedOutParentInfo = this.SessionState.Path.GetResolvedPSPathFromPSPath(outParent).First();
                if (resolvedOutParentInfo.Provider.ImplementingType.Name != "FileSystemProvider")
                {
                    throw new FileNotFoundException($"The file {outPath} is not located on a FileSystemProvider type of PSProvider");
                }
                resolvedOutPath = System.IO.Path.Combine(resolvedOutParentInfo.ProviderPath, System.IO.Path.GetFileName(outPath));
            }

            CATEncryptor cat = new CATEncryptor();
            WriteVerbose($"Resolved input at {resolvedFullPath}, resolved output at {resolvedOutPath}");
            using (FileStream inFs = File.OpenRead(resolvedFullPath))
            {
                using (FileStream outFs = new FileStream(resolvedOutPath, FileMode.Create))
                {
                    cat.Decrypt(inFs, outFs, Certificate.PrivateKey);
                    outFs.Close();
                }
                inFs.Close();
            }
        }
    }
}

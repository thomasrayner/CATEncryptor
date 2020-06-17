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
            WriteVerbose($"Resolved input at {resolvedFullPath}, resolved output at {resolvedOutPath}");
            using (FileStream inFs = File.OpenRead(resolvedFullPath))
            {
                using (FileStream outFs = new FileStream(resolvedOutPath, FileMode.Create))
                {
                    cat.Encrypt(inFs, outFs, Certificate.PublicKey.Key);
                    outFs.Close();
                }
                inFs.Close();
            }
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

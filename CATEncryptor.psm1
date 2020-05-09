# Work around for not supporting newer versions of PoweShell. Manifests and requires statements only allow
# you to restrict the minimum version, not the maximum.
if ($PSVersionTable.PSVersion.Major -ne 5) { throw "Cannot use PowerShell Version other than 5.x" }

$PSModule = $ExecutionContext.SessionState.Module
$binaryModulePath = "$PSScriptRoot\CATEncryptor.dll"
$binaryModule = Import-Module -Name $binaryModulePath -PassThru

# When the module is unloaded, remove the nested binary module that was loaded with it
$PSModule.OnRemove = {
    Remove-Module -ModuleInfo $binaryModule
}

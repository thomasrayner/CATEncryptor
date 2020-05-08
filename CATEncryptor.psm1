if ($PSVersionTable.PSVersion.Major -ne 5) { throw "Cannot use PowerShell Version other than 5.x" }

$PSModule = $ExecutionContext.SessionState.Module
$binaryModulePath = "$PSScriptRoot\CATEncryptor.dll"
$binaryModule = Import-Module -Name $binaryModulePath -PassThru

# When the module is unloaded, remove the nested binary module that was loaded with it
$PSModule.OnRemove = {
    Remove-Module -ModuleInfo $binaryModule
}

$PSModule = $ExecutionContext.SessionState.Module
$binaryModulePath = "$PSScriptRoot\CATEncryptor.dll"
$binaryModule = Import-Module -Name $binaryModulePath -PassThru

# When the module is unloaded, remove the nested binary module that was loaded with it
$PSModule.OnRemove = {
    Remove-Module -ModuleInfo $binaryModule
}

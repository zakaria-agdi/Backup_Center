@{
    RootModule = 'Hypervisors.psm1'
    ModuleVersion = '1.0.0'
    GUID = '4527840b-e608-4d5b-b30a-0b0ddc4af89a'
    Author = 'BackupCenter'
    Description = 'Proxmox REST, native Hyper-V and PowerCLI exports with a common local-source contract.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Export-ProxmoxVM', 'Export-HyperVVM', 'Export-VMwareVM', 'Get-ProxmoxVMStatus', 'Get-ProxmoxBackupStorage', 'Invoke-ProxmoxBackupTest', 'Get-ProxmoxBackupArtifact')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
@{
    RootModule = 'BackupEngine.psm1'
    ModuleVersion = '1.0.0'
    GUID = '271d8229-4eb4-43aa-a279-5d6bde8df6c0'
    Author = 'BackupCenter'
    Description = 'Sequential JSON backup queue, encrypted pipelines and independent remote verification.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('New-BackupJob', 'Add-BackupJob', 'Get-BackupQueue', 'Start-BackupQueue', 'Start-BackupPipeline', 'Protect-BackupArchive', 'Unprotect-BackupArchive', 'Invoke-ProxmoxTransferPipeline')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('BackupCenter', 'Backup', 'Queue', 'Rclone', 'Verification')
        }
    }
}
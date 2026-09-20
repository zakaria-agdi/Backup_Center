@{
    RootModule = 'Maintenance.psm1'
    ModuleVersion = '1.0.0'
    GUID = '5096260a-ecad-45d5-89f5-6f5dce10c762'
    Author = 'BackupCenter'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Send-TelegramAlert', 'Invoke-RetentionPolicy')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
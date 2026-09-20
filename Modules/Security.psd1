@{
    RootModule = 'Security.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'c1dadb34-28d6-48b1-ad43-cbf8c180d589'
    Author = 'BackupCenter'
    Description = 'Windows DPAPI secret storage and RFC 6238 TOTP for BackupCenter.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'Protect-BackupSecret',
        'Unprotect-BackupSecret',
        'Initialize-BackupCenterConfig',
        'Set-BackupSecret',
        'Get-BackupSecret',
        'New-TotpSecret',
        'Get-TotpCode',
        'Test-TotpCode'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('BackupCenter', 'Windows', 'DPAPI', 'TOTP', 'Security')
        }
    }
}
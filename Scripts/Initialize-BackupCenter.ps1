#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $root = Split-Path $PSScriptRoot -Parent
    foreach ($directory in @('Modules', 'Config', 'Logs', 'Scripts', 'WebUI')) {
        $null = [IO.Directory]::CreateDirectory((Join-Path $root $directory))
    }
    Import-Module (Join-Path $root 'Modules\Security.psd1') -Force -ErrorAction Stop
    $configPath = Join-Path $root 'Config\config.json'
    $logDirectory = Join-Path $root 'Logs'
    Initialize-BackupCenterConfig -ConfigPath $configPath -LogDirectory $logDirectory
    [pscustomobject]@{
        Project = 'BackupCenter'
        Configuration = $configPath
        Logs = $logDirectory
        ProtectionScope = 'DPAPI CurrentUser'
    }
}
catch {
    Write-Error 'BackupCenter initialization failed. Check the module audit log, Windows identity and permissions.' -ErrorAction Continue
    throw
}
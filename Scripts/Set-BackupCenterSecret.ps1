#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z')][string]$Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$secret = $null

try {
    $root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $root 'Modules\Security.psd1') -Force -ErrorAction Stop
    $secret = Read-Host -Prompt 'Secret (hidden input)' -AsSecureString
    Set-BackupSecret -Name $Name -Secret $secret
    Write-Output 'Secret encrypted and stored successfully.'
}
catch {
    Write-Error 'Secret storage failed. Initialize BackupCenter first and check the security audit log.' -ErrorAction Continue
    throw
}
finally {
    if ($null -ne $secret) { $secret.Dispose() }
}
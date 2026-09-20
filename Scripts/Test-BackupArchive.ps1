#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '..\Modules\Security.psd1') -Force
Import-Module (Join-Path $PSScriptRoot '..\Modules\BackupEngine.psd1') -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupArchive-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$checks = 0
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message }; $script:checks++ }
try {
    $options = @{ ConfigPath = (Join-Path $root 'secrets.json'); LogDirectory = (Join-Path $root 'Logs') }
    $source = Join-Path $root 'source.vma.zst'
    $payload = New-Object byte[] 2097191
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($payload) } finally { $random.Dispose() }
    [IO.File]::WriteAllBytes($source, $payload)
    $first = Protect-BackupArchive -SourcePath $source -OutputPath (Join-Path $root 'first.bca') @options
    $second = Protect-BackupArchive -SourcePath $source -OutputPath (Join-Path $root 'second.bca') @options
    Assert-True ($first.SecretName -cne $second.SecretName) 'Unique archive password identifier'
    Assert-True ((Get-FileHash $first.Path).Hash -cne (Get-FileHash $second.Path).Hash) 'Randomized ciphertext'
    Assert-True ($first.Size -gt $payload.Length) 'Authenticated file created'
    $restored = Join-Path $root 'restored.vma.zst'
    Unprotect-BackupArchive -SourcePath $first.Path -OutputPath $restored @options
    Assert-True ((Get-FileHash $source).Hash -ceq (Get-FileHash $restored).Hash) 'AES roundtrip across chunk boundary'
    $secret = Get-BackupSecret -Name $first.SecretName @options
    try { Assert-True ($secret -is [Security.SecureString] -and $secret.Length -gt 64) 'Password retrievable only through DPAPI API' } finally { $secret.Dispose() }
    foreach ($offset in @(0, 20, 36, ([int]$first.Size - 1))) {
        $corrupt = [IO.File]::ReadAllBytes($first.Path); $corrupt[$offset] = $corrupt[$offset] -bxor 1
        $badPath = Join-Path $root 'corrupt.bca'; [IO.File]::WriteAllBytes($badPath, $corrupt)
        $badOutput = Join-Path $root 'must-not-exist'; $failed = $false
        try { Unprotect-BackupArchive -SourcePath $badPath -OutputPath $badOutput @options } catch { $failed = $true }
        Assert-True ($failed -and -not [IO.File]::Exists($badOutput)) 'Tampering rejected before plaintext output'
    }
    $failed = $false
    try { Protect-BackupArchive -SourcePath $source -OutputPath $first.Path @options } catch { $failed = $true }
    Assert-True $failed 'Never overwrite encrypted archive'
    $failed = $false
    try { Unprotect-BackupArchive -SourcePath $first.Path -OutputPath $restored @options } catch { $failed = $true }
    Assert-True ($failed -and (Get-FileHash $source).Hash -ceq (Get-FileHash $restored).Hash) 'Never overwrite restored file'
    $wrong = ConvertTo-SecureString ([Convert]::ToBase64String((New-Object byte[] 64))) -AsPlainText -Force
    try { Set-BackupSecret -Name $first.SecretName -Secret $wrong @options } finally { $wrong.Dispose() }
    $failed = $false
    try { Unprotect-BackupArchive -SourcePath $first.Path -OutputPath (Join-Path $root 'wrong-key') @options } catch { $failed = $true }
    Assert-True ($failed -and -not [IO.File]::Exists((Join-Path $root 'wrong-key'))) 'Wrong password rejected before plaintext output'
    Write-Host ('PASS: ' + $checks + ' archive assertions; real AES, HMAC and DPAPI.')
}
finally { Remove-Item -LiteralPath $root -Recurse -Force }
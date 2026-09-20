#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('BackupCenter.Tests.' + [Guid]::NewGuid().ToString('N'))
$logDirectory = Join-Path $testRoot 'Logs'
$script:Assertions = 0
$secrets = [Collections.Generic.List[Security.SecureString]]::new()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('Assertion failed: ' + $Message) }
    $script:Assertions++
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $didThrow = $false
    try { $null = & $Action }
    catch { $didThrow = $true }
    Assert-True $didThrow $Message
}

try {
    $manifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\Security.psd1'
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Assert-True ($manifest.Version -eq [version]'1.0.0') 'Valid module manifest'
    Import-Module $manifestPath -Force -ErrorAction Stop
    $plainText = 'TEST-ONLY-api-password-' + [char]0x00E9 + [char]0x6F22
    $secret = ConvertTo-SecureString $plainText -AsPlainText -Force
    $secrets.Add($secret)
    $encrypted = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
    Assert-True ($encrypted.StartsWith('dpapi:v1:')) 'Versioned DPAPI envelope'
    Assert-True (-not $encrypted.Contains($plainText)) 'No plaintext in ciphertext'
    $restored = Unprotect-BackupSecret -ProtectedSecret $encrypted -LogDirectory $logDirectory
    $secrets.Add($restored)
    Assert-True ($restored -is [Security.SecureString]) 'Decryption returns SecureString'
    Assert-True ([Net.NetworkCredential]::new('', $restored).Password -ceq $plainText) 'DPAPI Unicode round trip'
    Assert-True ($encrypted -cne (Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory)) 'DPAPI randomized encryption'
    Assert-Throws { Unprotect-BackupSecret -ProtectedSecret 'plaintext' -LogDirectory $logDirectory } 'Reject plaintext'
    Assert-Throws { Unprotect-BackupSecret -ProtectedSecret 'dpapi:v1:invalid!' -LogDirectory $logDirectory } 'Reject malformed ciphertext'
    $tampered = [Convert]::FromBase64String($encrypted.Substring(9))
    $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1
    Assert-Throws { Unprotect-BackupSecret -ProtectedSecret ('dpapi:v1:' + [Convert]::ToBase64String($tampered)) -LogDirectory $logDirectory } 'Reject tampered DPAPI data'

    $vectors = @(
        @{ Time = 59L; SHA1 = '94287082'; SHA256 = '46119246'; SHA512 = '90693936' },
        @{ Time = 1111111109L; SHA1 = '07081804'; SHA256 = '68084774'; SHA512 = '25091201' },
        @{ Time = 1111111111L; SHA1 = '14050471'; SHA256 = '67062674'; SHA512 = '99943326' },
        @{ Time = 1234567890L; SHA1 = '89005924'; SHA256 = '91819424'; SHA512 = '93441116' },
        @{ Time = 2000000000L; SHA1 = '69279037'; SHA256 = '90698825'; SHA512 = '38618901' },
        @{ Time = 20000000000L; SHA1 = '65353130'; SHA256 = '77737706'; SHA512 = '47863826' }
    )
    $base32Keys = @{
        SHA1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA'
        SHA512 = ('GEZDGNBVGY3TQOJQ' * 6) + 'GEZDGNA'
    }
    foreach ($algorithm in @('SHA1', 'SHA256', 'SHA512')) {
        $totpSecret = ConvertTo-SecureString $base32Keys[$algorithm] -AsPlainText -Force
        $secrets.Add($totpSecret)
        foreach ($vector in $vectors) {
            $arguments = @{ Secret = $totpSecret; Algorithm = $algorithm; Digits = 8; UnixTime = $vector.Time; LogDirectory = $logDirectory }
            $code = Get-TotpCode @arguments
            Assert-True ($code -ceq $vector[$algorithm]) ('RFC 6238 ' + $algorithm + ' at ' + $vector.Time)
            Assert-True (Test-TotpCode @arguments -Code $vector[$algorithm] -Window 0) 'Validate RFC vector'
        }
        $generated = New-TotpSecret -Algorithm $algorithm -LogDirectory $logDirectory
        $secrets.Add($generated)
        $expectedLength = switch ($algorithm) { 'SHA1' { 32 } 'SHA256' { 52 } 'SHA512' { 103 } }
        Assert-True ($generated.Length -eq $expectedLength) 'Random secret size'
        $generatedCode = Get-TotpCode -Secret $generated -Algorithm $algorithm -UnixTime 59 -LogDirectory $logDirectory
        Assert-True (Test-TotpCode -Secret $generated -Algorithm $algorithm -Code $generatedCode -UnixTime 59 -Window 0 -LogDirectory $logDirectory) 'Random secret round trip'
    }

    $totpSecret = ConvertTo-SecureString $base32Keys.SHA1 -AsPlainText -Force
    $secrets.Add($totpSecret)
    $arguments = @{ Secret = $totpSecret; LogDirectory = $logDirectory }
    Assert-True ((Get-TotpCode @arguments -UnixTime 59) -ceq '287082') 'Six digits'
    Assert-True (Test-TotpCode @arguments -Code '287082' -UnixTime 60 -Window 1) 'Accept previous time step'
    Assert-True (Test-TotpCode @arguments -Code '287082' -UnixTime 29 -Window 1) 'Accept next time step'
    Assert-True (-not (Test-TotpCode @arguments -Code '287082' -UnixTime 60 -Window 0)) 'Strict window'
    Assert-True (-not (Test-TotpCode @arguments -Code '287082' -UnixTime 90 -Window 1)) 'Reject expired code'
    foreach ($invalid in @('', '12345', '1234567', 'abcdef', "287082`n", ' 287082', '000000')) {
        Assert-True (-not (Test-TotpCode @arguments -Code $invalid -UnixTime 59 -Window 0)) 'Reject invalid code'
    }
    $match = Test-TotpCode @arguments -Code '287082' -UnixTime 59 -Window 0 -PassThru
    Assert-True ($match.IsValid -and $match.TimeStep -eq 1) 'Return accepted time step'
    Assert-True (-not (Test-TotpCode @arguments -Code '287082' -UnixTime 59 -LastAcceptedTimeStep $match.TimeStep)) 'Reject replay with supplied state'
    $epochCode = Get-TotpCode @arguments -UnixTime 0
    Assert-True (Test-TotpCode @arguments -Code $epochCode -UnixTime 0 -Window 1) 'No negative counter at epoch'
    $invalidSecret = ConvertTo-SecureString ('!' * 32) -AsPlainText -Force
    $secrets.Add($invalidSecret)
    Assert-Throws { Get-TotpCode -Secret $invalidSecret -LogDirectory $logDirectory } 'Reject invalid Base32'

    $configPath = Join-Path $testRoot 'Config\config.json'
    $configArguments = @{ ConfigPath = $configPath; LogDirectory = $logDirectory }
    Initialize-BackupCenterConfig @configArguments
    Assert-True ([IO.File]::Exists($configPath)) 'Initialize JSON configuration'
    Set-BackupSecret @configArguments -Name 'Smtp.Password' -Secret $secret
    Set-BackupSecret @configArguments -Name 'Totp.TestUser' -Secret $totpSecret
    $configText = [IO.File]::ReadAllText($configPath)
    $configuration = $configText | ConvertFrom-Json
    Assert-True ($configuration.Secrets.'Smtp.Password'.StartsWith('dpapi:v1:')) 'Encrypted password in JSON'
    Assert-True ($configuration.Secrets.'Totp.TestUser'.StartsWith('dpapi:v1:')) 'Encrypted TOTP secret in JSON'
    Assert-True (-not $configText.Contains($plainText) -and -not $configText.Contains($base32Keys.SHA1)) 'No plaintext secrets in JSON'
    $loaded = Get-BackupSecret @configArguments -Name 'Smtp.Password'
    $secrets.Add($loaded)
    Assert-True ([Net.NetworkCredential]::new('', $loaded).Password -ceq $plainText) 'Read persisted password'
    Initialize-BackupCenterConfig @configArguments
    Assert-True ([IO.File]::ReadAllText($configPath) -ceq $configText) 'Idempotent initialization preserves secrets'
    Set-BackupSecret @configArguments -Name 'Smtp.Password' -Secret $totpSecret
    $updated = Get-BackupSecret @configArguments -Name 'Smtp.Password'
    $secrets.Add($updated)
    Assert-True ([Net.NetworkCredential]::new('', $updated).Password -ceq $base32Keys.SHA1) 'Update existing secret'
    $persistedTotp = Get-BackupSecret @configArguments -Name 'Totp.TestUser'
    $secrets.Add($persistedTotp)
    Assert-True (Test-TotpCode -Secret $persistedTotp -Code '287082' -UnixTime 59 -Window 0 -LogDirectory $logDirectory) 'Validate with persisted TOTP secret'
    Assert-Throws { Get-BackupSecret @configArguments -Name 'Missing' } 'Missing secret fails closed'
    $beforeLockTest = [IO.File]::ReadAllText($configPath)
    $heldLock = [IO.File]::Open($configPath + '.lock', [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        Assert-Throws { Set-BackupSecret @configArguments -Name 'Concurrent' -Secret $secret } 'Exclusive lock prevents concurrent writes'
    }
    finally { $heldLock.Dispose() }
    Assert-True ([IO.File]::ReadAllText($configPath) -ceq $beforeLockTest) 'Lock conflict preserves configuration'
    $acl = Get-Acl -LiteralPath $configPath
    Assert-True $acl.AreAccessRulesProtected 'Configuration ACL inheritance disabled'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $allowedSids = @($identity.User.Value, 'S-1-5-18')
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            Assert-True ($rule.IdentityReference.Value -in $allowedSids -and -not $rule.IsInherited) 'Only current user and SYSTEM have access'
        }
    }
    finally { $identity.Dispose() }
    Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $configPath -Parent) -Filter '*.tmp').Count -eq 0) 'No temporary configuration leftovers'
    $badConfigPath = Join-Path $testRoot 'Config\invalid.json'
    [IO.File]::WriteAllText($badConfigPath, '{ invalid json')
    Assert-Throws { Initialize-BackupCenterConfig -ConfigPath $badConfigPath -LogDirectory $logDirectory } 'Reject corrupt JSON without resetting'
    Assert-True ([IO.File]::ReadAllText($badConfigPath) -ceq '{ invalid json') 'Corrupt JSON remains untouched'
    $plaintextConfig = [ordered]@{ SchemaVersion = 1; Application = 'BackupCenter'; ProtectionScope = 'CurrentUser'; Secrets = @{ Password = $plainText } } | ConvertTo-Json
    [IO.File]::WriteAllText($badConfigPath, $plaintextConfig)
    Assert-Throws { Get-BackupSecret -ConfigPath $badConfigPath -Name 'Password' -LogDirectory $logDirectory } 'Reject plaintext secret in JSON'
    $blockedLogPath = Join-Path $testRoot 'not-a-directory'
    [IO.File]::WriteAllText($blockedLogPath, 'test')
    Assert-Throws { Test-TotpCode -Secret $totpSecret -Code '287082' -UnixTime 59 -LogDirectory $blockedLogPath } 'Audit failure denies validation'
    Assert-Throws { Set-BackupSecret -ConfigPath $configPath -Name 'NotWritten' -Secret $secret -LogDirectory $blockedLogPath } 'Audit failure prevents mutation'
    Assert-True ([IO.File]::ReadAllText($configPath) -ceq $beforeLockTest) 'Audit failure preserves configuration'

    $logText = (Get-ChildItem -LiteralPath $logDirectory -Filter '*.jsonl' | Get-Content) -join "`n"
    Assert-True (-not $logText.Contains($plainText)) 'No password in logs'
    Assert-True (-not $logText.Contains($base32Keys.SHA1)) 'No TOTP secret in logs'
    Assert-True (-not $logText.Contains('94287082')) 'No OTP in logs'
    foreach ($line in ($logText -split "`n")) {
        $entry = $line | ConvertFrom-Json -ErrorAction Stop
        Assert-True ($entry.Component -eq 'BackupCenter.Security' -and $entry.Outcome -in @('Success', 'Rejected', 'Error')) 'Structured audit event'
    }
    Write-Output ('PASS: {0} assertions; DPAPI, JSON, ACL, audit, replay and all 18 RFC 6238 vectors.' -f $script:Assertions)
}
catch {
    Write-Error ('Security tests failed: ' + $_.Exception.Message) -ErrorAction Continue
    throw
}
finally {
    foreach ($item in $secrets) { $item.Dispose() }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop }
}
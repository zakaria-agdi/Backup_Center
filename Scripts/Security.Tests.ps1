#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.7.1' }

BeforeDiscovery {
    $vectors = @(
        @{ Time = 59L; SHA1 = '94287082'; SHA256 = '46119246'; SHA512 = '90693936' },
        @{ Time = 1111111109L; SHA1 = '07081804'; SHA256 = '68084774'; SHA512 = '25091201' },
        @{ Time = 1111111111L; SHA1 = '14050471'; SHA256 = '67062674'; SHA512 = '99943326' },
        @{ Time = 1234567890L; SHA1 = '89005924'; SHA256 = '91819424'; SHA512 = '93441116' },
        @{ Time = 2000000000L; SHA1 = '69279037'; SHA256 = '90698825'; SHA512 = '38618901' },
        @{ Time = 20000000000L; SHA1 = '65353130'; SHA256 = '77737706'; SHA512 = '47863826' }
    )
    $keys = @{
        SHA1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA'
        SHA512 = ('GEZDGNBVGY3TQOJQ' * 6) + 'GEZDGNA'
    }
    $rfcCases = foreach ($algorithm in @('SHA1', 'SHA256', 'SHA512')) {
        foreach ($vector in $vectors) {
            @{ Algorithm = $algorithm; UnixTime = $vector.Time; Expected = $vector[$algorithm]; Base32 = $keys[$algorithm] }
        }
    }
    $auditCases = @(
        @{ Function = 'Protect-BackupSecret' }, @{ Function = 'Unprotect-BackupSecret' },
        @{ Function = 'New-TotpSecret' }, @{ Function = 'Get-TotpCode' }, @{ Function = 'Test-TotpCode' },
        @{ Function = 'Initialize-BackupCenterConfig' }, @{ Function = 'Set-BackupSecret' }, @{ Function = 'Get-BackupSecret' }
    )
}

Describe 'BackupCenter.Security' -Tag 'Security', 'Windows' {
    BeforeAll {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            throw 'These integration tests require Windows DPAPI and NTFS.'
        }
        $manifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\Security.psd1'
        Import-Module $manifestPath -Force -ErrorAction Stop
    }

    BeforeEach {
        $caseRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($caseRoot)
        $logDirectory = Join-Path $caseRoot 'Logs'
        $secrets = [Collections.Generic.List[Security.SecureString]]::new()
        $plainText = 'TEST-ONLY-password-' + [char]0x00E9 + [char]0x6F22
        $secret = ConvertTo-SecureString $plainText -AsPlainText -Force
        $totpSecret = ConvertTo-SecureString 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' -AsPlainText -Force
        $secrets.Add($secret)
        $secrets.Add($totpSecret)
    }

    AfterEach {
        foreach ($item in $secrets) { $item.Dispose() }
    }

    It 'preserves the eight public functions and the PowerShell 5.1 manifest' {
        $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        $manifest.PowerShellVersion | Should -Be ([version]'5.1')
        $manifest.ExportedFunctions.Count | Should -Be 8
        foreach ($name in @('Protect-BackupSecret', 'Unprotect-BackupSecret', 'New-TotpSecret', 'Get-TotpCode', 'Test-TotpCode', 'Initialize-BackupCenterConfig', 'Set-BackupSecret', 'Get-BackupSecret')) {
            $manifest.ExportedFunctions.Keys | Should -Contain $name
        }
    }

    Context 'DPAPI CurrentUser' {
        It 'round-trips a Unicode secret as a read-only SecureString' {
            $encrypted = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            $encrypted | Should -Match '\Adpapi:v1:'
            $encrypted.Contains($plainText) | Should -BeFalse
            $restored = Unprotect-BackupSecret -ProtectedSecret $encrypted -LogDirectory $logDirectory
            $secrets.Add($restored)
            $restored | Should -BeOfType ([Security.SecureString])
            $restored.IsReadOnly() | Should -BeTrue
            ([Net.NetworkCredential]::new('', $restored).Password -ceq $plainText) | Should -BeTrue
        }

        It 'uses the Windows CurrentUser scope and the versioned entropy' {
            $encrypted = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            $decoded = $null
            try {
                $decoded = [Security.Cryptography.ProtectedData]::Unprotect(
                    [Convert]::FromBase64String($encrypted.Substring(9)),
                    [Text.Encoding]::UTF8.GetBytes('BackupCenter.Security.v1'),
                    [Security.Cryptography.DataProtectionScope]::CurrentUser)
                ([Text.Encoding]::Unicode.GetString($decoded) -ceq $plainText) | Should -BeTrue
            }
            finally {
                if ($null -ne $decoded) { [Array]::Clear($decoded, 0, $decoded.Length) }
            }
        }

        It 'randomizes repeated encryption of the same input' {
            $first = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            $second = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            ($first -cne $second) | Should -BeTrue
        }

        It 'rejects an empty SecureString with a sanitized exception' {
            $empty = [Security.SecureString]::new()
            $secrets.Add($empty)
            { Protect-BackupSecret -Secret $empty -LogDirectory $logDirectory } |
                Should -Throw -ExceptionType ([InvalidOperationException]) -ExpectedMessage 'Secret encryption failed.'
        }

        It 'rejects <Label> ciphertext' -ForEach @(
            @{ Label = 'plaintext'; Ciphertext = 'TEST-ONLY-plaintext' },
            @{ Label = 'unknown version'; Ciphertext = 'dpapi:v2:AAAA' },
            @{ Label = 'invalid Base64'; Ciphertext = 'dpapi:v1:invalid!' },
            @{ Label = 'empty payload'; Ciphertext = 'dpapi:v1:' },
            @{ Label = 'non-DPAPI payload'; Ciphertext = 'dpapi:v1:AAAA' }
        ) {
            $failure = { Unprotect-BackupSecret -ProtectedSecret $Ciphertext -LogDirectory $logDirectory } |
                Should -Throw -ExceptionType ([InvalidOperationException]) -PassThru
            $failure.Exception.Message | Should -BeExactly 'Secret decryption failed. Check the Windows identity, profile and encrypted data.'
            $failure.Exception.InnerException | Should -BeNullOrEmpty
        }

        It 'rejects a modified encrypted blob' {
            $encrypted = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            $tampered = [Convert]::FromBase64String($encrypted.Substring(9))
            $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1
            { Unprotect-BackupSecret -ProtectedSecret ('dpapi:v1:' + [Convert]::ToBase64String($tampered)) -LogDirectory $logDirectory } |
                Should -Throw -ExceptionType ([InvalidOperationException])
        }

        It 'rejects a blob encrypted with a different application entropy' {
            $bytes = [Text.Encoding]::Unicode.GetBytes($plainText)
            try {
                $cipher = [Security.Cryptography.ProtectedData]::Protect($bytes,
                    [Text.Encoding]::UTF8.GetBytes('TEST-ONLY-other-application'),
                    [Security.Cryptography.DataProtectionScope]::CurrentUser)
                { Unprotect-BackupSecret -ProtectedSecret ('dpapi:v1:' + [Convert]::ToBase64String($cipher)) -LogDirectory $logDirectory } |
                    Should -Throw -ExceptionType ([InvalidOperationException])
            }
            finally { [Array]::Clear($bytes, 0, $bytes.Length) }
        }
    }

    Context 'RFC 6238 Appendix B' {
        It 'generates and validates <Algorithm> at Unix time <UnixTime>' -ForEach $rfcCases {
            $vectorSecret = ConvertTo-SecureString $Base32 -AsPlainText -Force
            $secrets.Add($vectorSecret)
            $arguments = @{ Secret = $vectorSecret; Algorithm = $Algorithm; Digits = 8; UnixTime = $UnixTime; LogDirectory = $logDirectory }
            ((Get-TotpCode @arguments) -ceq $Expected) | Should -BeTrue
            Test-TotpCode @arguments -Code $Expected -Window 0 | Should -BeTrue
        }
    }

    Context 'TOTP validation and key generation' {
        It 'generates independent read-only <Algorithm> keys of the required length' -ForEach @(
            @{ Algorithm = 'SHA1'; Length = 32 }, @{ Algorithm = 'SHA256'; Length = 52 }, @{ Algorithm = 'SHA512'; Length = 103 }
        ) {
            $first = New-TotpSecret -Algorithm $Algorithm -LogDirectory $logDirectory
            $secrets.Add($first)
            $second = New-TotpSecret -Algorithm $Algorithm -LogDirectory $logDirectory
            $secrets.Add($second)
            $first | Should -BeOfType ([Security.SecureString])
            $first.IsReadOnly() | Should -BeTrue
            $first.Length | Should -Be $Length
            ([Net.NetworkCredential]::new('', $first).Password -cne [Net.NetworkCredential]::new('', $second).Password) | Should -BeTrue
            $code = Get-TotpCode -Secret $first -Algorithm $Algorithm -UnixTime 59 -LogDirectory $logDirectory
            Test-TotpCode -Secret $first -Algorithm $Algorithm -Code $code -UnixTime 59 -Window 0 -LogDirectory $logDirectory | Should -BeTrue
        }

        It 'returns the six-digit RFC truncation by default' {
            ((Get-TotpCode -Secret $totpSecret -UnixTime 59 -LogDirectory $logDirectory) -ceq '287082') | Should -BeTrue
        }

        It 'handles the <Label> time window' -ForEach @(
            @{ Label = 'current step'; Time = 59; Window = 0; Valid = $true },
            @{ Label = 'previous step'; Time = 60; Window = 1; Valid = $true },
            @{ Label = 'next step'; Time = 29; Window = 1; Valid = $true },
            @{ Label = 'strict boundary'; Time = 60; Window = 0; Valid = $false },
            @{ Label = 'expired code'; Time = 90; Window = 1; Valid = $false }
        ) {
            Test-TotpCode -Secret $totpSecret -Code '287082' -UnixTime $Time -Window $Window -LogDirectory $logDirectory | Should -Be $Valid
        }

        It 'rejects a <Label> code as false, not as an infrastructure exception' -ForEach @(
            @{ Label = 'null'; Code = $null }, @{ Label = 'empty'; Code = '' },
            @{ Label = 'short'; Code = '12345' }, @{ Label = 'long'; Code = '1234567' },
            @{ Label = 'nonnumeric'; Code = 'abcdef' }, @{ Label = 'newline-suffixed'; Code = "287082`n" },
            @{ Label = 'space-prefixed'; Code = ' 287082' }, @{ Label = 'incorrect'; Code = '000000' },
            @{ Label = 'Unicode-digit'; Code = ([string][char]0x0661) * 6 }
        ) {
            $valid = Test-TotpCode -Secret $totpSecret -Code $Code -UnixTime 59 -Window 0 -LogDirectory $logDirectory
            $valid | Should -BeOfType ([bool])
            $valid | Should -BeFalse
            $entry = Get-ChildItem -LiteralPath $logDirectory -Filter '*.jsonl' | Get-Content | Select-Object -Last 1 | ConvertFrom-Json
            $entry.Outcome | Should -BeExactly 'Rejected'
        }

        It 'returns a matched counter and rejects its replay when supplied by the caller' {
            $accepted = Test-TotpCode -Secret $totpSecret -Code '287082' -UnixTime 59 -Window 0 -PassThru -LogDirectory $logDirectory
            $accepted.IsValid | Should -BeTrue
            $accepted.TimeStep | Should -Be 1
            $replay = Test-TotpCode -Secret $totpSecret -Code '287082' -UnixTime 59 -Window 0 -PassThru -LastAcceptedTimeStep $accepted.TimeStep -LogDirectory $logDirectory
            $replay.IsValid | Should -BeFalse
            $replay.TimeStep | Should -BeNullOrEmpty
        }

        It 'returns a null counter for malformed input with PassThru' {
            $rejected = Test-TotpCode -Secret $totpSecret -Code '' -PassThru -LogDirectory $logDirectory
            $rejected.IsValid | Should -BeFalse
            $rejected.TimeStep | Should -BeNullOrEmpty
        }

        It 'does not compute negative counters at the Unix epoch' {
            $code = Get-TotpCode -Secret $totpSecret -UnixTime 0 -LogDirectory $logDirectory
            Test-TotpCode -Secret $totpSecret -Code $code -UnixTime 0 -Window 2 -LogDirectory $logDirectory | Should -BeTrue
        }

        It 'does not overflow counters near Int64 MaxValue' {
            $code = Get-TotpCode -Secret $totpSecret -UnixTime ([long]::MaxValue) -Period 1 -LogDirectory $logDirectory
            Test-TotpCode -Secret $totpSecret -Code $code -UnixTime ([long]::MaxValue) -Period 1 -Window 2 -LogDirectory $logDirectory | Should -BeTrue
        }

        It 'accepts lowercase Base32 without changing the code' {
            $lowercase = ConvertTo-SecureString 'gezdgnbvgy3tqojqgezdgnbvgy3tqojq' -AsPlainText -Force
            $secrets.Add($lowercase)
            ((Get-TotpCode -Secret $lowercase -UnixTime 59 -LogDirectory $logDirectory) -ceq '287082') | Should -BeTrue
        }

        It 'rejects a <Label> Base32 secret' -ForEach @(
            @{ Label = 'short'; Key = 'A' * 31 }, @{ Label = 'long'; Key = 'A' * 206 },
            @{ Label = 'nonalphabetic'; Key = '!' * 32 },
            @{ Label = 'padded'; Key = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ=' },
            @{ Label = 'noncanonical'; Key = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZB' }
        ) {
            $invalid = ConvertTo-SecureString $Key -AsPlainText -Force
            $secrets.Add($invalid)
            { Get-TotpCode -Secret $invalid -UnixTime 59 -LogDirectory $logDirectory } |
                Should -Throw -ExpectedMessage 'TOTP generation failed. Verify the secret and parameters.'
            { Test-TotpCode -Secret $invalid -Code '287082' -UnixTime 59 -LogDirectory $logDirectory } |
                Should -Throw -ExpectedMessage 'TOTP validation failed. Access must be denied.'
        }

        It 'rejects the invalid <Label> parameter before executing the operation' -ForEach @(
            @{ Label = 'algorithm'; Options = @{ Algorithm = 'MD5' } },
            @{ Label = 'digit count'; Options = @{ Digits = 7 } },
            @{ Label = 'period'; Options = @{ Period = 0 } },
            @{ Label = 'window'; Options = @{ Window = 3 } },
            @{ Label = 'timestamp'; Options = @{ UnixTime = -1 } }
        ) {
            { Test-TotpCode -Secret $totpSecret -Code '287082' -LogDirectory $logDirectory @Options } | Should -Throw
            Test-Path -LiteralPath $logDirectory | Should -BeFalse
        }
    }

    Context 'JSON persistence and Windows permissions' {
        BeforeEach {
            $configPath = Join-Path $caseRoot 'Config\config.json'
            $configArguments = @{ ConfigPath = $configPath; LogDirectory = $logDirectory }
            Initialize-BackupCenterConfig @configArguments
        }

        It 'stores only encrypted envelopes and reads them back as SecureString' {
            Set-BackupSecret @configArguments -Name 'Fixture.Password' -Secret $secret
            Set-BackupSecret @configArguments -Name 'Fixture.Totp' -Secret $totpSecret
            $json = [IO.File]::ReadAllText($configPath)
            $configuration = $json | ConvertFrom-Json
            $configuration.ProtectionScope | Should -BeExactly 'CurrentUser'
            $configuration.Secrets.'Fixture.Password' | Should -Match '\Adpapi:v1:'
            $configuration.Secrets.'Fixture.Totp' | Should -Match '\Adpapi:v1:'
            $json.Contains($plainText) | Should -BeFalse
            $json.Contains('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ') | Should -BeFalse
            $restored = Get-BackupSecret @configArguments -Name 'Fixture.Password'
            $secrets.Add($restored)
            ([Net.NetworkCredential]::new('', $restored).Password -ceq $plainText) | Should -BeTrue
        }

        It 'limits <Target> ACLs to current user and SYSTEM without inheritance' -ForEach @(
            @{ Target = 'configuration'; Suffix = '' }, @{ Target = 'lock file'; Suffix = '.lock' }
        ) {
            $acl = Get-Acl -LiteralPath ($configPath + $Suffix)
            $acl.AreAccessRulesProtected | Should -BeTrue
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            try {
                $allowedSids = @($identity.User.Value, 'S-1-5-18') | Select-Object -Unique
                $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
                $rules.Count | Should -Be @($allowedSids).Count
                foreach ($rule in $rules) {
                    $allowedSids | Should -Contain $rule.IdentityReference.Value
                    $rule.IsInherited | Should -BeFalse
                    $rule.AccessControlType | Should -Be ([Security.AccessControl.AccessControlType]::Allow)
                    $rule.FileSystemRights | Should -Be ([Security.AccessControl.FileSystemRights]::FullControl)
                }
            }
            finally { $identity.Dispose() }
        }

        It 'keeps initialization idempotent and replaces an existing secret without temporary leftovers' {
            Set-BackupSecret @configArguments -Name 'Fixture.Password' -Secret $secret
            $before = [IO.File]::ReadAllText($configPath)
            Initialize-BackupCenterConfig @configArguments
            ([IO.File]::ReadAllText($configPath) -ceq $before) | Should -BeTrue
            Set-BackupSecret @configArguments -Name 'Fixture.Password' -Secret $totpSecret
            $restored = Get-BackupSecret @configArguments -Name 'Fixture.Password'
            $secrets.Add($restored)
            Test-TotpCode -Secret $restored -Code '287082' -UnixTime 59 -Window 0 -LogDirectory $logDirectory | Should -BeTrue
            @(Get-ChildItem -LiteralPath (Split-Path $configPath -Parent) -Filter '*.tmp').Count | Should -Be 0
        }

        It 'refuses corrupt JSON without silently resetting it' {
            [IO.File]::WriteAllText($configPath, '{ TEST-ONLY-invalid-json')
            { Initialize-BackupCenterConfig @configArguments } | Should -Throw
            [IO.File]::ReadAllText($configPath) | Should -BeExactly '{ TEST-ONLY-invalid-json'
        }

        It 'refuses a plaintext record in the configuration' {
            $configuration = [ordered]@{ SchemaVersion = 1; Application = 'BackupCenter'; ProtectionScope = 'CurrentUser'; Secrets = @{ Password = $plainText } }
            [IO.File]::WriteAllText($configPath, ($configuration | ConvertTo-Json))
            { Get-BackupSecret @configArguments -Name 'Password' } | Should -Throw
        }

        It 'rejects a missing secret' {
            { Get-BackupSecret @configArguments -Name 'Missing' } | Should -Throw
        }

        It 'preserves the configuration when its lock is held by another operation' {
            $before = [IO.File]::ReadAllText($configPath)
            $heldLock = [IO.File]::Open($configPath + '.lock', [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                { Set-BackupSecret @configArguments -Name 'Fixture.Password' -Secret $secret } | Should -Throw
            }
            finally { $heldLock.Dispose() }
            ([IO.File]::ReadAllText($configPath) -ceq $before) | Should -BeTrue
        }

        It 'does not mutate configuration when audit is unavailable before the write' {
            $before = [IO.File]::ReadAllText($configPath)
            $blockedPath = Join-Path $caseRoot 'blocked-audit'
            [IO.File]::WriteAllText($blockedPath, 'TEST-ONLY')
            { Set-BackupSecret -Name 'Fixture.Password' -Secret $secret -ConfigPath $configPath -LogDirectory $blockedPath } | Should -Throw
            ([IO.File]::ReadAllText($configPath) -ceq $before) | Should -BeTrue
        }
    }

    Context 'Fail-closed audit handling' {
        It 'identifies a real audit failure without returning a validation result' {
            $blockedPath = Join-Path $caseRoot 'not-a-directory'
            [IO.File]::WriteAllText($blockedPath, 'TEST-ONLY')
            $failure = {
                Test-TotpCode -Secret $totpSecret -Code '287082' -UnixTime 59 -Window 0 -LogDirectory $blockedPath
            } | Should -Throw -ExceptionType ([InvalidOperationException]) -PassThru
            $failure.Exception.Message | Should -BeExactly 'Security audit log unavailable; operation aborted.'
            $failure.Exception.Data['SecurityCode'] | Should -BeExactly 'AuditUnavailable'
            $failure.Exception.InnerException | Should -BeNullOrEmpty
        }

        It 'does not retry an audit failure in <Function>, including nested operations' -ForEach $auditCases {
            $encrypted = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            $configPath = Join-Path $caseRoot 'config.json'
            if ($Function -in @('Get-BackupSecret', 'Set-BackupSecret')) {
                Initialize-BackupCenterConfig -ConfigPath $configPath -LogDirectory $logDirectory
                Set-BackupSecret -Name 'Fixture.Password' -Secret $secret -ConfigPath $configPath -LogDirectory $logDirectory
            }
            InModuleScope Security -Parameters @{ FixtureSecret = $totpSecret; FixtureLogs = $logDirectory; FixtureFunction = $Function; FixtureCipher = $encrypted; FixtureConfig = $configPath } {
                param($FixtureSecret, $FixtureLogs, $FixtureFunction, $FixtureCipher, $FixtureConfig)
                Mock Write-SecurityLog {
                    $exception = [InvalidOperationException]::new('Security audit log unavailable; operation aborted.')
                    $exception.Data['SecurityCode'] = 'AuditUnavailable'
                    throw $exception
                }
                $failure = {
                    switch ($FixtureFunction) {
                        'Protect-BackupSecret' { Protect-BackupSecret -Secret $FixtureSecret -LogDirectory $FixtureLogs }
                        'Unprotect-BackupSecret' { Unprotect-BackupSecret -ProtectedSecret $FixtureCipher -LogDirectory $FixtureLogs }
                        'New-TotpSecret' { New-TotpSecret -LogDirectory $FixtureLogs }
                        'Get-TotpCode' { Get-TotpCode -Secret $FixtureSecret -UnixTime 59 -LogDirectory $FixtureLogs }
                        'Test-TotpCode' { Test-TotpCode -Secret $FixtureSecret -Code '287082' -UnixTime 59 -Window 0 -LogDirectory $FixtureLogs }
                        'Initialize-BackupCenterConfig' { Initialize-BackupCenterConfig -ConfigPath $FixtureConfig -LogDirectory $FixtureLogs }
                        'Set-BackupSecret' { Set-BackupSecret -Name 'Fixture.Password' -Secret $FixtureSecret -ConfigPath $FixtureConfig -LogDirectory $FixtureLogs }
                        'Get-BackupSecret' { Get-BackupSecret -Name 'Fixture.Password' -ConfigPath $FixtureConfig -LogDirectory $FixtureLogs }
                    }
                } | Should -Throw -ExpectedMessage 'Security audit log unavailable; operation aborted.' -PassThru
                $failure.Exception.Data['SecurityCode'] | Should -BeExactly 'AuditUnavailable'
                Should -Invoke Write-SecurityLog -Times 1 -Exactly -Scope It
            }
        }

        It 'emits no partial result when audit fails for an otherwise <Label> code' -ForEach @(
            @{ Label = 'valid'; Code = '287082' }, @{ Label = 'invalid'; Code = '000000' }
        ) {
            $blockedPath = Join-Path $caseRoot 'blocked-audit'
            [IO.File]::WriteAllText($blockedPath, 'TEST-ONLY')
            $output = [Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                Test-TotpCode -Secret $totpSecret -Code $Code -UnixTime 59 -Window 0 -LogDirectory $blockedPath |
                    ForEach-Object { $output.Add($_) }
            }
            catch { $failure = $_ }
            $failure | Should -Not -BeNullOrEmpty
            $output.Count | Should -Be 0
        }

        It 'does not expose raw dependency errors through the public exception or audit' {
            InModuleScope Security -Parameters @{ FixtureSecret = $totpSecret; FixtureLogs = $logDirectory } {
                param($FixtureSecret, $FixtureLogs)
                Mock ConvertFrom-Base32Secret { throw 'TEST-ONLY-sensitive-dependency-details' }
                $failure = { Get-TotpCode -Secret $FixtureSecret -LogDirectory $FixtureLogs } | Should -Throw -PassThru
                $failure.Exception.Message | Should -BeExactly 'TOTP generation failed. Verify the secret and parameters.'
                $failure.Exception.InnerException | Should -BeNullOrEmpty
                $logText = (Get-ChildItem -LiteralPath $FixtureLogs -Filter '*.jsonl' | Get-Content) -join "`n"
                $logText.Contains('TEST-ONLY-sensitive-dependency-details') | Should -BeFalse
                ($logText | ConvertFrom-Json).Outcome | Should -BeExactly 'Error'
            }
        }

        It 'logs structured events without passwords, secret keys or OTP values' {
            $null = Protect-BackupSecret -Secret $secret -LogDirectory $logDirectory
            $null = Get-TotpCode -Secret $totpSecret -UnixTime 59 -LogDirectory $logDirectory
            $null = Test-TotpCode -Secret $totpSecret -Code '287082' -UnixTime 59 -Window 0 -LogDirectory $logDirectory
            $null = Test-TotpCode -Secret $totpSecret -Code '000000' -UnixTime 59 -Window 0 -LogDirectory $logDirectory
            { Unprotect-BackupSecret -ProtectedSecret 'TEST-ONLY-invalid' -LogDirectory $logDirectory } | Should -Throw
            $lines = @(Get-ChildItem -LiteralPath $logDirectory -Filter '*.jsonl' | Get-Content)
            $text = $lines -join "`n"
            foreach ($sensitive in @($plainText, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082', '000000')) {
                $text.Contains($sensitive) | Should -BeFalse
            }
            $entries = @($lines | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
            foreach ($entry in $entries) {
                $entry.Component | Should -BeExactly 'BackupCenter.Security'
                @('Success', 'Rejected', 'Error') | Should -Contain $entry.Outcome
                $entry.PSObject.Properties.Name.Count | Should -Be 6
                foreach ($name in @('TimestampUtc', 'Component', 'Operation', 'Outcome', 'ProcessId', 'EventId')) {
                    $entry.PSObject.Properties.Name | Should -Contain $name
                }
            }
            $entries.Outcome | Should -Contain 'Success'
            $entries.Outcome | Should -Contain 'Rejected'
            $entries.Outcome | Should -Contain 'Error'
        }
    }
}
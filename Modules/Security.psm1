#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'BackupCenter.Security requires Windows DPAPI.'
}

try {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
}
catch {
    throw 'Unable to load Windows cryptography support.'
}

$script:DefaultLogDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) 'Logs'
$script:DefaultConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Config\config.json'
$script:Entropy = [Text.Encoding]::UTF8.GetBytes('BackupCenter.Security.v1')
$script:Base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function Write-SecurityLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][ValidateSet('Success', 'Rejected', 'Error')][string]$Outcome,
        [Parameter(Mandatory)][string]$LogDirectory
    )
    try {
        $null = [IO.Directory]::CreateDirectory($LogDirectory)
        $timestamp = [DateTimeOffset]::UtcNow
        $entry = [ordered]@{
            TimestampUtc = $timestamp.ToString('o')
            Component = 'BackupCenter.Security'
            Operation = $Operation
            Outcome = $Outcome
            ProcessId = $PID
            EventId = [Guid]::NewGuid().ToString('N')
        } | ConvertTo-Json -Compress
        $path = Join-Path $LogDirectory ('security-{0}.jsonl' -f $timestamp.ToString('yyyy-MM-dd'))
        $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($entry + [Environment]::NewLine)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    catch {
        $exception = [InvalidOperationException]::new('Security audit log unavailable; operation aborted.')
        $exception.Data['SecurityCode'] = 'AuditUnavailable'
        throw $exception
    }
}

function Protect-BackupSecret {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][Security.SecureString]$Secret,
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $pointer = [IntPtr]::Zero
    $plainBytes = $null
    try {
        if ($Secret.Length -eq 0) { throw 'Empty secret.' }
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        $plainBytes = [byte[]]::new($Secret.Length * 2)
        [Runtime.InteropServices.Marshal]::Copy($pointer, $plainBytes, 0, $plainBytes.Length)
        $cipherBytes = [Security.Cryptography.ProtectedData]::Protect(
            $plainBytes, $script:Entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        Write-SecurityLog -Operation 'Secret.Protect' -Outcome Success -LogDirectory $LogDirectory
        return 'dpapi:v1:' + [Convert]::ToBase64String($cipherBytes)
    }
    catch {
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Secret.Protect' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('Secret encryption failed.')
    }
    finally {
        if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Unprotect-BackupSecret {
    [CmdletBinding()]
    [OutputType([Security.SecureString])]
    param(
        [Parameter(Mandatory)][string]$ProtectedSecret,
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $plainBytes = $null
    $result = $null
    try {
        if (-not $ProtectedSecret.StartsWith('dpapi:v1:', [StringComparison]::Ordinal)) {
            throw 'Unsupported secret envelope.'
        }
        $cipherBytes = [Convert]::FromBase64String($ProtectedSecret.Substring(9))
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $cipherBytes, $script:Entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        if ($plainBytes.Length -eq 0 -or $plainBytes.Length % 2 -ne 0) { throw 'Invalid secret encoding.' }
        $result = [Security.SecureString]::new()
        for ($index = 0; $index -lt $plainBytes.Length; $index += 2) {
            $result.AppendChar([char]([int]$plainBytes[$index] -bor ([int]$plainBytes[$index + 1] -shl 8)))
        }
        $result.MakeReadOnly()
        Write-SecurityLog -Operation 'Secret.Unprotect' -Outcome Success -LogDirectory $LogDirectory
        return $result
    }
    catch {
        if ($null -ne $result) { $result.Dispose() }
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Secret.Unprotect' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('Secret decryption failed. Check the Windows identity, profile and encrypted data.')
    }
    finally {
        if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    }
}

function ConvertFrom-Base32Secret {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.SecureString]$Secret)
    $pointer = [IntPtr]::Zero
    $decoded = $null
    $completed = $false
    try {
        if ($Secret.Length -lt 32 -or $Secret.Length -gt 205 -or $Secret.Length % 8 -notin @(0, 2, 4, 5, 7)) {
            throw 'Invalid Base32 length.'
        }
        $decoded = [byte[]]::new([int][Math]::Floor($Secret.Length * 5 / 8))
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        $buffer = 0
        $bitCount = 0
        $offset = 0
        for ($index = 0; $index -lt $Secret.Length; $index++) {
            $character = [char][Runtime.InteropServices.Marshal]::ReadInt16($pointer, $index * 2)
            $value = $script:Base32Alphabet.IndexOf([char]::ToUpperInvariant($character))
            if ($value -lt 0) { throw 'Invalid Base32 character.' }
            $buffer = ($buffer -shl 5) -bor $value
            $bitCount += 5
            if ($bitCount -ge 8) {
                $bitCount -= 8
                $decoded[$offset++] = [byte](($buffer -shr $bitCount) -band 255)
                $buffer = $buffer -band ((1 -shl $bitCount) - 1)
            }
        }
        if ($buffer -ne 0) { throw 'Non-canonical Base32 trailing bits.' }
        $completed = $true
        return ,$decoded
    }
    catch {
        throw [ArgumentException]::new('TOTP secret must be unpadded Base32 containing 20 to 128 bytes.')
    }
    finally {
        if (-not $completed -and $null -ne $decoded) { [Array]::Clear($decoded, 0, $decoded.Length) }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function New-TotpSecret {
    [CmdletBinding()]
    [OutputType([Security.SecureString])]
    param(
        [ValidateSet('SHA1', 'SHA256', 'SHA512')][string]$Algorithm = 'SHA1',
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $random = $null
    $keyBytes = $null
    $result = $null
    try {
        $length = switch ($Algorithm) { 'SHA1' { 20 } 'SHA256' { 32 } 'SHA512' { 64 } }
        $keyBytes = [byte[]]::new($length)
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        $random.GetBytes($keyBytes)
        $result = [Security.SecureString]::new()
        $buffer = 0
        $bitCount = 0
        foreach ($keyByte in $keyBytes) {
            $buffer = ($buffer -shl 8) -bor $keyByte
            $bitCount += 8
            while ($bitCount -ge 5) {
                $bitCount -= 5
                $result.AppendChar($script:Base32Alphabet[($buffer -shr $bitCount) -band 31])
            }
            $buffer = $buffer -band ((1 -shl $bitCount) - 1)
        }
        if ($bitCount -gt 0) { $result.AppendChar($script:Base32Alphabet[($buffer -shl (5 - $bitCount)) -band 31]) }
        $result.MakeReadOnly()
        Write-SecurityLog -Operation 'Totp.Secret.Generate' -Outcome Success -LogDirectory $LogDirectory
        return $result
    }
    catch {
        if ($null -ne $result) { $result.Dispose() }
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Totp.Secret.Generate' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('TOTP secret generation failed.')
    }
    finally {
        if ($null -ne $random) { $random.Dispose() }
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
    }
}

function Get-TotpValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$KeyBytes,
        [Parameter(Mandatory)][long]$TimeStep,
        [Parameter(Mandatory)][string]$Algorithm,
        [Parameter(Mandatory)][int]$Digits
    )
    $hmac = $null
    $hash = $null
    try {
        $counter = [BitConverter]::GetBytes($TimeStep)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counter) }
        $hmac = switch ($Algorithm) {
            'SHA1' { [Security.Cryptography.HMACSHA1]::new() }
            'SHA256' { [Security.Cryptography.HMACSHA256]::new() }
            'SHA512' { [Security.Cryptography.HMACSHA512]::new() }
        }
        $hmac.Key = $KeyBytes
        $hash = $hmac.ComputeHash($counter)
        $offset = $hash[$hash.Length - 1] -band 15
        $binary = (([long]$hash[$offset] -band 127) -shl 24) -bor
            ([long]$hash[$offset + 1] -shl 16) -bor
            ([long]$hash[$offset + 2] -shl 8) -bor [long]$hash[$offset + 3]
        $modulus = if ($Digits -eq 6) { 1000000 } else { 100000000 }
        return ($binary % $modulus).ToString(('D{0}' -f $Digits), [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw [InvalidOperationException]::new('TOTP computation failed.')
    }
    finally {
        if ($null -ne $hmac) { $hmac.Dispose() }
        if ($null -ne $hash) { [Array]::Clear($hash, 0, $hash.Length) }
    }
}

function Get-TotpCode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][Security.SecureString]$Secret,
        [ValidateSet('SHA1', 'SHA256', 'SHA512')][string]$Algorithm = 'SHA1',
        [ValidateSet(6, 8)][int]$Digits = 6,
        [ValidateRange(1, 300)][int]$Period = 30,
        [ValidateRange(0, [long]::MaxValue)][long]$UnixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(),
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $keyBytes = $null
    try {
        $keyBytes = ConvertFrom-Base32Secret -Secret $Secret
        $remainder = 0L
        $timeStep = [Math]::DivRem($UnixTime, [long]$Period, [ref]$remainder)
        $code = Get-TotpValue -KeyBytes $keyBytes -TimeStep $timeStep -Algorithm $Algorithm -Digits $Digits
        Write-SecurityLog -Operation 'Totp.Code.Generate' -Outcome Success -LogDirectory $LogDirectory
        return $code
    }
    catch {
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Totp.Code.Generate' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('TOTP generation failed. Verify the secret and parameters.')
    }
    finally {
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
    }
}

function Test-TotpCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.SecureString]$Secret,
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Code,
        [ValidateSet('SHA1', 'SHA256', 'SHA512')][string]$Algorithm = 'SHA1',
        [ValidateSet(6, 8)][int]$Digits = 6,
        [ValidateRange(1, 300)][int]$Period = 30,
        [ValidateRange(0, 2)][int]$Window = 1,
        [ValidateRange(0, [long]::MaxValue)][long]$UnixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(),
        [ValidateRange(-1, [long]::MaxValue)][long]$LastAcceptedTimeStep = -1,
        [switch]$PassThru,
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $keyBytes = $null
    try {
        $matchedTimeStep = -1L
        if ($null -ne $Code -and [regex]::IsMatch($Code, ('\A[0-9]{{{0}}}\z' -f $Digits))) {
            $keyBytes = ConvertFrom-Base32Secret -Secret $Secret
            $remainder = 0L
            $currentTimeStep = [Math]::DivRem($UnixTime, [long]$Period, [ref]$remainder)
            for ($delta = -$Window; $delta -le $Window; $delta++) {
                if ($delta -lt 0 -and $currentTimeStep -lt -$delta) { continue }
                if ($delta -gt 0 -and $currentTimeStep -gt [long]::MaxValue - $delta) { continue }
                $candidateTimeStep = $currentTimeStep + $delta
                $expected = Get-TotpValue -KeyBytes $keyBytes -TimeStep $candidateTimeStep -Algorithm $Algorithm -Digits $Digits
                $difference = 0
                for ($index = 0; $index -lt $Digits; $index++) {
                    $difference = $difference -bor ([int][char]$Code[$index] -bxor [int][char]$expected[$index])
                }
                if ($difference -eq 0 -and $candidateTimeStep -gt $LastAcceptedTimeStep) {
                    $matchedTimeStep = $candidateTimeStep
                }
            }
        }
        $valid = $matchedTimeStep -ge 0
        $outcome = if ($valid) { 'Success' } else { 'Rejected' }
        Write-SecurityLog -Operation 'Totp.Code.Validate' -Outcome $outcome -LogDirectory $LogDirectory
        if ($PassThru) {
            return [pscustomobject]@{ IsValid = $valid; TimeStep = $(if ($valid) { $matchedTimeStep } else { $null }) }
        }
        return $valid
    }
    catch {
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Totp.Code.Validate' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('TOTP validation failed. Access must be denied.')
    }
    finally {
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
    }
}

function Set-PrivateFilePermissions {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $identity = $null
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $allowedSids = @($identity.User.Value, 'S-1-5-18') | Select-Object -Unique
        $existingRules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $unexpectedRules = @($existingRules | Where-Object {
            $_.IdentityReference.Value -notin $allowedSids -or $_.IsInherited -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl
        })
        $actualSids = @($existingRules | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)
        if ($acl.AreAccessRulesProtected -and $unexpectedRules.Count -eq 0 -and $actualSids.Count -eq @($allowedSids).Count) {
            return
        }
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($existingRule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
            $null = $acl.RemoveAccessRuleSpecific($existingRule)
        }
        foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow)
            $null = $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
    catch {
        throw [InvalidOperationException]::new('Unable to restrict configuration file permissions.')
    }
    finally {
        if ($null -ne $identity) { $identity.Dispose() }
    }
}

function Open-ConfigurationLock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    $stream = $null
    try {
        $fullPath = [IO.Path]::GetFullPath($ConfigPath)
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullPath))
        $stream = [IO.File]::Open($fullPath + '.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Dispose()
        $stream = $null
        Set-PrivateFilePermissions -Path ($fullPath + '.lock')
        $stream = [IO.File]::Open($fullPath + '.lock', [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        return $stream
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw [InvalidOperationException]::new('Configuration is locked or inaccessible. Retry after the current operation completes.')
    }
}

function Read-SecretConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    try {
        if (-not [IO.File]::Exists($ConfigPath)) { throw 'Configuration missing.' }
        Set-PrivateFilePermissions -Path $ConfigPath
        if ([IO.FileInfo]::new($ConfigPath).Length -gt 1MB) { throw 'Configuration too large.' }
        $configuration = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
        if ($configuration -isnot [pscustomobject] -or $configuration.SchemaVersion -ne 1 -or
            $configuration.Application -cne 'BackupCenter' -or $configuration.ProtectionScope -cne 'CurrentUser' -or
            $configuration.Secrets -isnot [pscustomobject]) { throw 'Invalid configuration schema.' }
        foreach ($property in $configuration.PSObject.Properties) {
            if ($property.Name -cnotin @('SchemaVersion', 'Application', 'ProtectionScope', 'Secrets')) {
                throw 'Unexpected configuration property.'
            }
        }
        foreach ($property in $configuration.Secrets.PSObject.Properties) {
            if ($property.Name -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z' -or
                $property.Value -isnot [string] -or
                -not $property.Value.StartsWith('dpapi:v1:', [StringComparison]::Ordinal)) { throw 'Invalid secret record.' }
            $cipherBytes = [Convert]::FromBase64String($property.Value.Substring(9))
            if ($cipherBytes.Length -eq 0) { throw 'Empty encrypted record.' }
        }
        return $configuration
    }
    catch {
        throw [InvalidOperationException]::new('Configuration is missing, invalid or inaccessible. Existing data has not been reset.')
    }
}

function Write-SecretConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][pscustomobject]$Configuration
    )
    $temporaryPath = $null
    $stream = $null
    try {
        $fullPath = [IO.Path]::GetFullPath($ConfigPath)
        $temporaryPath = $fullPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        $json = $Configuration | ConvertTo-Json -Depth 8
        $bytes = [Text.Encoding]::UTF8.GetBytes($json + [Environment]::NewLine)
        if ($bytes.Length -gt 1MB) { throw 'Configuration too large.' }
        $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Dispose()
        $stream = $null
        Set-PrivateFilePermissions -Path $temporaryPath
        $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        if ([IO.File]::Exists($fullPath)) {
            [IO.File]::Replace($temporaryPath, $fullPath, [NullString]::Value)
        }
        else {
            [IO.File]::Move($temporaryPath, $fullPath)
        }
    }
    catch {
        throw [InvalidOperationException]::new('Atomic configuration write failed.')
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $temporaryPath -and [IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

function Initialize-BackupCenterConfig {
    [CmdletBinding()]
    param(
        [string]$ConfigPath = $script:DefaultConfigPath,
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $lock = $null
    try {
        $lock = Open-ConfigurationLock -ConfigPath $ConfigPath
        if ([IO.File]::Exists($ConfigPath)) {
            $null = Read-SecretConfiguration -ConfigPath $ConfigPath
        }
        else {
            $configuration = [pscustomobject][ordered]@{
                SchemaVersion = 1
                Application = 'BackupCenter'
                ProtectionScope = 'CurrentUser'
                Secrets = [pscustomobject]@{}
            }
            Write-SecurityLog -Operation 'Config.Initialize.Prepare' -Outcome Success -LogDirectory $LogDirectory
            Write-SecretConfiguration -ConfigPath $ConfigPath -Configuration $configuration
        }
        Write-SecurityLog -Operation 'Config.Initialize' -Outcome Success -LogDirectory $LogDirectory
    }
    catch {
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Config.Initialize' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('Configuration initialization failed. Check permissions, audit logs and file format.')
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

function Set-BackupSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z')][string]$Name,
        [Parameter(Mandatory)][Security.SecureString]$Secret,
        [string]$ConfigPath = $script:DefaultConfigPath,
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $lock = $null
    try {
        $lock = Open-ConfigurationLock -ConfigPath $ConfigPath
        $configuration = Read-SecretConfiguration -ConfigPath $ConfigPath
        $encrypted = Protect-BackupSecret -Secret $Secret -LogDirectory $LogDirectory
        $configuration.Secrets | Add-Member -MemberType NoteProperty -Name $Name -Value $encrypted -Force -ErrorAction Stop
        Write-SecurityLog -Operation 'Config.Secret.Set.Prepare' -Outcome Success -LogDirectory $LogDirectory
        Write-SecretConfiguration -ConfigPath $ConfigPath -Configuration $configuration
        Write-SecurityLog -Operation 'Config.Secret.Set' -Outcome Success -LogDirectory $LogDirectory
    }
    catch {
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Config.Secret.Set' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('Secret storage failed. Check configuration, permissions and audit logs.')
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

function Get-BackupSecret {
    [CmdletBinding()]
    [OutputType([Security.SecureString])]
    param(
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z')][string]$Name,
        [string]$ConfigPath = $script:DefaultConfigPath,
        [string]$LogDirectory = $script:DefaultLogDirectory
    )
    $lock = $null
    $result = $null
    try {
        $lock = Open-ConfigurationLock -ConfigPath $ConfigPath
        $configuration = Read-SecretConfiguration -ConfigPath $ConfigPath
        $property = $configuration.Secrets.PSObject.Properties[$Name]
        if ($null -eq $property) { throw 'Secret not found.' }
        $result = Unprotect-BackupSecret -ProtectedSecret $property.Value -LogDirectory $LogDirectory
        Write-SecurityLog -Operation 'Config.Secret.Get' -Outcome Success -LogDirectory $LogDirectory
        return $result
    }
    catch {
        if ($null -ne $result) { $result.Dispose() }
        if ($_.Exception.Data['SecurityCode'] -eq 'AuditUnavailable') { throw }
        Write-SecurityLog -Operation 'Config.Secret.Get' -Outcome Error -LogDirectory $LogDirectory
        throw [InvalidOperationException]::new('Secret retrieval failed. Check the secret name, configuration and Windows identity.')
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

Export-ModuleMember -Function Protect-BackupSecret, Unprotect-BackupSecret, New-TotpSecret, Get-TotpCode, Test-TotpCode, Initialize-BackupCenterConfig, Set-BackupSecret, Get-BackupSecret
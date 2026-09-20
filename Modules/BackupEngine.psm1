#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Security.psd1') -ErrorAction Stop

$script:ProjectRoot = Split-Path $PSScriptRoot -Parent
$script:StepNames = @('Export/Pull', 'Compress & Encrypt', 'Upload', 'Archive', 'Offsite', 'VERIFY')

function Stop-BackupOperation {
    param([Parameter(Mandatory)][string]$Code)
    $exception = [InvalidOperationException]::new('BackupCenter: ' + $Code)
    $exception.Data['BackupCode'] = $Code
    throw $exception
}

function Write-BackupEvent {
    param(
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$JobId,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)][string]$Status,
        [string]$ErrorCode
    )
    $stream = $null
    try {
        $null = [IO.Directory]::CreateDirectory($LogDirectory)
        $now = [DateTimeOffset]::UtcNow
        $entry = [ordered]@{
            TimestampUtc = $now.ToString('o'); Component = 'BackupCenter.BackupEngine'
            JobId = $JobId; RunId = $RunId; Step = $Step; Status = $Status
            ErrorCode = $ErrorCode; ProcessId = $PID
        } | ConvertTo-Json -Compress
        $path = Join-Path $LogDirectory ('backup-{0}.jsonl' -f $now.ToString('yyyy-MM-dd'))
        $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $bytes = [Text.Encoding]::UTF8.GetBytes($entry + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    catch { Stop-BackupOperation 'AuditUnavailable' }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Open-BackupLock {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullPath))
        return [IO.File]::Open($fullPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch { Stop-BackupOperation 'LockBusyOrUnavailable' }
}

function Protect-BackupWorkDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $identity = $null
    try {
        $null = [IO.Directory]::CreateDirectory($Path)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
            $null = $acl.RemoveAccessRuleSpecific($rule)
        }
        foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
            $null = $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
    catch { Stop-BackupOperation 'WorkDirectoryProtectionFailed' }
    finally { if ($null -ne $identity) { $identity.Dispose() } }
}

function Assert-BackupJob {
    param([Parameter(Mandatory)][pscustomobject]$Job)
    try {
        $identifier = [Guid]::Empty
        if (-not [Guid]::TryParseExact([string]$Job.Id, 'D', [ref]$identifier)) { throw 'Invalid identifier.' }
        if ($Job.Name -isnot [string] -or $Job.Name -notmatch '\A[A-Za-z0-9][A-Za-z0-9_. -]{0,79}\z') { throw 'Invalid name.' }
        if ($Job.SourceKind -cnotin @('Local', 'Rclone')) { throw 'Invalid source kind.' }
        foreach ($value in @($Job.SourcePath, $Job.PrimaryDestination, $Job.OffsiteDestination, $Job.ArchiveDirectory)) {
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value -match '[\x00-\x1f]') { throw 'Invalid path.' }
        }
        foreach ($remote in @($Job.PrimaryDestination, $Job.OffsiteDestination)) {
            if ($remote -notmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{1,63}:[^\r\n]*\z') { throw 'Use a named rclone remote.' }
        }
        if ($Job.PrimaryDestination.TrimEnd('/') -ieq $Job.OffsiteDestination.TrimEnd('/')) { throw 'Distinct destinations required.' }
        if ($Job.SourceKind -eq 'Rclone' -and $Job.SourcePath -notmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{1,63}:[^\r\n]*\z') { throw 'Invalid pull remote.' }
        if ($Job.Recipient -isnot [string] -or $Job.Recipient -cnotmatch '\Aage1[a-z0-9]{58}\z') { throw 'Invalid age recipient.' }
        if ($Job.RequireRemoteHash -isnot [bool]) { throw 'Invalid verification policy.' }
        $allowed = @('Id', 'Name', 'SourceKind', 'SourcePath', 'PrimaryDestination', 'OffsiteDestination', 'ArchiveDirectory', 'Recipient', 'RequireRemoteHash')
        foreach ($property in $Job.PSObject.Properties) {
            if ($property.Name -cnotin $allowed) { throw 'Unexpected job field.' }
        }
    }
    catch { Stop-BackupOperation 'InvalidJobDefinition' }
}

function New-BackupJob {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$SourcePath,
        [Parameter(ParameterSetName = 'Path')][ValidateSet('Local', 'Rclone')][string]$SourceKind = 'Local',
        [Parameter(Mandatory, ParameterSetName = 'Export')][pscustomobject]$ExportResult,
        [Parameter(Mandatory)][string]$PrimaryDestination,
        [Parameter(Mandatory)][string]$OffsiteDestination,
        [Parameter(Mandatory)][string]$ArchiveDirectory,
        [Parameter(Mandatory)][string]$Recipient,
        [switch]$RequireRemoteHash
    )
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Export') {
            if ($ExportResult.SchemaVersion -ne 1 -or $ExportResult.Status -cne 'Success' -or
                $ExportResult.Provider -cnotin @('Proxmox', 'HyperV', 'VMware') -or $ExportResult.SourceKind -cne 'Local' -or
                [string]::IsNullOrWhiteSpace($ExportResult.SourcePath) -or -not [IO.Directory]::Exists($ExportResult.SourcePath) -or
                @($ExportResult.Files).Count -eq 0 -or $ExportResult.TotalBytes -le 0) {
                Stop-BackupOperation 'InvalidExportResult'
            }
            $SourcePath = $ExportResult.SourcePath
            $SourceKind = 'Local'
        }
        $job = [pscustomobject][ordered]@{
            Id = [Guid]::NewGuid().ToString('D'); Name = $Name; SourceKind = $SourceKind
            SourcePath = $(if ($SourceKind -eq 'Local') { [IO.Path]::GetFullPath($SourcePath) } else { $SourcePath })
            PrimaryDestination = $PrimaryDestination.TrimEnd('/'); OffsiteDestination = $OffsiteDestination.TrimEnd('/')
            ArchiveDirectory = [IO.Path]::GetFullPath($ArchiveDirectory); Recipient = $Recipient
            RequireRemoteHash = [bool]$RequireRemoteHash
        }
        Assert-BackupJob $job
        return $job
    }
    catch { Stop-BackupOperation 'InvalidJobDefinition' }
}

function Invoke-BackupCommand {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [scriptblock]$CommandRunner,
        [scriptblock]$OnProgress
    )
    $process = $null
    $processStarted = $false
    try {
        if ($null -ne $CommandRunner) {
            $response = & $CommandRunner $Executable $Arguments $OnProgress
        }
        else {
            $command = Get-Command -Name $Executable -CommandType Application -ErrorAction Stop | Select-Object -First 1
            $info = [Diagnostics.ProcessStartInfo]::new()
            $info.FileName = $command.Source
            $info.UseShellExecute = $false
            $info.CreateNoWindow = $true
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true
            $quoted = foreach ($argument in $Arguments) {
                $escaped = [regex]::Replace($argument, '(\\*)"', '$1$1\"')
                $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
                '"' + $escaped + '"'
            }
            $info.Arguments = $quoted -join ' '
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $info
            if (-not $process.Start()) { Stop-BackupOperation 'ProcessStartFailed' }
            $processStarted = $true
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            if ($null -ne $OnProgress) {
                $clock = [Diagnostics.Stopwatch]::StartNew(); $last = 0.0
                $progressBytes = 0L; $progressTotal = 0L; $progressSpeed = 0.0
                $lineTask = $process.StandardError.ReadLineAsync()
                while ($true) {
                    if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) { Stop-BackupOperation 'ProcessTimeout' }
                    if ($lineTask.Wait(1000)) {
                        $line = $lineTask.GetAwaiter().GetResult()
                        if ($null -eq $line) { break }
                        if ($line.Length -lt 65536) {
                            try {
                                $entry = $line | ConvertFrom-Json -ErrorAction Stop
                                if ($null -ne $entry.PSObject.Properties['stats']) {
                                    $values = @($entry.stats.bytes, $entry.stats.totalBytes, $entry.stats.speed)
                                    $valid = $true
                                    foreach ($value in $values) {
                                        if (($value -isnot [int] -and $value -isnot [long] -and $value -isnot [double]) -or
                                            [double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0 -or $value -gt [long]::MaxValue) { $valid = $false }
                                    }
                                    if ($valid) { $progressBytes = [long]$values[0]; $progressTotal = [long]$values[1]; $progressSpeed = [double]$values[2] }
                                }
                            } catch { }
                        }
                        $lineTask = $process.StandardError.ReadLineAsync()
                    }
                    if ($clock.Elapsed.TotalSeconds - $last -ge 2) {
                        $null = & $OnProgress $progressBytes $progressTotal $progressSpeed
                        $last = $clock.Elapsed.TotalSeconds
                    }
                }
                $remainingMs = [int][Math]::Max(1, ($TimeoutSeconds - $clock.Elapsed.TotalSeconds) * 1000)
                if (-not $process.WaitForExit($remainingMs)) { Stop-BackupOperation 'ProcessTimeout' }
                $null = & $OnProgress $progressBytes $progressTotal $progressSpeed
            }
            else {
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit($TimeoutSeconds * 1000)) { Stop-BackupOperation 'ProcessTimeout' }
                $null = $stderrTask.GetAwaiter().GetResult()
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $response = [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout }
        }
        if ($response -isnot [pscustomobject] -or $response.ExitCode -isnot [int] -or $response.ExitCode -ne 0) {
            Stop-BackupOperation 'ExternalCommandFailed'
        }
        if ($response.Stdout -isnot [string]) { Stop-BackupOperation 'InvalidCommandResponse' }
        return $response.Stdout
    }
    catch {
        if ($_.Exception.Data.Contains('BackupCode')) { throw }
        Stop-BackupOperation 'ExternalCommandFailed'
    }
    finally {
        if ($null -ne $process) {
            try {
                if ($processStarted -and -not $process.HasExited) {
                    $process.Kill()
                    $process.WaitForExit()
                }
            }
            finally { $process.Dispose() }
        }
    }
}

function Get-BackupArchiveKey {
    param([string]$Name, [string]$ConfigPath, [string]$LogDirectory)
    $secret = $null; $pointer = [IntPtr]::Zero
    try {
        $secret = Get-BackupSecret -Name $Name -ConfigPath $ConfigPath -LogDirectory $LogDirectory
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        $bytes = [Convert]::FromBase64String([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
        if ($bytes.Length -ne 64) { Stop-BackupOperation 'InvalidArchiveKey' }
        return ,$bytes
    }
    finally {
        if ($null -ne $secret) { $secret.Dispose() }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Get-BackupArchiveMac {
    param([IO.Stream]$Stream, [byte[]]$Key, [long]$Length, [scriptblock]$OnProgress)
    $mac = [Security.Cryptography.HMACSHA256]::new($Key)
    $buffer = New-Object byte[] 1048576
    $clock = [Diagnostics.Stopwatch]::StartNew(); $last = 0.0; $processed = 0L
    try {
        $Stream.Position = 0
        while ($processed -lt $Length) {
            $count = $Stream.Read($buffer, 0, [int][Math]::Min($buffer.Length, $Length - $processed))
            if ($count -le 0) { Stop-BackupOperation 'TruncatedArchive' }
            $null = $mac.TransformBlock($buffer, 0, $count, $buffer, 0)
            $processed += $count
            if ($null -ne $OnProgress -and $clock.Elapsed.TotalSeconds - $last -ge 2) {
                $null = & $OnProgress $processed $Length ($processed / [Math]::Max(0.001, $clock.Elapsed.TotalSeconds))
                $last = $clock.Elapsed.TotalSeconds
            }
        }
        $null = $mac.TransformFinalBlock([byte[]]@(), 0, 0)
        return ,$mac.Hash
    }
    finally { $mac.Dispose(); [Array]::Clear($buffer, 0, $buffer.Length) }
}

function Protect-BackupArchive {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourcePath, [Parameter(Mandatory)][string]$OutputPath,
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'Config\secrets.json'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'), [scriptblock]$OnProgress)
    $key = New-Object byte[] 64; $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    $secret = $null; $source = $null; $output = $null; $aes = $null; $crypto = $null; $transform = $null
    $created = $false; $completed = $false; $buffer = New-Object byte[] 1048576
    $identifier = [guid]::NewGuid(); $secretName = 'Archive.' + $identifier.ToString('D')
    try {
        if ([IO.File]::Exists($OutputPath)) { Stop-BackupOperation 'ArtifactAlreadyExists' }
        $source = [IO.File]::Open($SourcePath, 'Open', 'Read', 'Read')
        if ($source.Length -le 0) { Stop-BackupOperation 'EmptyExport' }
        $random.GetBytes($key)
        $secret = ConvertTo-SecureString ([Convert]::ToBase64String($key)) -AsPlainText -Force
        Initialize-BackupCenterConfig -ConfigPath $ConfigPath -LogDirectory $LogDirectory
        Set-BackupSecret -Name $secretName -Secret $secret -ConfigPath $ConfigPath -LogDirectory $LogDirectory
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = [byte[]]$key[0..31]; $aes.GenerateIV()
        $header = [Text.Encoding]::ASCII.GetBytes('BCA1') + $identifier.ToByteArray() + $aes.IV
        $output = [IO.File]::Open($OutputPath, 'CreateNew', 'ReadWrite', 'None'); $created = $true
        $output.Write($header, 0, $header.Length)
        $transform = $aes.CreateEncryptor()
        $crypto = [Security.Cryptography.CryptoStream]::new($output, $transform, [Security.Cryptography.CryptoStreamMode]::Write, $true)
        $clock = [Diagnostics.Stopwatch]::StartNew(); $last = 0.0; $processed = 0L
        while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $crypto.Write($buffer, 0, $count); $processed += $count
            if ($null -ne $OnProgress -and $clock.Elapsed.TotalSeconds - $last -ge 2) {
                $null = & $OnProgress $processed $source.Length ($processed / [Math]::Max(0.001, $clock.Elapsed.TotalSeconds))
                $last = $clock.Elapsed.TotalSeconds
            }
        }
        $crypto.FlushFinalBlock(); $crypto.Dispose(); $crypto = $null
        $tag = Get-BackupArchiveMac -Stream $output -Key ([byte[]]$key[32..63]) -Length $output.Length -OnProgress $OnProgress
        $output.Position = $output.Length; $output.Write($tag, 0, $tag.Length); $output.Flush($true)
        $completed = $true
        [pscustomobject]@{ Path = [IO.Path]::GetFullPath($OutputPath); SecretName = $secretName; Format = 'BCA1-AES256-CBC-HMACSHA256'; Size = $output.Length }
    }
    catch { Stop-BackupOperation 'ArchiveEncryptionFailed' }
    finally {
        foreach ($resource in @($crypto, $transform, $aes, $source, $output, $secret, $random)) { if ($null -ne $resource) { $resource.Dispose() } }
        [Array]::Clear($key, 0, $key.Length); [Array]::Clear($buffer, 0, $buffer.Length)
        if ($created -and -not $completed) { [IO.File]::Delete($OutputPath) }
    }
}

function Unprotect-BackupArchive {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourcePath, [Parameter(Mandatory)][string]$OutputPath,
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'Config\secrets.json'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'))
    $source = $null; $output = $null; $aes = $null; $crypto = $null; $transform = $null; $key = $null
    $created = $false; $completed = $false; $buffer = New-Object byte[] 1048576
    try {
        if ([IO.File]::Exists($OutputPath)) { Stop-BackupOperation 'ArtifactAlreadyExists' }
        $source = [IO.File]::Open($SourcePath, 'Open', 'Read', 'Read')
        $header = New-Object byte[] 36
        if ($source.Length -lt 84 -or ($source.Length - 68) % 16 -ne 0 -or $source.Read($header, 0, 36) -ne 36 -or
            [Text.Encoding]::ASCII.GetString($header, 0, 4) -cne 'BCA1') { Stop-BackupOperation 'InvalidArchiveFormat' }
        $identifier = [guid]::new([byte[]]$header[4..19])
        $key = Get-BackupArchiveKey -Name ('Archive.' + $identifier.ToString('D')) -ConfigPath $ConfigPath -LogDirectory $LogDirectory
        $tag = Get-BackupArchiveMac -Stream $source -Key ([byte[]]$key[32..63]) -Length ($source.Length - 32)
        $storedTag = New-Object byte[] 32
        if ($source.Read($storedTag, 0, 32) -ne 32) { Stop-BackupOperation 'TruncatedArchive' }
        $difference = 0
        for ($index = 0; $index -lt 32; $index++) { $difference = $difference -bor ($tag[$index] -bxor $storedTag[$index]) }
        if ($difference -ne 0) { Stop-BackupOperation 'ArchiveAuthenticationFailed' }
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = [byte[]]$key[0..31]; $aes.IV = [byte[]]$header[20..35]
        $output = [IO.File]::Open($OutputPath, 'CreateNew', 'Write', 'None'); $created = $true
        $transform = $aes.CreateDecryptor()
        $crypto = [Security.Cryptography.CryptoStream]::new($output, $transform, [Security.Cryptography.CryptoStreamMode]::Write, $true)
        $source.Position = 36; $remaining = $source.Length - 68
        while ($remaining -gt 0) {
            $count = $source.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining))
            if ($count -le 0) { Stop-BackupOperation 'TruncatedArchive' }
            $crypto.Write($buffer, 0, $count); $remaining -= $count
        }
        $crypto.FlushFinalBlock(); $output.Flush($true); $completed = $true
    }
    catch { Stop-BackupOperation 'ArchiveDecryptionFailed' }
    finally {
        foreach ($resource in @($crypto, $transform, $aes, $source, $output)) { if ($null -ne $resource) { $resource.Dispose() } }
        if ($null -ne $key) { [Array]::Clear($key, 0, $key.Length) }
        [Array]::Clear($buffer, 0, $buffer.Length)
        if ($created -and -not $completed) { [IO.File]::Delete($OutputPath) }
    }
}

function Test-BackupRemoteArtifact {
    param(
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][hashtable]$Hashes,
        [Parameter(Mandatory)][long]$ExpectedSize,
        [Parameter(Mandatory)][bool]$RequireRemoteHash,
        [Parameter(Mandatory)][hashtable]$CommandOptions
    )
    try {
        $json = Invoke-BackupCommand @CommandOptions -Arguments @('lsjson', '--stat', '--hash', '--', $RemotePath)
        if ($json.Length -gt 1MB) { Stop-BackupOperation 'RemoteMetadataInvalid' }
        $metadata = $json | ConvertFrom-Json -ErrorAction Stop
        if ($metadata -isnot [pscustomobject] -or $metadata.IsDir -isnot [bool] -or $metadata.IsDir -or
            $metadata.Name -cne [IO.Path]::GetFileName($ArtifactPath)) { Stop-BackupOperation 'RemoteObjectMissingOrInvalid' }
        if (($metadata.Size -isnot [long] -and $metadata.Size -isnot [int]) -or $metadata.Size -ne $ExpectedSize) {
            Stop-BackupOperation 'RemoteSizeMismatch'
        }
        $algorithm = $null
        $remoteHash = $null
        $hashProperty = $metadata.PSObject.Properties['Hashes']
        if ($null -ne $hashProperty -and $null -ne $hashProperty.Value) {
            foreach ($candidate in @(
                @{ Remote = 'SHA-256'; Local = 'SHA256'; Length = 64 },
                @{ Remote = 'SHA-1'; Local = 'SHA1'; Length = 40 },
                @{ Remote = 'MD5'; Local = 'MD5'; Length = 32 }
            )) {
                $property = $hashProperty.Value.PSObject.Properties[$candidate.Remote]
                if ($null -eq $property -or [string]::IsNullOrEmpty([string]$property.Value)) { continue }
                if ($property.Value -isnot [string] -or $property.Value -notmatch ('\A[0-9a-fA-F]{' + $candidate.Length + '}\z')) {
                    Stop-BackupOperation 'RemoteHashInvalid'
                }
                $algorithm = $candidate.Local
                if (-not $Hashes.ContainsKey($algorithm)) {
                    $Hashes[$algorithm] = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm $algorithm -ErrorAction Stop).Hash
                }
                $remoteHash = $property.Value
                if ($remoteHash -ine $Hashes[$algorithm]) { Stop-BackupOperation 'RemoteHashMismatch' }
                break
            }
        }
        if ($RequireRemoteHash -and $null -eq $algorithm) { Stop-BackupOperation 'RemoteHashUnavailable' }
        return [pscustomobject]@{
            Destination = $RemotePath; Status = 'Success'; Method = $(if ($null -eq $algorithm) { 'Size' } else { 'HashAndSize' })
            ExpectedSize = $ExpectedSize; ActualSize = [long]$metadata.Size; HashAlgorithm = $algorithm
            ExpectedHash = $(if ($null -ne $algorithm) { $Hashes[$algorithm] } else { $null }); ActualHash = $remoteHash
            CheckedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        }
    }
    catch {
        if ($_.Exception.Data.Contains('BackupCode')) { throw }
        Stop-BackupOperation 'RemoteMetadataInvalid'
    }
}

function ConvertTo-BackupErrorRecord {
    param([System.Management.Automation.ErrorRecord]$Record, [string]$Code)
    [pscustomobject][ordered]@{
        Sanitized = $true
        ExceptionType = $Record.Exception.GetType().FullName
        Message = 'BackupCenter: ' + $Code
        Category = $Record.CategoryInfo.Category.ToString()
        ScriptLineNumber = $Record.InvocationInfo.ScriptLineNumber
    }
}

function Publish-BackupProgress {
    param([pscustomobject]$Result, [string]$Step, [string]$Status, [string]$LogDirectory, [string]$QueuePath, [string]$ErrorCode)
    Write-BackupEvent -LogDirectory $LogDirectory -JobId $Result.JobId -RunId $Result.RunId -Step $Step -Status $Status -ErrorCode $ErrorCode
    if (-not [string]::IsNullOrEmpty($QueuePath)) { Update-QueuedBackupResult -QueuePath $QueuePath -Result $Result }
}

function Invoke-BackupPipelineCore {
    param(
        [pscustomobject]$Job, [string]$WorkDirectory, [string]$LogDirectory,
        [string]$RclonePath, [string]$AgePath, [int]$CommandTimeoutSeconds,
        [scriptblock]$CommandRunner, [string]$QueuePath, [string]$RunId = [Guid]::NewGuid().ToString('D')
    )
    Assert-BackupJob $Job
    $workPath = Join-Path ([IO.Path]::GetFullPath($WorkDirectory)) $RunId
    $exportPath = Join-Path $workPath 'export'
    $zipPath = Join-Path $workPath 'payload.zip'
    $artifactName = 'backup-{0}-{1}.zip.age' -f $Job.Id, $RunId
    $artifactPath = Join-Path $workPath $artifactName
    $archivePath = Join-Path $Job.ArchiveDirectory $artifactName
    $primaryPath = $Job.PrimaryDestination + '/' + $artifactName
    $offsitePath = $Job.OffsiteDestination + '/' + $artifactName
    $result = [pscustomobject][ordered]@{
        JobId = $Job.Id; RunId = $RunId; Status = 'Running'; StartedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        CompletedUtc = $null; ErrorCode = $null; ErrorRecord = $null; CleanupStatus = 'Pending'; CleanupErrorRecord = $null
        ArtifactPath = $artifactPath; ArchivePath = $archivePath; PrimaryPath = $primaryPath; OffsitePath = $offsitePath
        Steps = @($script:StepNames | ForEach-Object {
            [pscustomobject][ordered]@{ Name = $_; Status = 'Pending'; StartedUtc = $null; CompletedUtc = $null; DurationMs = 0L; ErrorCode = $null; ErrorRecord = $null; Details = $null }
        })
    }
    $commandOptions = @{ Executable = $RclonePath; TimeoutSeconds = $CommandTimeoutSeconds; CommandRunner = $CommandRunner }
    $hashes = @{}
    $expectedSize = 0L
    try {
        foreach ($step in $result.Steps) {
            $step.Status = 'Running'
            $step.StartedUtc = [DateTimeOffset]::UtcNow.ToString('o')
            $timer = [Diagnostics.Stopwatch]::StartNew()
            try {
                Publish-BackupProgress $result $step.Name 'Running' $LogDirectory $QueuePath
                switch ($step.Name) {
                    'Export/Pull' {
                        if ($Job.SourceKind -eq 'Local') {
                            $source = Get-Item -LiteralPath $Job.SourcePath -Force -ErrorAction Stop
                            $sourcePrefix = $source.FullName.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                            if ($source.PSIsContainer -and $workPath.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
                                Stop-BackupOperation 'WorkDirectoryInsideSource'
                            }
                            $items = @($source)
                            if ($source.PSIsContainer) { $items += @(Get-ChildItem -LiteralPath $source.FullName -Recurse -Force -ErrorAction Stop) }
                            foreach ($item in $items) {
                                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-BackupOperation 'SourceReparsePointNotAllowed' }
                            }
                        }
                        Protect-BackupWorkDirectory $workPath
                        $null = [IO.Directory]::CreateDirectory($exportPath)
                        if ($Job.SourceKind -eq 'Local') {
                            Copy-Item -LiteralPath $Job.SourcePath -Destination (Join-Path $exportPath 'source') -Recurse -Force -ErrorAction Stop
                        }
                        else {
                            $null = Invoke-BackupCommand @commandOptions -Arguments @('copy', '--', $Job.SourcePath, $exportPath)
                        }
                        $files = @(Get-ChildItem -LiteralPath $exportPath -File -Recurse -Force -ErrorAction Stop)
                        if ($files.Count -eq 0) { Stop-BackupOperation 'EmptyExport' }
                        $step.Details = [pscustomobject]@{ FileCount = $files.Count; SourceKind = $Job.SourceKind }
                    }
                    'Compress & Encrypt' {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
                        [IO.Compression.ZipFile]::CreateFromDirectory($exportPath, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
                        $null = Invoke-BackupCommand -Executable $AgePath -TimeoutSeconds $CommandTimeoutSeconds -CommandRunner $CommandRunner -Arguments @(
                            '--encrypt', '--recipient', $Job.Recipient, '--output', $artifactPath, '--', $zipPath)
                        if (-not [IO.File]::Exists($artifactPath)) { Stop-BackupOperation 'EncryptedArtifactMissing' }
                        $expectedSize = [IO.FileInfo]::new($artifactPath).Length
                        if ($expectedSize -le 0) { Stop-BackupOperation 'EncryptedArtifactEmpty' }
                        $hashes.SHA256 = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash
                        $step.Details = [pscustomobject]@{ Format = 'zip.age'; Size = $expectedSize; SHA256 = $hashes.SHA256 }
                    }
                    'Upload' {
                        $null = Invoke-BackupCommand @commandOptions -Arguments @('copyto', '--transfers', '8', '--checkers', '8', '--drive-chunk-size', '256M', '--buffer-size', '128M', '--', $artifactPath, $primaryPath)
                        $step.Details = [pscustomobject]@{ Destination = $primaryPath; Verified = $false }
                    }
                    'Archive' {
                        $null = [IO.Directory]::CreateDirectory($Job.ArchiveDirectory)
                        [IO.File]::Copy($artifactPath, $archivePath, $false)
                        $step.Details = [pscustomobject]@{ Path = $archivePath; Verified = $false }
                    }
                    'Offsite' {
                        $null = Invoke-BackupCommand @commandOptions -Arguments @('copyto', '--transfers', '8', '--checkers', '8', '--drive-chunk-size', '256M', '--buffer-size', '128M', '--', $archivePath, $offsitePath)
                        $step.Details = [pscustomobject]@{ Destination = $offsitePath; Verified = $false }
                    }
                    'VERIFY' {
                        $step.Details = [pscustomobject]@{ Primary = $null; Archive = $null; Offsite = $null }
                        if ([IO.FileInfo]::new($artifactPath).Length -ne $expectedSize -or
                            (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash -ine $hashes.SHA256) {
                            Stop-BackupOperation 'LocalArtifactChanged'
                        }
                        $verifyOptions = @{ ArtifactPath = $artifactPath; Hashes = $hashes; ExpectedSize = $expectedSize; RequireRemoteHash = $Job.RequireRemoteHash; CommandOptions = $commandOptions }
                        $step.Details.Primary = Test-BackupRemoteArtifact @verifyOptions -RemotePath $primaryPath
                        if ([IO.FileInfo]::new($archivePath).Length -ne $expectedSize -or
                            (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256 -ErrorAction Stop).Hash -ine $hashes.SHA256) {
                            Stop-BackupOperation 'ArchiveIntegrityMismatch'
                        }
                        $step.Details.Archive = [pscustomobject]@{ Status = 'Success'; Method = 'HashAndSize'; SHA256 = $hashes.SHA256; Size = $expectedSize }
                        $step.Details.Offsite = Test-BackupRemoteArtifact @verifyOptions -RemotePath $offsitePath
                    }
                }
                $step.Status = 'Success'
            }
            catch {
                $step.Status = 'Failed'
                $step.ErrorCode = if ($_.Exception.Data.Contains('BackupCode')) { [string]$_.Exception.Data['BackupCode'] } else { 'StepExecutionFailed' }
                $step.ErrorRecord = ConvertTo-BackupErrorRecord -Record $_ -Code $step.ErrorCode
                $result.Status = 'Failed'
                $result.ErrorCode = $step.ErrorCode
                $result.ErrorRecord = $step.ErrorRecord
                foreach ($remaining in $result.Steps) {
                    if ($remaining.Status -eq 'Pending') { $remaining.Status = 'Skipped'; $remaining.ErrorCode = 'PreviousStepFailed' }
                }
            }
            finally {
                $timer.Stop()
                $step.CompletedUtc = [DateTimeOffset]::UtcNow.ToString('o')
                $step.DurationMs = $timer.ElapsedMilliseconds
            }
            Publish-BackupProgress $result $step.Name $step.Status $LogDirectory $QueuePath $step.ErrorCode
            if ($step.Status -eq 'Failed') { break }
        }
    }
    finally {
        try {
            if ([IO.Directory]::Exists($exportPath)) { Remove-Item -LiteralPath $exportPath -Recurse -Force -ErrorAction Stop }
            if ([IO.File]::Exists($zipPath)) { [IO.File]::Delete($zipPath) }
            $result.CleanupStatus = 'Success'
        }
        catch {
            $result.CleanupStatus = 'Failed'
            $result.Status = 'Failed'
            $result.ErrorCode = 'PlaintextCleanupFailed'
            $result.CleanupErrorRecord = ConvertTo-BackupErrorRecord -Record $_ -Code 'PlaintextCleanupFailed'
            if ($null -eq $result.ErrorRecord) { $result.ErrorRecord = $result.CleanupErrorRecord }
        }
    }
    if ($result.Status -eq 'Running') { $result.Status = 'Success' }
    $result.CompletedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    Publish-BackupProgress $result 'Pipeline' $result.Status $LogDirectory $QueuePath $result.ErrorCode
    return $result
}

function Start-BackupPipeline {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Job,
        [string]$WorkDirectory = (Join-Path $script:ProjectRoot 'Work'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock'),
        [string]$RclonePath = 'rclone.exe',
        [string]$AgePath = 'age.exe',
        [ValidateRange(1, 86400)][int]$CommandTimeoutSeconds = 3600,
        [scriptblock]$CommandRunner
    )
    $lock = $null
    try {
        $lock = Open-BackupLock $EngineLockPath
        return Invoke-BackupPipelineCore -Job $Job -WorkDirectory $WorkDirectory -LogDirectory $LogDirectory -RclonePath $RclonePath -AgePath $AgePath -CommandTimeoutSeconds $CommandTimeoutSeconds -CommandRunner $CommandRunner
    }
    catch {
        Write-BackupEvent -LogDirectory $LogDirectory -JobId ([Guid]::Empty.ToString('D')) -RunId ([Guid]::Empty.ToString('D')) -Step 'Pipeline' -Status 'Error' -ErrorCode 'PipelineUnavailable'
        throw
    }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
}

function Invoke-ProxmoxTransferPipeline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$ResolveArchive,
        [Parameter(Mandatory)][string]$SftpHost, [Parameter(Mandatory)][pscustomobject]$Settings,
        [Parameter(Mandatory)][scriptblock]$OnProgress,
        [string]$WorkDirectory = (Join-Path $script:ProjectRoot 'Temp'),
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'Config\secrets.json'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock'),
        [ValidateRange(1, 86400)][int]$CommandTimeoutSeconds = 3600, [scriptblock]$CommandRunner)
    $runId = [guid]::NewGuid().ToString('D')
    $state = [pscustomobject]@{ Status = 'Running'; ErrorCode = $null; Artifact = $null; Progress = $null
        Steps = @($script:StepNames | ForEach-Object { [pscustomobject]@{ Name = $_; Status = 'Skipped' } }) }
    $lock = $null; $plainPath = $null; $partialPath = $null; $step = $null
    try {
        $lock = Open-BackupLock $EngineLockPath
        if ($SftpHost -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9.-]*\z' -or
            $Settings.SftpUser -cnotmatch '\A[A-Za-z_][A-Za-z0-9_.-]{0,63}\z' -or
            ($Settings.SftpPort -isnot [int] -and $Settings.SftpPort -isnot [long]) -or $Settings.SftpPort -lt 1 -or $Settings.SftpPort -gt 65535 -or
            $Settings.UploadDestination -isnot [string] -or $Settings.UploadDestination -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{1,63}:[^\x00-\x1f]+\z') {
            Stop-BackupOperation 'InvalidTransferConfiguration'
        }
        foreach ($path in @($Settings.KnownHostsFile, $Settings.PrivateKeyFile)) {
            if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path) -or -not [IO.File]::Exists($path)) { Stop-BackupOperation 'SSHFilesRequired' }
        }
        $rclone = [string]$Settings.RclonePath
        if ([string]::IsNullOrWhiteSpace($rclone)) { Stop-BackupOperation 'RcloneRequired' }
        if ($null -eq $CommandRunner) { $null = Get-Command -Name $rclone -CommandType Application -ErrorAction Stop }
        $workPath = Join-Path ([IO.Path]::GetFullPath($WorkDirectory)) $runId
        Protect-BackupWorkDirectory $workPath
        for ($stage = 0; $stage -lt 3; $stage++) {
            $step = $state.Steps[$stage]; $step.Status = 'Running'; $state.Progress = $null
            Write-BackupEvent $LogDirectory $runId $runId $step.Name 'Running'
            $null = & $OnProgress $state
            $progress = {
                param($Bytes, $TotalBytes, $BytesPerSecond)
                $state.Progress = [pscustomobject]@{ Step = $step.Name; Bytes = [long]$Bytes; TotalBytes = [long]$TotalBytes; BytesPerSecond = [double]$BytesPerSecond }
                $null = & $OnProgress $state
            }.GetNewClosure()
            switch ($stage) {
                0 {
                    $archive = & $ResolveArchive
                    if ($archive.FileName -cnotmatch '\Avzdump-qemu-[0-9]+-[0-9_]{10}-[0-9_]{8}\.vma\.zst\z' -or
                        $archive.RemotePath -cnotmatch '\A/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\z' -or
                        $archive.RemotePath.Split('/') -contains '..' -or $archive.RemotePath.Split('/') -contains '.' -or
                        $archive.RemotePath.Split('/')[-1] -cne $archive.FileName -or $archive.Size -le 0) { Stop-BackupOperation 'InvalidPullArtifact' }
                    $plainPath = Join-Path $workPath $archive.FileName; $partialPath = $plainPath + '.partial'
                    $arguments = @('copyto', '--sftp-host', $SftpHost, '--sftp-port', [string]$Settings.SftpPort,
                        '--sftp-user', $Settings.SftpUser, '--sftp-key-file', $Settings.PrivateKeyFile,
                        '--sftp-known-hosts-file', $Settings.KnownHostsFile, '--sftp-disable-hashcheck',
                        '--sftp-shell-type', 'none', '--inplace',
                        '--use-json-log', '--stats', '2s', '--stats-log-level', 'NOTICE', '--log-level', 'NOTICE',
                        '--retries', '1', '--low-level-retries', '1', '--', (':sftp:' + $archive.RemotePath), $partialPath)
                    $null = Invoke-BackupCommand -Executable $rclone -Arguments $arguments -TimeoutSeconds $CommandTimeoutSeconds -CommandRunner $CommandRunner -OnProgress $progress
                    if (-not [IO.File]::Exists($partialPath) -or [IO.FileInfo]::new($partialPath).Length -ne $archive.Size) { Stop-BackupOperation 'PullSizeMismatch' }
                    [IO.File]::Move($partialPath, $plainPath)
                }
                1 {
                    $state.Artifact = Protect-BackupArchive -SourcePath $plainPath -OutputPath (Join-Path $workPath ('backup-' + $runId + '.vma.zst.bca')) `
                        -ConfigPath $ConfigPath -LogDirectory $LogDirectory -OnProgress $progress
                    [IO.File]::Delete($plainPath)
                }
                2 {
                    $arguments = @('copy', '--transfers', '8', '--checkers', '8', '--drive-chunk-size', '256M', '--buffer-size', '128M',
                        '--use-json-log', '--stats', '2s', '--stats-log-level', 'NOTICE', '--log-level', 'NOTICE',
                        '--retries', '1', '--', $state.Artifact.Path, $Settings.UploadDestination)
                    $null = Invoke-BackupCommand -Executable $rclone -Arguments $arguments -TimeoutSeconds $CommandTimeoutSeconds -CommandRunner $CommandRunner -OnProgress $progress
                    $remotePath = $Settings.UploadDestination.TrimEnd('/') + '/' + [IO.Path]::GetFileName($state.Artifact.Path)
                    $commandOptions = @{ Executable = $rclone; TimeoutSeconds = $CommandTimeoutSeconds; CommandRunner = $CommandRunner }
                    $hashes = @{}
                    $null = Test-BackupRemoteArtifact -RemotePath $remotePath -ArtifactPath $state.Artifact.Path -Hashes $hashes `
                        -ExpectedSize $state.Artifact.Size -RequireRemoteHash $false -CommandOptions $commandOptions
                }
            }
            $step.Status = 'Success'
            Write-BackupEvent $LogDirectory $runId $runId $step.Name 'Success'
            $null = & $OnProgress $state
        }
        $state.Status = 'Success'
    }
    catch {
        $state.Status = 'Failed'
        $state.ErrorCode = if ($_.Exception.Data.Contains('BackupCode')) { [string]$_.Exception.Data['BackupCode'] } elseif ($_.Exception.Data.Contains('HypervisorCode')) { [string]$_.Exception.Data['HypervisorCode'] } else { 'TransferPipelineFailed' }
        if ($null -ne $step) { $step.Status = 'Failed' }
    }
    finally {
        try {
            foreach ($path in @($plainPath, $partialPath)) { if ($path -and [IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
        }
        catch { $state.Status = 'Failed'; $state.ErrorCode = 'PlaintextCleanupFailed' }
        if ($null -ne $lock) { $lock.Dispose() }
    }
    Write-BackupEvent $LogDirectory $runId $runId 'TransferPipeline' $state.Status $state.ErrorCode
    $null = & $OnProgress $state
    return $state
}

function Read-BackupQueueFile {
    param([Parameter(Mandatory)][string]$QueuePath)
    try {
        if (-not [IO.File]::Exists($QueuePath)) {
            return [pscustomobject][ordered]@{ SchemaVersion = 1; Application = 'BackupCenter.BackupQueue'; Jobs = @() }
        }
        if ([IO.FileInfo]::new($QueuePath).Length -gt 16MB) { Stop-BackupOperation 'QueueTooLarge' }
        $queue = [IO.File]::ReadAllText($QueuePath, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
        if ($queue -isnot [pscustomobject] -or $queue.SchemaVersion -ne 1 -or
            $queue.Application -cne 'BackupCenter.BackupQueue' -or $queue.Jobs -isnot [array]) { throw 'Invalid queue schema.' }
        $identifiers = @{}
        foreach ($record in $queue.Jobs) {
            Assert-BackupJob $record.Job
            if ($record.JobId -cne $record.Job.Id -or $identifiers.ContainsKey($record.JobId) -or
                $record.Status -cnotin @('Pending', 'Running', 'Success', 'Failed', 'Interrupted')) { throw 'Invalid queue record.' }
            if ($null -eq $record.PSObject.Properties['Result']) { throw 'Missing result field.' }
            $identifiers[$record.JobId] = $true
        }
        return $queue
    }
    catch { Stop-BackupOperation 'QueueInvalidOrUnreadable' }
}

function Write-BackupQueueFile {
    param([Parameter(Mandatory)][string]$QueuePath, [Parameter(Mandatory)][pscustomobject]$Queue)
    $temporaryPath = $null
    $stream = $null
    try {
        $fullPath = [IO.Path]::GetFullPath($QueuePath)
        $temporaryPath = $fullPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Queue | ConvertTo-Json -Depth 20) + [Environment]::NewLine)
        if ($bytes.Length -gt 16MB) { Stop-BackupOperation 'QueueTooLarge' }
        $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        if ([IO.File]::Exists($fullPath)) { [IO.File]::Replace($temporaryPath, $fullPath, [NullString]::Value) }
        else { [IO.File]::Move($temporaryPath, $fullPath) }
    }
    catch { Stop-BackupOperation 'QueuePersistenceFailed' }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $temporaryPath -and [IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

function Update-QueuedBackupResult {
    param([Parameter(Mandatory)][string]$QueuePath, [Parameter(Mandatory)][pscustomobject]$Result)
    $lock = $null
    try {
        $lock = Open-BackupLock ($QueuePath + '.lock')
        $queue = Read-BackupQueueFile $QueuePath
        $records = @($queue.Jobs | Where-Object { $_.JobId -ceq $Result.JobId })
        if ($records.Count -ne 1 -or $null -eq $records[0].Result -or $records[0].Result.RunId -cne $Result.RunId) {
            Stop-BackupOperation 'QueueOwnershipLost'
        }
        $records[0].Status = $Result.Status
        $records[0].UpdatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        $records[0].Result = $Result
        Write-BackupQueueFile -QueuePath $QueuePath -Queue $queue
    }
    catch { Stop-BackupOperation 'QueueProgressPersistenceFailed' }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
}

function Add-BackupJob {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Job,
        [string]$QueuePath = (Join-Path $script:ProjectRoot 'Config\backup-queue.json'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs')
    )
    $lock = $null
    try {
        Assert-BackupJob $Job
        $lock = Open-BackupLock ($QueuePath + '.lock')
        $queue = Read-BackupQueueFile $QueuePath
        if (@($queue.Jobs | Where-Object { $_.JobId -ceq $Job.Id }).Count -ne 0) { Stop-BackupOperation 'JobAlreadyQueued' }
        $now = [DateTimeOffset]::UtcNow.ToString('o')
        $record = [pscustomobject][ordered]@{
            JobId = $Job.Id; Job = $Job; Status = 'Pending'; QueuedUtc = $now; UpdatedUtc = $now; Result = $null
        }
        Write-BackupEvent -LogDirectory $LogDirectory -JobId $Job.Id -RunId ([Guid]::Empty.ToString('D')) -Step 'Queue.Add' -Status 'Preparing'
        $queue.Jobs = @($queue.Jobs) + @($record)
        Write-BackupQueueFile -QueuePath $QueuePath -Queue $queue
        Write-BackupEvent -LogDirectory $LogDirectory -JobId $Job.Id -RunId ([Guid]::Empty.ToString('D')) -Step 'Queue.Add' -Status 'Pending'
        return $record
    }
    catch {
        Write-BackupEvent -LogDirectory $LogDirectory -JobId ([Guid]::Empty.ToString('D')) -RunId ([Guid]::Empty.ToString('D')) -Step 'Queue.Add' -Status 'Error' -ErrorCode 'QueueAddFailed'
        throw
    }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
}

function Get-BackupQueue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$QueuePath = (Join-Path $script:ProjectRoot 'Config\backup-queue.json'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs')
    )
    $lock = $null
    try {
        $lock = Open-BackupLock ($QueuePath + '.lock')
        $queue = Read-BackupQueueFile $QueuePath
        return $queue.Jobs
    }
    catch {
        Write-BackupEvent -LogDirectory $LogDirectory -JobId ([Guid]::Empty.ToString('D')) -RunId ([Guid]::Empty.ToString('D')) -Step 'Queue.Read' -Status 'Error' -ErrorCode 'QueueReadFailed'
        throw
    }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
}

function Get-NextQueuedBackup {
    param([Parameter(Mandatory)][string]$QueuePath, [Parameter(Mandatory)][string]$LogDirectory, [switch]$RecoverInterrupted)
    $lock = $null
    try {
        $lock = Open-BackupLock ($QueuePath + '.lock')
        $queue = Read-BackupQueueFile $QueuePath
        $changed = $false
        if ($RecoverInterrupted) {
            foreach ($record in $queue.Jobs) {
                if ($record.Status -ne 'Running') { continue }
                $record.Status = 'Interrupted'
                $record.UpdatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
                if ($null -eq $record.Result) {
                    $record.Result = [pscustomobject]@{
                        JobId = $record.JobId; RunId = [Guid]::Empty.ToString('D'); Status = 'Interrupted'
                        StartedUtc = $null; CompletedUtc = $record.UpdatedUtc; ErrorCode = 'InterruptedPreviousRun'; Steps = @()
                    }
                }
                else {
                    $record.Result.Status = 'Interrupted'
                    $record.Result.CompletedUtc = $record.UpdatedUtc
                    $record.Result.ErrorCode = 'InterruptedPreviousRun'
                    foreach ($step in $record.Result.Steps) {
                        if ($step.Status -eq 'Running') {
                            $step.Status = 'Interrupted'; $step.ErrorCode = 'InterruptedPreviousRun'; $step.CompletedUtc = $record.UpdatedUtc
                        }
                        elseif ($step.Status -eq 'Pending') { $step.Status = 'Skipped'; $step.ErrorCode = 'InterruptedPreviousRun' }
                    }
                }
                Write-BackupEvent -LogDirectory $LogDirectory -JobId $record.JobId -RunId $record.Result.RunId -Step 'Queue.Recover' -Status 'Interrupted' -ErrorCode 'InterruptedPreviousRun'
                $changed = $true
            }
        }
        $next = $queue.Jobs | Where-Object { $_.Status -eq 'Pending' } | Select-Object -First 1
        if ($null -ne $next) {
            $now = [DateTimeOffset]::UtcNow.ToString('o')
            $next.Status = 'Running'
            $next.UpdatedUtc = $now
            $next.Result = [pscustomobject]@{
                JobId = $next.JobId; RunId = [Guid]::NewGuid().ToString('D'); Status = 'Running'
                StartedUtc = $now; CompletedUtc = $null; ErrorCode = $null; Steps = @()
            }
            Write-BackupEvent -LogDirectory $LogDirectory -JobId $next.JobId -RunId $next.Result.RunId -Step 'Queue.Claim' -Status 'Running'
            $changed = $true
        }
        if ($changed) { Write-BackupQueueFile -QueuePath $QueuePath -Queue $queue }
        return $next
    }
    catch {
        if ($_.Exception.Data.Contains('BackupCode')) { throw }
        Stop-BackupOperation 'QueueClaimFailed'
    }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
}

function Start-BackupQueue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$QueuePath = (Join-Path $script:ProjectRoot 'Config\backup-queue.json'),
        [string]$WorkDirectory = (Join-Path $script:ProjectRoot 'Work'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock'),
        [string]$RclonePath = 'rclone.exe',
        [string]$AgePath = 'age.exe',
        [ValidateRange(1, 86400)][int]$CommandTimeoutSeconds = 3600,
        [ValidateRange(1, 10000)][int]$MaxJobs = 100,
        [scriptblock]$CommandRunner
    )
    $lock = $null
    try {
        $lock = Open-BackupLock $EngineLockPath
        for ($index = 0; $index -lt $MaxJobs; $index++) {
            $record = Get-NextQueuedBackup -QueuePath $QueuePath -LogDirectory $LogDirectory -RecoverInterrupted:($index -eq 0)
            if ($null -eq $record) { break }
            $result = Invoke-BackupPipelineCore -Job $record.Job -RunId $record.Result.RunId -QueuePath $QueuePath -WorkDirectory $WorkDirectory -LogDirectory $LogDirectory -RclonePath $RclonePath -AgePath $AgePath -CommandTimeoutSeconds $CommandTimeoutSeconds -CommandRunner $CommandRunner
            Write-Output $result
        }
    }
    catch {
        Write-BackupEvent -LogDirectory $LogDirectory -JobId ([Guid]::Empty.ToString('D')) -RunId ([Guid]::Empty.ToString('D')) -Step 'Queue.Run' -Status 'Error' -ErrorCode 'QueueRunAborted'
        throw
    }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
}

Export-ModuleMember -Function New-BackupJob, Start-BackupPipeline, Add-BackupJob, Get-BackupQueue, Start-BackupQueue, Protect-BackupArchive, Unprotect-BackupArchive, Invoke-ProxmoxTransferPipeline
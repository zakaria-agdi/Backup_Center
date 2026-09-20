#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ProjectRoot = Split-Path $PSScriptRoot -Parent
$script:BackupEngine = Import-Module (Join-Path $PSScriptRoot 'BackupEngine.psd1') -PassThru
$script:StepNames = @('Export/Pull', 'Compress & Encrypt', 'Upload', 'Archive', 'Offsite', 'VERIFY')

function Stop-MaintenanceOperation {
    param([string]$Code)
    $exception = [InvalidOperationException]::new('BackupCenter: ' + $Code)
    $exception.Data['MaintenanceCode'] = $Code
    throw $exception
}

function Get-MaintenanceProperty {
    param($Object, [string]$Name)
    if ($null -ne $Object) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) { return $property.Value }
    }
}

function Format-MaintenanceError {
    param($Record, [string]$Code)
    $knownCodes = @(
        'ExternalCommandFailed', 'ProcessTimeout', 'ProcessStartFailed', 'InvalidCommandResponse',
        'StepExecutionFailed', 'PlaintextCleanupFailed', 'EmptyExport', 'EncryptedArtifactMissing',
        'EncryptedArtifactEmpty', 'RemoteMetadataInvalid', 'RemoteObjectMissingOrInvalid',
        'RemoteSizeMismatch', 'RemoteHashInvalid', 'RemoteHashMismatch', 'RemoteHashUnavailable',
        'LocalArtifactChanged', 'ArchiveIntegrityMismatch', 'AuditUnavailable',
        'WorkDirectoryProtectionFailed', 'SourceReparsePointNotAllowed', 'WorkDirectoryInsideSource',
        'QueueProgressPersistenceFailed', 'InterruptedPreviousRun'
    )
    $safeCode = if ($Code -cin $knownCodes) { $Code } else { 'NonDisponible' }
    if ($null -eq $Record) { return ('ErrorRecord: non disponible; code=' + $safeCode) }
    if ($Record -is [System.Management.Automation.ErrorRecord]) {
        $exceptionType = $Record.Exception.GetType().FullName
        $category = $Record.CategoryInfo.Category.ToString()
        $line = $Record.InvocationInfo.ScriptLineNumber
    }
    else {
        $exceptionType = Get-MaintenanceProperty $Record 'ExceptionType'
        $category = Get-MaintenanceProperty $Record 'Category'
        $line = Get-MaintenanceProperty $Record 'ScriptLineNumber'
    }
    $allowedTypes = @(
        'System.InvalidOperationException', 'System.ArgumentException', 'System.IO.IOException',
        'System.UnauthorizedAccessException', 'System.IO.FileNotFoundException', 'System.IO.DirectoryNotFoundException',
        'System.Management.Automation.RuntimeException', 'System.Management.Automation.MethodInvocationException',
        'System.Management.Automation.ItemNotFoundException', 'System.Management.Automation.CommandNotFoundException'
    )
    if ($exceptionType -cnotin $allowedTypes) { $exceptionType = 'Exception (type masque)' }
    if ($category -cnotin [Enum]::GetNames([System.Management.Automation.ErrorCategory])) { $category = 'NotSpecified' }
    if (($line -isnot [int] -and $line -isnot [long]) -or $line -lt 0) { $line = 0 }
    return ('ErrorRecord: {0}; Category={1}; ligne={2}; code={3}; message libre masque' -f $exceptionType, $category, $line, $safeCode)
}

function Send-TelegramAlert {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][pscustomobject]$PipelineResult,
        [Parameter(Mandatory)][Security.SecureString]$BotToken,
        [Parameter(Mandatory)][ValidatePattern('\A(?:-?[0-9]+|@[A-Za-z][A-Za-z0-9_]{4,})\z')][string]$ChatId,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
    )
    process {
        $buffer = [IntPtr]::Zero
        $parameters = @{}
        try {
            $status = Get-MaintenanceProperty $PipelineResult 'Status'
            if ($status -cnotin @('Success', 'Failed', 'Interrupted')) { Stop-MaintenanceOperation 'InvalidPipelineResult' }
            $lines = [Collections.Generic.List[string]]::new()
            $lines.Add('BackupCenter')
            foreach ($field in @('JobId', 'RunId')) {
                $identifier = [Guid]::Empty
                if ([Guid]::TryParseExact([string](Get-MaintenanceProperty $PipelineResult $field), 'D', [ref]$identifier)) {
                    $lines.Add($field + ': ' + $identifier.ToString('D'))
                }
            }
            if ($status -ceq 'Success') { $lines.Add('Succes du pipeline.') }
            else {
                $failedSteps = @(Get-MaintenanceProperty $PipelineResult 'Steps' | Where-Object { $_.Status -cin @('Failed', 'Interrupted') })
                $step = if ($failedSteps.Count -gt 0) { $failedSteps[0] } else { $null }
                $stepName = Get-MaintenanceProperty $step 'Name'
                if ($stepName -cnotin $script:StepNames) { $stepName = 'Pipeline (hors etape ou avant execution)' }
                if ($null -eq $step -and (Get-MaintenanceProperty $PipelineResult 'CleanupStatus') -ceq 'Failed') { $stepName = 'Nettoyage des fichiers en clair' }
                $label = if ($status -ceq 'Interrupted') { 'Interruption lors de ' } else { ([char]0x00C9).ToString() + 'chec lors de ' }
                $lines.Add($label + $stepName)
                $record = if ($null -ne $ErrorRecord) { $ErrorRecord } else { Get-MaintenanceProperty $step 'ErrorRecord' }
                if ($null -eq $record) { $record = Get-MaintenanceProperty $PipelineResult 'ErrorRecord' }
                $code = if ($null -ne $step) { Get-MaintenanceProperty $step 'ErrorCode' } else { Get-MaintenanceProperty $PipelineResult 'ErrorCode' }
                $lines.Add((Format-MaintenanceError $record $code))
                if ($null -ne $step -and (Get-MaintenanceProperty $PipelineResult 'CleanupStatus') -ceq 'Failed') {
                    $lines.Add('Echec supplementaire: Nettoyage des fichiers en clair')
                    $lines.Add((Format-MaintenanceError (Get-MaintenanceProperty $PipelineResult 'CleanupErrorRecord') 'PlaintextCleanupFailed'))
                }
            }
            $text = $lines -join "`n"
            if ($text.Length -gt 4000 -or $BotToken.Length -eq 0) { Stop-MaintenanceOperation 'InvalidAlert' }
            $buffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BotToken)
            $tokenText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($buffer)
            if ($tokenText -cnotmatch '\A[0-9]+:[A-Za-z0-9_-]{20,}\z') { Stop-MaintenanceOperation 'InvalidBotToken' }
            $parameters = @{
                Uri = 'https://api.telegram.org/bot' + $tokenText + '/sendMessage'
                Method = 'POST'; ContentType = 'application/json; charset=utf-8'
                Body = [Text.Encoding]::UTF8.GetBytes((@{ chat_id = $ChatId; text = $text; disable_web_page_preview = $true } | ConvertTo-Json -Compress))
                TimeoutSec = $TimeoutSeconds; MaximumRedirection = 0
                ErrorAction = 'Stop'; Verbose = $false; Debug = $false
            }
            $response = Invoke-RestMethod @parameters
            if ((Get-MaintenanceProperty $response 'ok') -isnot [bool] -or -not $response.ok) { Stop-MaintenanceOperation 'TelegramRejected' }
            return [pscustomobject]@{ Status = 'Sent'; TimestampUtc = [DateTimeOffset]::UtcNow.ToString('o') }
        }
        catch {
            if ($_.Exception.Data.Contains('MaintenanceCode')) { throw }
            Stop-MaintenanceOperation 'TelegramDeliveryFailed'
        }
        finally {
            $parameters.Clear()
            $tokenText = $null
            if ($buffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($buffer) }
        }
    }
}

function Assert-MaintenanceDirectory {
    param([string]$Path)
    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer) { Stop-MaintenanceOperation 'InvalidRetentionDirectory' }
    while ($null -ne $directory) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-MaintenanceOperation 'RetentionReparsePoint' }
        $directory = $directory.Parent
    }
}

function Read-RetentionPolicy {
    param([string]$Path)
    try {
        if ([IO.FileInfo]::new($Path).Length -gt 1MB) { Stop-MaintenanceOperation 'InvalidRetentionPolicy' }
        $policy = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
        if ($policy.SchemaVersion -ne 1 -or $policy.Sources -isnot [array] -or $policy.Sources.Count -eq 0) { throw 'Invalid schema' }
        foreach ($property in $policy.PSObject.Properties.Name) {
            if ($property -cnotin @('SchemaVersion', 'Sources')) { throw 'Unknown policy field' }
        }
        $sources = @{}
        $jobs = @{}
        foreach ($source in $policy.Sources) {
            foreach ($property in $source.PSObject.Properties.Name) {
                if ($property -cnotin @('SourceId', 'JobIds', 'KeepLast', 'Locations')) { throw 'Unknown source field' }
            }
            $identifier = [Guid]::Empty
            if (-not [Guid]::TryParseExact([string]$source.SourceId, 'D', [ref]$identifier) -or $sources.ContainsKey($source.SourceId)) { throw 'Invalid source' }
            $sources[$source.SourceId] = $true
            if (($source.KeepLast -isnot [int] -and $source.KeepLast -isnot [long]) -or $source.KeepLast -lt 1 -or $source.KeepLast -gt 100000) { throw 'Invalid retention count' }
            if ($source.JobIds -isnot [array] -or $source.JobIds.Count -eq 0 -or $source.Locations -isnot [array] -or $source.Locations.Count -eq 0) { throw 'Missing scope' }
            foreach ($jobId in $source.JobIds) {
                if (-not [Guid]::TryParseExact([string]$jobId, 'D', [ref]$identifier) -or $jobs.ContainsKey($jobId)) { throw 'Ambiguous job scope' }
                $jobs[$jobId] = $true
            }
            $locations = @{}
            foreach ($location in $source.Locations) {
                foreach ($property in $location.PSObject.Properties.Name) {
                    if ($property -cnotin @('Kind', 'Path')) { throw 'Unknown location field' }
                }
                if ($location.Path -isnot [string] -or [string]::IsNullOrWhiteSpace($location.Path) -or $location.Path -match '[\x00-\x1f]') { throw 'Invalid location' }
                if ($location.Kind -ceq 'Local') {
                    if ($location.Path -notmatch '\A(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)' -or $location.Path -match '\A\\\\[?.]\\') { throw 'Absolute filesystem path required' }
                    $location.Path = [IO.Path]::GetFullPath($location.Path).TrimEnd('\', '/')
                    if ($location.Path -match '\A[A-Za-z]:\z') { throw 'Drive root not allowed' }
                }
                elseif ($location.Kind -ceq 'Rclone') {
                    if ($location.Path -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{1,63}:[^\\\r\n]*\z' -or $location.Path -match '[:/]\.{1,2}(?:/|$)') { throw 'Named rclone directory required' }
                    $location.Path = $location.Path.TrimEnd('/')
                }
                else { throw 'Invalid location kind' }
                $key = $location.Kind + ':' + $location.Path
                if ($locations.ContainsKey($key)) { throw 'Duplicate location' }
                $locations[$key] = $true
            }
        }
        return $policy
    }
    catch { Stop-MaintenanceOperation 'InvalidRetentionPolicy' }
}

function Invoke-MaintenanceCommand {
    param([hashtable]$Options, [string[]]$Arguments)
    try {
        return & $script:BackupEngine {
            param($options, $arguments)
            Invoke-BackupCommand @options -Arguments $arguments
        } $Options $Arguments
    }
    catch { Stop-MaintenanceOperation 'RetentionCommandFailed' }
}

function Get-RetentionInventory {
    param($Source, $Location, [hashtable]$CommandOptions)
    $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $pattern = '\Abackup-(?<job>' + $guidPattern + ')-' + $guidPattern + '\.zip\.age\z'
    if ($Location.Kind -ceq 'Local') {
        Assert-MaintenanceDirectory $Location.Path
        $entries = @(Get-ChildItem -LiteralPath $Location.Path -File -Force -ErrorAction Stop)
    }
    else {
        $json = Invoke-MaintenanceCommand $CommandOptions @('lsjson', '--files-only', '--max-depth', '1', '--', $Location.Path)
        if ($json.Length -gt 16MB -or -not $json.TrimStart().StartsWith('[')) { Stop-MaintenanceOperation 'InvalidRetentionListing' }
        try { $entries = $json | ConvertFrom-Json -ErrorAction Stop }
        catch { Stop-MaintenanceOperation 'InvalidRetentionListing' }
    }
    $names = @{}
    foreach ($entry in $entries) {
        if ($null -eq $entry -or $entry.Name -isnot [string]) { Stop-MaintenanceOperation 'InvalidRetentionListing' }
        $match = [regex]::Match($entry.Name, $pattern)
        if (-not $match.Success -or $match.Groups['job'].Value -notin $Source.JobIds) { continue }
        if ($names.ContainsKey($entry.Name)) { Stop-MaintenanceOperation 'AmbiguousRetentionListing' }
        $names[$entry.Name] = $true
        if ($Location.Kind -ceq 'Local') {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-MaintenanceOperation 'RetentionReparsePoint' }
            $size = $entry.Length
            $modified = [DateTimeOffset]::new($entry.LastWriteTimeUtc)
            $target = Join-Path $Location.Path $entry.Name
        }
        else {
            if ($entry.Path -cne $entry.Name -or $entry.IsDir -isnot [bool] -or $entry.IsDir -or
                ($entry.Size -isnot [int] -and $entry.Size -isnot [long])) { Stop-MaintenanceOperation 'InvalidRetentionListing' }
            $size = $entry.Size
            $modified = [DateTimeOffset]::MinValue
            if ($entry.ModTime -is [datetime]) { $modified = [DateTimeOffset]::new($entry.ModTime) }
            elseif ($entry.ModTime -is [DateTimeOffset]) { $modified = $entry.ModTime }
            elseif ($entry.ModTime -isnot [string] -or $entry.ModTime -notmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T.*(?:Z|[+-][0-9]{2}:[0-9]{2})\z' -or
                -not [DateTimeOffset]::TryParse($entry.ModTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$modified)) {
                Stop-MaintenanceOperation 'InvalidRetentionTimestamp'
            }
            $target = $Location.Path.TrimEnd('/') + '/' + $entry.Name
        }
        if ($size -le 0 -or $modified -le [DateTimeOffset]'1970-01-01T00:00:00Z') { Stop-MaintenanceOperation 'InvalidRetentionMetadata' }
        [pscustomobject]@{
            Name = $entry.Name; Path = $target; Size = [long]$size; ModifiedUtcTicks = $modified.UtcTicks
            ModifiedUtc = $modified.ToUniversalTime().ToString('o')
        }
    }
}

function Assert-RetentionInventoryUnchanged {
    param([array]$Expected, [array]$Actual)
    if ($Expected.Count -ne $Actual.Count) { Stop-MaintenanceOperation 'RetentionInventoryChanged' }
    $index = @{}
    foreach ($item in $Actual) { $index[$item.Name] = $item }
    foreach ($item in $Expected) {
        if (-not $index.ContainsKey($item.Name) -or $index[$item.Name].Size -ne $item.Size -or
            $index[$item.Name].ModifiedUtcTicks -ne $item.ModifiedUtcTicks) { Stop-MaintenanceOperation 'RetentionInventoryChanged' }
    }
}

function Open-RetentionAudit {
    param([string]$Path)
    $stream = $null
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $parent = [IO.Path]::GetDirectoryName($fullPath)
        $null = [IO.Directory]::CreateDirectory($parent)
        Assert-MaintenanceDirectory $parent
        if ([IO.File]::Exists($fullPath) -and ((Get-Item -LiteralPath $fullPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-MaintenanceOperation 'AuditUnavailable'
        }
        $stream = [IO.File]::Open($fullPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        if ($stream.Length -gt 0) {
            $null = $stream.Seek(-1, [IO.SeekOrigin]::End)
            if ($stream.ReadByte() -ne 10) { Stop-MaintenanceOperation 'AuditIncompleteTail' }
        }
        $null = $stream.Seek(0, [IO.SeekOrigin]::End)
        return $stream
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        Stop-MaintenanceOperation 'AuditUnavailable'
    }
}

function Write-RetentionAudit {
    param([IO.FileStream]$Stream, [string]$RunId, [string]$OperationId, $Source, $Location, $Item, [string]$Status, [string]$ErrorCode)
    try {
        $record = [ordered]@{
            TimestampUtc = [DateTimeOffset]::UtcNow.ToString('o'); Component = 'BackupCenter.Retention'
            RunId = $RunId; OperationId = $OperationId; SourceId = $Source.SourceId; KeepLast = $Source.KeepLast
            Kind = $Location.Kind; Directory = $Location.Path; Archive = $Item.Name
            Size = $Item.Size; ModifiedUtc = $Item.ModifiedUtc; Status = $Status; ErrorCode = $ErrorCode; ProcessId = $PID
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress) + [Environment]::NewLine)
        $Stream.Write($bytes, 0, $bytes.Length)
        $Stream.Flush($true)
    }
    catch { Stop-MaintenanceOperation 'AuditUnavailable' }
}

function Invoke-RetentionPolicy {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$PolicyPath,
        [string]$AuditPath = (Join-Path $script:ProjectRoot 'Logs\Maintenance\retention.jsonl'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock'),
        [string]$RclonePath = 'rclone.exe',
        [ValidateRange(1, 86400)][int]$CommandTimeoutSeconds = 3600,
        [scriptblock]$CommandRunner
    )
    $lock = $null
    $audit = $null
    $runId = [Guid]::NewGuid().ToString('D')
    try {
        if ([IO.Path]::GetExtension($AuditPath) -ine '.jsonl') { Stop-MaintenanceOperation 'InvalidAuditPath' }
        $policy = Read-RetentionPolicy $PolicyPath
        $lock = & $script:BackupEngine { param($path) Open-BackupLock $path } $EngineLockPath
        $commandOptions = @{ Executable = $RclonePath; TimeoutSeconds = $CommandTimeoutSeconds; CommandRunner = $CommandRunner }
        $groups = [Collections.Generic.List[object]]::new()
        foreach ($source in $policy.Sources) {
            foreach ($location in $source.Locations) {
                $items = @(Get-RetentionInventory $source $location $commandOptions)
                $ordered = @($items | Sort-Object -Property @{ Expression = { $_.ModifiedUtcTicks }; Descending = $true }, Name)
                $groups.Add([pscustomobject]@{
                    Source = $source; Location = $location; Items = $items
                    Candidates = @($ordered | Select-Object -Skip $source.KeepLast | Sort-Object ModifiedUtcTicks, Name)
                })
            }
        }
        foreach ($group in $groups) {
            foreach ($item in $group.Candidates) {
                $operationId = [Guid]::NewGuid().ToString('D')
                $outcome = [pscustomobject]@{ RunId = $runId; OperationId = $operationId; SourceId = $group.Source.SourceId; Path = $item.Path; Status = 'Skipped' }
                if ($PSCmdlet.ShouldProcess($item.Path, 'Supprimer definitivement cette ancienne archive')) {
                    $current = @(Get-RetentionInventory $group.Source $group.Location $commandOptions)
                    Assert-RetentionInventoryUnchanged $group.Items $current
                    if ($null -eq $audit) { $audit = Open-RetentionAudit $AuditPath }
                    $auditOptions = @{ Stream = $audit; RunId = $runId; OperationId = $operationId; Source = $group.Source; Location = $group.Location; Item = $item }
                    Write-RetentionAudit @auditOptions -Status 'DeleteIntent'
                    try {
                        if ($group.Location.Kind -ceq 'Local') { [IO.File]::Delete($item.Path) }
                        else { $null = Invoke-MaintenanceCommand $commandOptions @('deletefile', '--', $item.Path) }
                        $after = @(Get-RetentionInventory $group.Source $group.Location $commandOptions)
                        $expected = @($group.Items | Where-Object { $_.Name -cne $item.Name })
                        Assert-RetentionInventoryUnchanged $expected $after
                    }
                    catch {
                        Write-RetentionAudit @auditOptions -Status 'DeleteUnconfirmed' -ErrorCode 'DeletionUnconfirmed'
                        Stop-MaintenanceOperation 'DeletionUnconfirmed'
                    }
                    Write-RetentionAudit @auditOptions -Status 'Deleted'
                    $group.Items = $expected
                    $outcome.Status = 'Deleted'
                }
                elseif ($WhatIfPreference) { $outcome.Status = 'Planned' }
                $outcome
            }
        }
    }
    catch {
        if ($_.Exception.Data.Contains('MaintenanceCode')) { throw }
        if ($_.Exception.Data.Contains('BackupCode') -and $_.Exception.Data['BackupCode'] -eq 'LockBusyOrUnavailable') { Stop-MaintenanceOperation 'LockBusyOrUnavailable' }
        Stop-MaintenanceOperation 'RetentionFailed'
    }
    finally {
        if ($null -ne $audit) { $audit.Dispose() }
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

Export-ModuleMember -Function Send-TelegramAlert, Invoke-RetentionPolicy
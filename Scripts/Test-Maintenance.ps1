#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Assertions = 0
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupCenter.MaintenanceTests.' + [Guid]::NewGuid().ToString('N'))
$token = $null
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('Assertion failed: ' + $Message) }
    $script:Assertions++
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Code)
    $caught = $false
    try { $null = & $Action } catch { $caught = $_.Exception.Message -ceq ('BackupCenter: ' + $Code) }
    Assert-True $caught ('Fails safely: ' + $Code)
}
try {
    $manifest = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\Maintenance.psd1'
    $manifestInfo = Test-ModuleManifest $manifest
    Assert-True ($manifestInfo.ExportedFunctions.Count -eq 2) 'Manifest exposes only the two maintenance commands'
    $module = Import-Module $manifest -Force -PassThru
    $state = @{ Mode = 'Good'; Messages = [Collections.Generic.List[string]]::new() }
    & $module {
        param($state)
        $script:TestState = $state
        function script:Invoke-RestMethod {
            [CmdletBinding()]
            param($Uri, $Method, $ContentType, $Body, $TimeoutSec, $MaximumRedirection)
            $script:TestState.TransportOK = $Uri -ceq 'https://api.telegram.org/bot123456:TEST_ONLY_TOKEN_1234567890/sendMessage' -and
                $Method -ceq 'POST' -and $MaximumRedirection -eq 0 -and $TimeoutSec -eq 30 -and $ContentType -like 'application/json*'
            $payload = [Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json
            $script:TestState.Messages.Add($payload.text)
            if ($script:TestState.Mode -eq 'HttpFailure') { throw 'TEST_ONLY_TOKEN_1234567890 private error' }
            return [pscustomobject]@{ ok = ($script:TestState.Mode -ne 'Rejected') }
        }
    } $state
    $token = ConvertTo-SecureString '123456:TEST_ONLY_TOKEN_1234567890' -AsPlainText -Force
    $result = [pscustomobject]@{
        JobId = [Guid]::NewGuid().ToString('D'); RunId = [Guid]::NewGuid().ToString('D'); Status = 'Failed'
        ErrorCode = 'ExternalCommandFailed'; CleanupStatus = 'Success'
        Steps = @([pscustomobject]@{
            Name = 'Compress & Encrypt'; Status = 'Failed'; ErrorCode = 'ExternalCommandFailed'
            ErrorRecord = [pscustomobject]@{ ExceptionType = 'System.InvalidOperationException'; Category = 'OperationStopped'; ScriptLineNumber = 12; Message = 'DO-NOT-SEND-SECRET' }
        })
    }
    $sent = Send-TelegramAlert -PipelineResult $result -BotToken $token -ChatId '-123456'
    Assert-True ($sent.Status -eq 'Sent' -and $state.TransportOK) 'HTTPS Telegram contract without redirects'
    Assert-True ($state.Messages[-1].Contains('chec lors de Compress & Encrypt') -and $state.Messages[-1].Contains('System.InvalidOperationException')) 'Alert contains exact step and structured exception'
    Assert-True (-not $state.Messages[-1].Contains('DO-NOT-SEND-SECRET')) 'Arbitrary ErrorRecord message is never transmitted'
    try { throw 'DO-NOT-SEND-PASSWORD' } catch { $nativeError = $_ }
    $null = Send-TelegramAlert -PipelineResult $result -ErrorRecord $nativeError -BotToken $token -ChatId '-123456'
    Assert-True ($state.Messages[-1].Contains('ErrorRecord:') -and -not $state.Messages[-1].Contains('DO-NOT-SEND-PASSWORD')) 'Native ErrorRecord is projected safely'
    $state.Mode = 'HttpFailure'
    Assert-Throws { Send-TelegramAlert -PipelineResult $result -BotToken $token -ChatId '-123456' } 'TelegramDeliveryFailed'
    $state.Mode = 'Rejected'
    Assert-Throws { Send-TelegramAlert -PipelineResult $result -BotToken $token -ChatId '-123456' } 'TelegramRejected'
    $state.Mode = 'Good'
    $result.Status = 'Success'
    $null = Send-TelegramAlert -PipelineResult $result -BotToken $token -ChatId '-123456'
    Assert-True ($state.Messages[-1].Contains('Succes du pipeline')) 'Success message'
    $result.Status = 'Running'
    Assert-Throws { Send-TelegramAlert -PipelineResult $result -BotToken $token -ChatId '-123456' } 'InvalidPipelineResult'
    $local = Join-Path $root 'archives'
    $null = [IO.Directory]::CreateDirectory($local)
    $sourceId = [Guid]::NewGuid().ToString('D')
    $jobId = [Guid]::NewGuid().ToString('D')
    $otherJobId = [Guid]::NewGuid().ToString('D')
    $policy = [pscustomobject]@{ SchemaVersion = 1; Sources = @([pscustomobject]@{
        SourceId = $sourceId; JobIds = @($jobId); KeepLast = 2
        Locations = @([pscustomobject]@{ Kind = 'Local'; Path = $local }, [pscustomobject]@{ Kind = 'Rclone'; Path = 'remote:backups' })
    }) }
    $policyPath = Join-Path $root 'retention.json'
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    $remote = @{ Items = @{}; Deletes = [Collections.Generic.List[string]]::new(); Mode = 'Good'; Listings = 0 }
    $archiveNames = @()
    for ($version = 1; $version -le 4; $version++) {
        $name = 'backup-' + $jobId + '-' + [Guid]::NewGuid().ToString('D') + '.zip.age'
        $archiveNames += $name
        $path = Join-Path $local $name
        [IO.File]::WriteAllText($path, 'TEST-ONLY')
        $modified = [datetime]::SpecifyKind([datetime]'2026-01-01', [DateTimeKind]::Utc).AddDays($version)
        [IO.File]::SetLastWriteTimeUtc($path, $modified)
        $remote.Items[$name] = [pscustomobject]@{ Name = $name; Path = $name; IsDir = $false; Size = 9; ModTime = $modified.ToString('o') }
    }
    $unrelated = 'backup-' + $otherJobId + '-' + [Guid]::NewGuid().ToString('D') + '.zip.age'
    [IO.File]::WriteAllText((Join-Path $local $unrelated), 'TEST-ONLY unrelated')
    [IO.File]::WriteAllText((Join-Path $local 'notes.txt'), 'TEST-ONLY unrelated')
    $nested = Join-Path $local 'nested'
    $null = [IO.Directory]::CreateDirectory($nested)
    [IO.File]::WriteAllText((Join-Path $nested $archiveNames[0]), 'TEST-ONLY nested')
    $options = @{
        PolicyPath = $policyPath; AuditPath = (Join-Path $root 'Audit\retention.jsonl')
        EngineLockPath = (Join-Path $root 'engine.lock'); RclonePath = 'rclone.test'
    }
    $runner = {
        param($Executable, $Arguments)
        if ($Executable -ne 'rclone.test') { throw 'Unexpected executable' }
        if ($Arguments[0] -eq 'lsjson') {
            $remote.Listings++
            if (($Arguments -join '|') -cne 'lsjson|--files-only|--max-depth|1|--|remote:backups') { throw 'Unexpected listing scope' }
            if ($remote.Mode -eq 'Malformed') { return [pscustomobject]@{ ExitCode = 0; Stdout = '{invalid' } }
            if ($remote.Mode -eq 'Changed' -and $remote.Listings -eq $remote.ChangeAt) { $remote.Items[$remote.ChangeName].Size++ }
            if ($remote.Mode -eq 'Duplicate') {
                $items = @($remote.Items.Values)
                return [pscustomobject]@{ ExitCode = 0; Stdout = (ConvertTo-Json -InputObject @($items + $items[0]) -Depth 5 -Compress) }
            }
            return [pscustomobject]@{ ExitCode = 0; Stdout = (ConvertTo-Json -InputObject @($remote.Items.Values) -Depth 5 -Compress) }
        }
        if ($Arguments[0] -eq 'deletefile') {
            if ($Arguments.Count -ne 3 -or $Arguments[1] -cne '--') { throw 'Deletion must target one literal file' }
            $name = $Arguments[-1].Substring('remote:backups/'.Length)
            $journal = @(Get-Content -LiteralPath $options.AuditPath | ForEach-Object { $_ | ConvertFrom-Json })
            if ($journal[-1].Status -cne 'DeleteIntent' -or $journal[-1].Archive -cne $name) { throw 'Missing durable intent' }
            $remote.Deletes.Add($Arguments[-1])
            if ($remote.Mode -eq 'DeleteFailure') { return [pscustomobject]@{ ExitCode = 1; Stdout = '' } }
            if ($remote.Mode -ne 'NoOpDelete') { $remote.Items.Remove($name) }
            return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
        }
        throw 'Unexpected retention command'
    }.GetNewClosure()
    $options.CommandRunner = $runner
    $planned = @(Invoke-RetentionPolicy @options -WhatIf)
    Assert-True ($planned.Count -eq 4 -and @($planned | Where-Object Status -ne 'Planned').Count -eq 0) 'WhatIf plans per-location retention'
    Assert-True (-not [IO.File]::Exists($options.AuditPath) -and $remote.Deletes.Count -eq 0 -and [IO.File]::Exists((Join-Path $local $archiveNames[0]))) 'WhatIf neither deletes nor writes audit'
    $deleted = @(Invoke-RetentionPolicy @options -Confirm:$false)
    Assert-True ($deleted.Count -eq 4 -and @($deleted | Where-Object Status -ne 'Deleted').Count -eq 0) 'Prunes oldest two copies locally and remotely'
    Assert-True ($deleted[0].Path.EndsWith($archiveNames[0]) -and $remote.Deletes[0].EndsWith($archiveNames[0])) 'Oldest version deleted first'
    Assert-True ([IO.File]::Exists((Join-Path $local $archiveNames[2])) -and [IO.File]::Exists((Join-Path $local $archiveNames[3])) -and $remote.Items.Count -eq 2) 'Newest versions retained'
    Assert-True ([IO.File]::Exists((Join-Path $local $unrelated)) -and [IO.File]::Exists((Join-Path $local 'notes.txt')) -and [IO.File]::Exists((Join-Path $nested $archiveNames[0]))) 'Other jobs, ordinary files and nested files untouched'
    $journal = @(Get-Content -LiteralPath $options.AuditPath | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True ($journal.Count -eq 8 -and @($journal | Where-Object Status -eq 'Deleted').Count -eq 4) 'Durable intent and confirmation for every deletion'
    foreach ($entry in @($journal | Where-Object Status -eq 'Deleted')) {
        Assert-True (@($journal | Where-Object { $_.OperationId -ceq $entry.OperationId -and $_.Status -ceq 'DeleteIntent' }).Count -eq 1) 'Audit correlates before and after records'
    }
    Assert-True (@(Invoke-RetentionPolicy @options -Confirm:$false).Count -eq 0) 'Retention is idempotent'
    $policy.Sources[0].KeepLast = 1
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    $busy = [IO.File]::Open($options.EngineLockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'LockBusyOrUnavailable' }
    finally { $busy.Dispose() }
    $busy = [IO.File]::Open($options.AuditPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'AuditUnavailable' }
    finally { $busy.Dispose() }
    Assert-True ([IO.File]::Exists((Join-Path $local $archiveNames[2])) -and $remote.Items.Count -eq 2) 'Audit outage blocks deletion'
    $policy.Sources[0].KeepLast = 0
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'InvalidRetentionPolicy'
    $policy.Sources[0].KeepLast = 1
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    $remote.Mode = 'Malformed'
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'InvalidRetentionListing'
    Assert-True ([IO.File]::Exists((Join-Path $local $archiveNames[2]))) 'All locations scanned before any deletion'
    $remote.Mode = 'Duplicate'
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'AmbiguousRetentionListing'
    $remote.Mode = 'Good'
    $remote.Items[$archiveNames[2]].Path = '../' + $archiveNames[2]
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'InvalidRetentionListing'
    $remote.Items[$archiveNames[2]].Path = $archiveNames[2]
    $originalTime = $remote.Items[$archiveNames[2]].ModTime
    $remote.Items[$archiveNames[2]].ModTime = 'not-a-date'
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'InvalidRetentionTimestamp'
    $remote.Items[$archiveNames[2]].ModTime = $originalTime
    $policy.Sources[0].Locations = @($policy.Sources[0].Locations[1])
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    $remote.Mode = 'Changed'
    $remote.ChangeAt = $remote.Listings + 2
    $remote.ChangeName = $archiveNames[3]
    $auditBefore = [IO.File]::ReadAllText($options.AuditPath)
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'RetentionInventoryChanged'
    Assert-True ([IO.File]::ReadAllText($options.AuditPath) -ceq $auditBefore) 'Changed inventory blocks intent and deletion'
    $remote.Items[$archiveNames[3]].Size--
    $remote.Mode = 'Good'
    $badAudit = $options.Clone()
    $badAudit.AuditPath = Join-Path $root 'incomplete.jsonl'
    [IO.File]::WriteAllText($badAudit.AuditPath, '{partial')
    Assert-Throws { Invoke-RetentionPolicy @badAudit -Confirm:$false } 'AuditUnavailable'
    $badAudit.AuditPath = Join-Path $local $archiveNames[2]
    Assert-Throws { Invoke-RetentionPolicy @badAudit -Confirm:$false } 'InvalidAuditPath'
    foreach ($mode in @('DeleteFailure', 'NoOpDelete')) {
        $remote.Mode = $mode
        Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'DeletionUnconfirmed'
        $entries = @(Get-Content -LiteralPath $options.AuditPath | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-True ($entries[-1].Status -ceq 'DeleteUnconfirmed' -and $entries[-2].Status -ceq 'DeleteIntent' -and $remote.Items.Count -eq 2) 'Failed or ineffective delete is never confirmed'
    }
    $remote.Mode = 'Good'
    $null = Invoke-RetentionPolicy @options -Confirm:$false
    Assert-True ([IO.File]::ReadAllText($options.AuditPath).StartsWith($auditBefore) -and $remote.Items.Count -eq 1) 'Subsequent execution appends audit without truncation'
    Assert-True (@(Invoke-RetentionPolicy @options -Confirm:$false).Count -eq 0) 'Single remote entry remains intact'
    $remote.Items.Clear()
    Assert-True (@(Invoke-RetentionPolicy @options -Confirm:$false).Count -eq 0) 'Empty remote listing is valid'
    $policy.Sources[0].Locations[0].Path = 'remote:../backups'
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'InvalidRetentionPolicy'

    $secondSource = [pscustomobject]@{
        SourceId = [Guid]::NewGuid().ToString('D'); JobIds = @($otherJobId); KeepLast = 3
        Locations = @([pscustomobject]@{ Kind = 'Local'; Path = $local })
    }
    $policy.Sources[0].Locations = @([pscustomobject]@{ Kind = 'Local'; Path = $local })
    $policy.Sources += $secondSource
    for ($version = 1; $version -le 3; $version++) {
        $path = Join-Path $local ('backup-' + $otherJobId + '-' + [Guid]::NewGuid().ToString('D') + '.zip.age')
        [IO.File]::WriteAllText($path, 'TEST-ONLY second source')
        [IO.File]::SetLastWriteTimeUtc($path, ([datetime]::SpecifyKind([datetime]'2026-02-01', [DateTimeKind]::Utc).AddDays($version)))
    }
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    $multiSource = @(Invoke-RetentionPolicy @options -Confirm:$false)
    Assert-True ($multiSource.Count -eq 2 -and @($multiSource | Where-Object SourceId -eq $sourceId).Count -eq 1) 'Each source uses its own KeepLast in a shared directory'
    Assert-True (@(Get-ChildItem -LiteralPath $local -Filter ('backup-' + $otherJobId + '-*.zip.age')).Count -eq 3) 'Second source keeps three versions'
    $secondSource.JobIds = @($jobId)
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 10))
    Assert-Throws { Invoke-RetentionPolicy @options -Confirm:$false } 'InvalidRetentionPolicy'

    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\BackupEngine.psd1')
    $pipelineSource = Join-Path $root 'payload.txt'
    [IO.File]::WriteAllText($pipelineSource, 'TEST-ONLY pipeline source')
    $job = New-BackupJob -Name 'AlertTest' -SourcePath $pipelineSource -PrimaryDestination 'primary:backups' -OffsiteDestination 'offsite:backups' -ArchiveDirectory (Join-Path $root 'PipelineArchive') -Recipient ('age1' + ('q' * 58))
    $pipeline = Start-BackupPipeline -Job $job -WorkDirectory (Join-Path $root 'Work') -LogDirectory (Join-Path $root 'PipelineLogs') -EngineLockPath $options.EngineLockPath -AgePath 'age.test' -CommandRunner { throw 'DO-NOT-SEND-PRIVATE-DIAGNOSTIC' }
    $restored = $pipeline | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $null = Send-TelegramAlert -PipelineResult $restored -BotToken $token -ChatId '-123456'
    Assert-True ($state.Messages[-1].Contains('chec lors de Compress & Encrypt') -and $state.Messages[-1].Contains('ExternalCommandFailed')) 'Actual pipeline failure becomes Telegram message after JSON round trip'
    Assert-True (-not ($state.Messages -join '').Contains('DO-NOT-SEND-PRIVATE-DIAGNOSTIC')) 'Pipeline native command diagnostic is not disclosed'
    $restored.CleanupStatus = 'Failed'
    $restored.CleanupErrorRecord = $restored.ErrorRecord
    $null = Send-TelegramAlert -PipelineResult $restored -BotToken $token -ChatId '-123456'
    Assert-True ($state.Messages[-1].Contains('Compress & Encrypt') -and $state.Messages[-1].Contains('Nettoyage des fichiers en clair')) 'Primary and cleanup failures both reported'
    $restored.Steps = @()
    $null = Send-TelegramAlert -PipelineResult $restored -BotToken $token -ChatId '-123456'
    Assert-True ($state.Messages[-1].Contains('chec lors de Nettoyage des fichiers en clair')) 'Cleanup-only failure has an exact phase'
    $restored.CleanupStatus = 'Success'
    $restored.Status = 'Interrupted'
    $null = Send-TelegramAlert -PipelineResult $restored -BotToken $token -ChatId '-123456'
    Assert-True ($state.Messages[-1].Contains('Interruption lors de Pipeline')) 'Interrupted legacy result without step details is supported'
    Write-Host ('PASS: {0} Maintenance assertions (isolated files, simulated services).' -f $script:Assertions)
}
finally {
    if ($null -ne $token) { $token.Dispose() }
    Remove-Module Maintenance -Force -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupCenter.EngineTests.' + [Guid]::NewGuid().ToString('N'))
$script:Assertions = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('Assertion failed: ' + $Message) }
    $script:Assertions++
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $failed = $false
    try { $null = & $Action } catch { $failed = $true }
    Assert-True $failed $Message
}

try {
    $manifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\BackupEngine.psd1'
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Assert-True ($manifest.ExportedFunctions.Count -eq 8) 'Valid module manifest with explicit public API'
    Import-Module $manifestPath -Force -ErrorAction Stop
    $source = Join-Path $root 'source'
    $null = [IO.Directory]::CreateDirectory($source)
    [IO.File]::WriteAllText((Join-Path $source 'database.dump'), 'TEST-ONLY snapshot payload')
    $state = @{ Mode = 'Good'; Calls = [Collections.Generic.List[string]]::new(); Remote = @{} }
    $runner = {
        param($Executable, $Arguments)
        $state.Calls.Add(($Executable + ':' + $Arguments[0]))
        if ($Executable -eq 'age.test') {
            if ($state.ContainsKey('ObservationQueue')) {
                $records = @(Get-BackupQueue -QueuePath $state.ObservationQueue -LogDirectory $state.ObservationLog)
                $active = @($records | Where-Object Status -eq 'Running')
                $state.ObservedStages.Add($active[0].Result.Steps[1].Status)
                if ($state.InjectJob) {
                    $null = Add-BackupJob -Job $state.InjectJob -QueuePath $state.ObservationQueue -LogDirectory $state.ObservationLog
                    $state.InjectJob = $null
                }
            }
            if ($state.Mode -eq 'EncryptionFailure') { return [pscustomobject]@{ ExitCode = 1; Stdout = '' } }
            $outputIndex = [Array]::IndexOf($Arguments, '--output') + 1
            $destination = $Arguments[$outputIndex]
            $payload = [IO.File]::ReadAllBytes($Arguments[$Arguments.Count - 1])
            [IO.File]::WriteAllBytes($destination, $payload)
            return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
        }
        if ($Arguments[0] -eq 'copy') {
            [IO.File]::WriteAllText((Join-Path $Arguments[$Arguments.Count - 1] 'pulled.dump'), 'TEST-ONLY remote snapshot')
            return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
        }
        if ($Arguments[0] -eq 'copyto') {
            foreach ($option in @(@('--transfers', '8'), @('--checkers', '8'), @('--drive-chunk-size', '256M'), @('--buffer-size', '128M'))) {
                $optionIndex = [Array]::IndexOf($Arguments, $option[0])
                if ($optionIndex -lt 0 -or $Arguments[$optionIndex + 1] -cne $option[1]) { throw 'Missing upload tuning option.' }
            }
            $localPath = $Arguments[$Arguments.Count - 2]
            $remotePath = $Arguments[$Arguments.Count - 1]
            $state.Remote[$remotePath] = @{
                Name = [IO.Path]::GetFileName($localPath); Size = [IO.FileInfo]::new($localPath).Length
                IsDir = $false; Hashes = @{ 'SHA-256' = (Get-FileHash -LiteralPath $localPath -Algorithm SHA256).Hash }
            }
            if ($state.Mode -eq 'ArchiveTamper' -and $remotePath.StartsWith('offsite:')) {
                [IO.File]::AppendAllText($localPath, 'tampered')
            }
            return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
        }
        if ($Arguments[0] -eq 'lsjson') {
            $remotePath = $Arguments[$Arguments.Count - 1]
            if ($state.Mode -eq 'Missing') { return [pscustomobject]@{ ExitCode = 3; Stdout = '' } }
            if ($state.Mode -eq 'MalformedMetadata') { return [pscustomobject]@{ ExitCode = 0; Stdout = '{ invalid' } }
            $metadata = $state.Remote[$remotePath].Clone()
            if ($state.Mode -eq 'WrongSize') { $metadata.Size++ }
            if ($state.Mode -eq 'WrongHash' -or ($state.Mode -eq 'OffsiteWrongHash' -and $remotePath.StartsWith('offsite:'))) {
                $metadata.Hashes = @{ 'SHA-256' = ('0' * 64) }
            }
            if ($state.Mode -eq 'SizeOnly') { $metadata.Hashes = @{} }
            if ($state.Mode -eq 'Directory') { $metadata.IsDir = $true }
            if ($state.Mode -eq 'WrongName') { $metadata.Name = 'unrelated.zip.age' }
            return [pscustomobject]@{ ExitCode = 0; Stdout = ($metadata | ConvertTo-Json -Depth 5 -Compress) }
        }
        throw 'Unexpected command in test double.'
    }.GetNewClosure()
    $options = @{
        WorkDirectory = (Join-Path $root 'Work'); LogDirectory = (Join-Path $root 'Logs')
        EngineLockPath = (Join-Path $root 'engine.lock'); RclonePath = 'rclone.test'; AgePath = 'age.test'; CommandRunner = $runner
    }
    $jobArguments = @{
        Name = 'Database'; SourcePath = $source; PrimaryDestination = 'primary:backups'
        OffsiteDestination = 'offsite:backups'; ArchiveDirectory = (Join-Path $root 'Archive'); Recipient = ('age1' + ('q' * 58))
    }
    $job = New-BackupJob @jobArguments
    $result = Start-BackupPipeline -Job $job @options
    Assert-True ($result -is [pscustomobject] -and $result.Status -eq 'Success') 'Successful pipeline returns a monitoring object'
    Assert-True (($result.Steps.Name -join '|') -ceq 'Export/Pull|Compress & Encrypt|Upload|Archive|Offsite|VERIFY') 'Strict six-step order'
    Assert-True (@($result.Steps | Where-Object Status -ne 'Success').Count -eq 0) 'All steps succeeded'
    Assert-True (($state.Calls -join '|') -ceq 'age.test:--encrypt|rclone.test:copyto|rclone.test:copyto|rclone.test:lsjson|rclone.test:lsjson') 'Uploads happen before independent remote queries'
    Assert-True ($result.Steps[5].Details.Primary.Method -eq 'HashAndSize' -and $result.Steps[5].Details.Offsite.Method -eq 'HashAndSize') 'Verify both remote copies'
    Assert-True ($result.Steps[5].Details.Archive.Status -eq 'Success') 'Verify local archive'
    Assert-True ($result.CleanupStatus -eq 'Success' -and -not [IO.File]::Exists((Join-Path (Split-Path $result.ArtifactPath -Parent) 'payload.zip'))) 'Remove plaintext ZIP'
    Assert-True (-not [IO.Directory]::Exists((Join-Path (Split-Path $result.ArtifactPath -Parent) 'export'))) 'Remove plaintext export'
    Assert-True ([IO.File]::Exists((Join-Path $source 'database.dump'))) 'Never remove original source'
    foreach ($mode in @('Missing', 'WrongSize', 'WrongHash', 'OffsiteWrongHash', 'MalformedMetadata', 'ArchiveTamper', 'Directory', 'WrongName')) {
        $state.Mode = $mode
        $failedResult = Start-BackupPipeline -Job $job @options
        Assert-True ($failedResult.Status -eq 'Failed' -and $failedResult.Steps[5].Status -eq 'Failed') ('VERIFY rejects ' + $mode)
        Assert-True ($failedResult.Steps[2].Status -eq 'Success' -and $failedResult.Steps[4].Status -eq 'Success') 'Upload exit zero is not proof of success'
        Assert-True ($null -ne $failedResult.ErrorCode -and $failedResult.CleanupStatus -eq 'Success') 'Failure reason and cleanup returned'
    }
    $state.Mode = 'SizeOnly'
    $sizeResult = Start-BackupPipeline -Job $job @options
    Assert-True ($sizeResult.Status -eq 'Success' -and $sizeResult.Steps[5].Details.Primary.Method -eq 'Size') 'Explicit size fallback without remote hashes'
    $strictJob = New-BackupJob @jobArguments -RequireRemoteHash
    $strictResult = Start-BackupPipeline -Job $strictJob @options
    Assert-True ($strictResult.Status -eq 'Failed' -and $strictResult.ErrorCode -eq 'RemoteHashUnavailable') 'Strict hash policy forbids size fallback'
    $state.Mode = 'EncryptionFailure'
    $state.Calls.Clear()
    $failedResult = Start-BackupPipeline -Job $job @options
    Assert-True ($failedResult.Steps[1].Status -eq 'Failed' -and @($failedResult.Steps | Where-Object Status -eq 'Skipped').Count -eq 4) 'Stop after failed encryption'
    Assert-True ($state.Calls.Count -eq 1) 'No upload after encryption failure'
    Assert-True ($failedResult.Steps[1].ErrorRecord.ExceptionType -eq 'System.InvalidOperationException' -and
        $failedResult.ErrorRecord.Sanitized -and $failedResult.ErrorRecord.Message -eq 'BackupCenter: ExternalCommandFailed') 'Failed step retains a sanitized ErrorRecord'
    $restoredFailure = $failedResult | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    Assert-True ($restoredFailure.Steps[1].ErrorRecord.ExceptionType -eq $failedResult.ErrorRecord.ExceptionType) 'ErrorRecord summary survives JSON persistence'
    $state.Mode = 'Good'
    $lock = [IO.File]::Open($options.EngineLockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { Assert-Throws { Start-BackupPipeline -Job $job @options } 'Concurrent pipeline is refused' }
    finally { $lock.Dispose() }
    $pullArguments = $jobArguments.Clone()
    $pullArguments.SourcePath = 'source:snapshots'
    $pullJob = New-BackupJob @pullArguments -SourceKind Rclone
    $pullResult = Start-BackupPipeline -Job $pullJob @options
    Assert-True ($pullResult.Status -eq 'Success' -and $pullResult.Steps[0].Details.SourceKind -eq 'Rclone') 'Pull from a named rclone remote'

    $queuePath = Join-Path $root 'Config\queue.json'
    $queueOptions = @{ QueuePath = $queuePath; LogDirectory = $options.LogDirectory }
    Assert-True (@(Get-BackupQueue @queueOptions).Count -eq 0) 'Absent queue is empty'
    $firstJob = New-BackupJob @jobArguments
    $secondJob = New-BackupJob @jobArguments
    $null = Add-BackupJob -Job $firstJob @queueOptions
    $null = Add-BackupJob -Job $secondJob @queueOptions
    Assert-True (@(Get-BackupQueue @queueOptions).Count -eq 2) 'Jobs persisted in JSON'
    Assert-Throws { Add-BackupJob -Job $firstJob @queueOptions } 'Duplicate job is refused'
    $state.Calls.Clear()
    $results = @(Start-BackupQueue -QueuePath $queuePath @options)
    Assert-True ($results.Count -eq 2 -and $results[0].JobId -ceq $firstJob.Id -and $results[1].JobId -ceq $secondJob.Id) 'Queue consumes FIFO'
    Assert-True ($results[0].Status -eq 'Success' -and $results[1].Status -eq 'Success') 'Both queued jobs succeeded'
    Assert-True ([DateTimeOffset]::Parse($results[1].StartedUtc) -ge [DateTimeOffset]::Parse($results[0].CompletedUtc)) 'Second pipeline starts only after first completes'
    $persisted = @(Get-BackupQueue @queueOptions)
    Assert-True ($persisted[0].Status -eq 'Success' -and $persisted[0].Result.Steps.Count -eq 6) 'Detailed results persisted'
    Assert-True ($persisted[0].Result.Steps[5].Details.Offsite.Status -eq 'Success') 'Remote verification evidence persisted'
    Assert-True (@(Start-BackupQueue -QueuePath $queuePath @options).Count -eq 0) 'Completed jobs are not run again'
    Assert-True ($results[0].ArtifactPath -cne $results[1].ArtifactPath) 'Unique per-run artifacts avoid overwrites'

    $thirdJob = New-BackupJob @jobArguments
    $fourthJob = New-BackupJob @jobArguments
    $null = Add-BackupJob -Job $thirdJob @queueOptions
    $null = Add-BackupJob -Job $fourthJob @queueOptions
    $state.Mode = 'WrongHash'
    $limited = @(Start-BackupQueue -QueuePath $queuePath -MaxJobs 1 @options)
    Assert-True ($limited.Count -eq 1 -and $limited[0].Status -eq 'Failed') 'Persist failed verification in queue'
    $persisted = @(Get-BackupQueue @queueOptions)
    Assert-True ($persisted[2].Status -eq 'Failed' -and $persisted[3].Status -eq 'Pending') 'MaxJobs and failure status respected'
    $state.Mode = 'Good'
    $nextResults = @(Start-BackupQueue -QueuePath $queuePath @options)
    Assert-True ($nextResults.Count -eq 1 -and $nextResults[0].JobId -eq $fourthJob.Id) 'Failure is not retried implicitly'

    $staleJob = New-BackupJob @jobArguments
    $null = Add-BackupJob -Job $staleJob @queueOptions
    $queueDocument = [IO.File]::ReadAllText($queuePath) | ConvertFrom-Json
    $stale = $queueDocument.Jobs[$queueDocument.Jobs.Count - 1]
    $stale.Status = 'Running'
    $stale.Result = [pscustomobject]@{
        JobId = $staleJob.Id; RunId = [Guid]::NewGuid().ToString('D'); Status = 'Running'
        StartedUtc = [DateTimeOffset]::UtcNow.ToString('o'); CompletedUtc = $null; ErrorCode = $null
        Steps = @([pscustomobject]@{ Name = 'Upload'; Status = 'Running'; ErrorCode = $null; CompletedUtc = $null })
    }
    [IO.File]::WriteAllText($queuePath, ($queueDocument | ConvertTo-Json -Depth 20))
    $state.Calls.Clear()
    Assert-True (@(Start-BackupQueue -QueuePath $queuePath @options).Count -eq 0) 'Stale running job is not silently reexecuted'
    $persisted = @(Get-BackupQueue @queueOptions)
    Assert-True ($persisted[4].Status -eq 'Interrupted' -and $persisted[4].Result.Steps[0].Status -eq 'Interrupted') 'Interrupted job and active step recovered explicitly'
    Assert-True ($state.Calls.Count -eq 0) 'Recovery does not perform external work'

    $heldLock = [IO.File]::Open($options.EngineLockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $worker = $null
    try {
        Assert-Throws { Start-BackupQueue -QueuePath $queuePath @options } 'Queue and direct pipeline share engine lock'
        $modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\BackupEngine.psm1'
        $worker = Start-Job -ScriptBlock {
            param($ModulePath, $LockPath, $QueuePath, $LogDirectory)
            Import-Module $ModulePath -Force -ErrorAction Stop
            try {
                $null = Start-BackupQueue -EngineLockPath $LockPath -QueuePath $QueuePath -LogDirectory $LogDirectory
                'UnexpectedSuccess'
            }
            catch { [string]$_.Exception.Data['BackupCode'] }
        } -ArgumentList $modulePath, $options.EngineLockPath, $queuePath, $options.LogDirectory
        $workerResult = @(Receive-Job -Job $worker -Wait -ErrorAction Stop)
        Assert-True ($workerResult.Count -eq 1 -and $workerResult[0] -eq 'LockBusyOrUnavailable') 'Second PowerShell process cannot acquire engine lock'
    }
    finally {
        if ($null -ne $worker) { Remove-Job -Job $worker -Force -ErrorAction Stop }
        $heldLock.Dispose()
    }
    $fileLock = [IO.File]::Open($queuePath + '.lock', [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { Assert-Throws { Add-BackupJob -Job (New-BackupJob @jobArguments) @queueOptions } 'Queue writes are exclusive' }
    finally { $fileLock.Dispose() }
    $badQueuePath = Join-Path $root 'Config\broken.json'
    [IO.File]::WriteAllText($badQueuePath, '{ corrupt')
    Assert-Throws { Start-BackupQueue -QueuePath $badQueuePath @options } 'Corrupt queue fails closed'
    Assert-True ([IO.File]::ReadAllText($badQueuePath) -ceq '{ corrupt') 'Corrupt queue is never reset'
    Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $queuePath -Parent) -Filter '*.tmp').Count -eq 0) 'No temporary queue files left'

    $observedJob = New-BackupJob @jobArguments
    $injectedJob = New-BackupJob @jobArguments
    $null = Add-BackupJob -Job $observedJob @queueOptions
    $state.ObservationQueue = $queuePath
    $state.ObservationLog = $options.LogDirectory
    $state.ObservedStages = [Collections.Generic.List[string]]::new()
    $state.InjectJob = $injectedJob
    $observedResults = @(Start-BackupQueue -QueuePath $queuePath @options)
    Assert-True ($observedResults.Count -eq 2 -and $observedResults[1].JobId -eq $injectedJob.Id) 'Producer can enqueue during pipeline without lost updates'
    Assert-True ($state.ObservedStages.Count -eq 2 -and @($state.ObservedStages | Where-Object { $_ -ne 'Running' }).Count -eq 0) 'Monitoring reads active stage while worker runs'

    $nativeOptions = @{
        Executable = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
        Arguments = @('-NoProfile', '-NonInteractive', '-File', (Join-Path $PSScriptRoot 'TestFixtures\NativeCommandProbe.ps1'), '-Value', 'D:\data with spaces\')
        TimeoutSeconds = 15
    }
    $engineModule = Get-Module BackupEngine
    $nativeOutput = & $engineModule { param($Options) Invoke-BackupCommand @Options } $nativeOptions
    Assert-True (($nativeOutput | ConvertFrom-Json).Value -ceq 'D:\data with spaces\') 'Native argument quoting and stderr draining'
    $failureOptions = $nativeOptions.Clone()
    $failureOptions.Arguments = $nativeOptions.Arguments + @('-ExitCode', '7')
    $nativeFailure = $null
    try { $null = & $engineModule { param($Options) Invoke-BackupCommand @Options } $failureOptions }
    catch { $nativeFailure = $_.Exception.Data['BackupCode'] }
    Assert-True ($nativeFailure -eq 'ExternalCommandFailed') 'Actual nonzero exit is rejected'
    $timeoutOptions = $nativeOptions.Clone()
    $timeoutOptions.Arguments = $nativeOptions.Arguments + @('-Block')
    $timeoutOptions.TimeoutSeconds = 1
    $timeoutFailure = $null
    try { $null = & $engineModule { param($Options) Invoke-BackupCommand @Options } $timeoutOptions }
    catch { $timeoutFailure = $_.Exception.Data['BackupCode'] }
    Assert-True ($timeoutFailure -eq 'ProcessTimeout') 'Actual process timeout is enforced'

    $events = @(Get-ChildItem -LiteralPath $options.LogDirectory -Filter '*.jsonl' | Get-Content | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True (@($events | Where-Object { $_.Step -eq 'VERIFY' -and $_.Status -eq 'Failed' }).Count -ge 7) 'Verification failures are logged'
    Write-Output ('PASS: {0} BackupEngine assertions (CLI test doubles, no live remote).' -f $script:Assertions)
}
catch {
    Write-Error ('BackupEngine tests failed: ' + $_.Exception.Message) -ErrorAction Continue
    throw
}
finally {
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
}
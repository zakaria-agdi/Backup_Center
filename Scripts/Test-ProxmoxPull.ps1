#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RclonePath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = Split-Path $PSScriptRoot -Parent
$engine = Import-Module (Join-Path $project 'Modules\BackupEngine.psd1') -Force -PassThru
$rclone = (Get-Command $RclonePath -CommandType Application -ErrorAction Stop).Source
$keygen = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupPull-' + [guid]::NewGuid().ToString('N'))
$server = $null; $context = $null; $web = $null; $watcher = $null
$environment = @{}
$checks = 0
function Assert-Pull { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message }; $script:checks++ }
try {
    & $engine { param($path); Protect-BackupWorkDirectory $path } $root
    foreach ($variable in @(Get-ChildItem Env:RCLONE_*)) {
        $environment[$variable.Name] = $variable.Value
        Remove-Item -LiteralPath ('Env:' + $variable.Name)
    }
    $env:RCLONE_CONFIG = Join-Path $root 'rclone.conf'
    [IO.File]::WriteAllText($env:RCLONE_CONFIG, "[pulltest]`ntype = local`n")
    foreach ($name in @('host', 'client')) {
        $keyInfo = [Diagnostics.ProcessStartInfo]::new()
        $keyInfo.FileName = $keygen; $keyInfo.UseShellExecute = $false; $keyInfo.CreateNoWindow = $true
        $keyInfo.RedirectStandardOutput = $true; $keyInfo.RedirectStandardError = $true
        $keyInfo.Arguments = '-q -t ed25519 -N "" -f "' + (Join-Path $root $name) + '"'
        $keyProcess = [Diagnostics.Process]::new(); $keyProcess.StartInfo = $keyInfo
        try {
            if (-not $keyProcess.Start()) { throw 'Fixture key generation unavailable' }
            if (-not $keyProcess.WaitForExit(15000)) { $keyProcess.Kill(); $keyProcess.WaitForExit(); throw 'Fixture key generation timed out' }
            if ($keyProcess.ExitCode -ne 0) { throw 'Fixture key generation failed' }
        }
        finally { $keyProcess.Dispose() }
    }
    $sourceDirectory = Join-Path $root 'source'
    $null = [IO.Directory]::CreateDirectory($sourceDirectory)
    $fileName = 'vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst'
    $source = Join-Path $sourceDirectory $fileName
    $payload = New-Object byte[] 8MB
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($payload); [IO.File]::WriteAllBytes($source, $payload) }
    finally { $random.Dispose(); [Array]::Clear($payload, 0, $payload.Length) }
    $archive = [pscustomobject]@{ FileName = $fileName; RemotePath = '/' + $fileName; Size = 8MB }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $rclone; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.Arguments = 'serve sftp "' + $sourceDirectory + '" --addr 127.0.0.1:0 --key "' +
        (Join-Path $root 'host') + '" --authorized-keys "' + (Join-Path $root 'client.pub') +
        '" --read-only --bwlimit 2M --use-json-log --log-level INFO'
    $server = [Diagnostics.Process]::new(); $server.StartInfo = $info
    Assert-Pull ($server.Start()) 'Local SFTP server starts'
    $serverOutput = $server.StandardOutput.ReadToEndAsync()
    $startup = [Diagnostics.Stopwatch]::StartNew(); $port = 0
    while ($port -eq 0 -and $startup.Elapsed.TotalSeconds -lt 15) {
        $line = $server.StandardError.ReadLineAsync()
        if (-not $line.Wait(15000)) { throw 'Local SFTP startup timeout' }
        $message = $line.GetAwaiter().GetResult()
        if ($null -eq $message) { throw 'Local SFTP stopped before listening' }
        if ($message -match 'listening.*127\.0\.0\.1:([0-9]+)') { $port = [int]$Matches[1] }
    }
    Assert-Pull ($port -gt 0) 'SFTP bound to a loopback ephemeral port'
    $serverErrors = $server.StandardError.ReadToEndAsync()
    $knownHosts = Join-Path $root 'known_hosts'
    $hostPublicKey = [IO.File]::ReadAllText((Join-Path $root 'host.pub')).Trim()
    [IO.File]::WriteAllText($knownHosts, ('[127.0.0.1]:' + $port + ' ' + $hostPublicKey + "`n"))
    $settings = [pscustomobject]@{ SftpUser = 'backup'; SftpPort = $port; KnownHostsFile = $knownHosts
        PrivateKeyFile = Join-Path $root 'client'; RclonePath = $rclone; UploadDestination = 'pulltest:' + (Join-Path $root 'uploaded') }
    $samples = [Collections.Generic.List[object]]::new()
    $options = @{ SftpHost = '127.0.0.1'; Settings = $settings; ResolveArchive = { $archive }.GetNewClosure()
        WorkDirectory = Join-Path $root 'Temp'; ConfigPath = Join-Path $root 'secrets.json'
        LogDirectory = Join-Path $root 'Logs'; EngineLockPath = Join-Path $root 'engine.lock'; CommandTimeoutSeconds = 30
        OnProgress = { param($state); if ($null -ne $state.Progress) { $samples.Add($state.Progress.PSObject.Copy()) } }.GetNewClosure() }
    $result = Invoke-ProxmoxTransferPipeline @options
    Assert-Pull ($result.Status -ceq 'Success') ('Real SFTP Pull succeeds: ' + $result.ErrorCode)
    Assert-Pull (@($samples | Where-Object { $_.Step -ceq 'Export/Pull' -and $_.Bytes -gt 0 -and $_.TotalBytes -eq 8MB -and $_.BytesPerSecond -gt 0 }).Count -gt 0) 'Real rclone JSON yields numeric Pull progress and speed'
    $restored = Join-Path $root 'restored.zst'
    Unprotect-BackupArchive -SourcePath $result.Artifact.Path -OutputPath $restored -ConfigPath $options.ConfigPath -LogDirectory $options.LogDirectory
    Assert-Pull ((Get-FileHash $source).Hash -ceq (Get-FileHash $restored).Hash) 'Downloaded and decrypted bytes exactly match the SFTP source'
    $uploaded = Join-Path (Join-Path $root 'uploaded') ([IO.Path]::GetFileName($result.Artifact.Path))
    Assert-Pull ((Get-FileHash $uploaded).Hash -ceq (Get-FileHash $result.Artifact.Path).Hash) 'Only encrypted artifact reaches isolated local upload destination'
    foreach ($mode in @('WrongHost', 'WrongClient', 'WrongSize')) {
        if ($mode -ceq 'WrongHost') {
            $wrongKey = [IO.File]::ReadAllText((Join-Path $root 'client.pub')).Trim()
            [IO.File]::WriteAllText($knownHosts, ('[127.0.0.1]:' + $port + ' ' + $wrongKey + "`n"))
        }
        elseif ($mode -ceq 'WrongClient') { $settings.PrivateKeyFile = Join-Path $root 'host' }
        else { $archive.Size++ }
        $result = Invoke-ProxmoxTransferPipeline @options
        $expectedCode = if ($mode -ceq 'WrongSize') { 'PullSizeMismatch' } else { 'ExternalCommandFailed' }
        Assert-Pull ($result.Status -ceq 'Failed' -and $result.ErrorCode -ceq $expectedCode) ('Real SFTP rejects ' + $mode + ': ' + $result.ErrorCode)
        Assert-Pull ($null -eq $result.Artifact -and ($result.Steps.Status -join ',') -ceq 'Failed,Skipped,Skipped,Skipped,Skipped,Skipped') 'Rejected Pull cannot proceed to encryption or upload'
        Assert-Pull (@(Get-ChildItem $options.WorkDirectory -Recurse -File | Where-Object { $_.Extension -in @('.zst', '.partial') }).Count -eq 0) 'No plaintext or partial file after rejected Pull'
        [IO.File]::WriteAllText($knownHosts, ('[127.0.0.1]:' + $port + ' ' + $hostPublicKey + "`n"))
        $settings.PrivateKeyFile = Join-Path $root 'client'; $archive.Size = 8MB
    }
    $null = [IO.Directory]::CreateDirectory((Join-Path $root 'Modules'))
    foreach ($file in @('WebBackend.psm1', 'Security.psd1', 'Security.psm1', 'BackupEngine.psd1', 'BackupEngine.psm1')) {
        Copy-Item -LiteralPath (Join-Path $project ('Modules\' + $file)) -Destination (Join-Path $root 'Modules')
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Fixtures\TransferTestHypervisors.psm1') -Destination (Join-Path $root 'Modules\Hypervisors.psm1')
    New-ModuleManifest -Path (Join-Path $root 'Modules\Hypervisors.psd1') -RootModule 'Hypervisors.psm1' -FunctionsToExport @('Get-ProxmoxBackupArtifact', 'Invoke-ProxmoxBackupTest')
    [IO.File]::WriteAllText((Join-Path $root 'artifact.json'), ($archive | ConvertTo-Json))
    $web = Import-Module (Join-Path $root 'Modules\WebBackend.psm1') -Force -PassThru
    $context = New-BackupCenterWebContext -ProjectRoot $root -TargetPath (Join-Path $project 'Config\proxmox.example.json')
    $context.Target.ApiUri = 'https://127.0.0.1:8006/'
    [IO.File]::WriteAllText($context.TransferSettingsPath, ($settings | ConvertTo-Json))
    $saved = Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' @{ TokenId = 'backup@pve!pullfixture'; TokenSecret = 'TEST-ONLY-PULL-SECRET' }
    Assert-Pull ($saved.StatusCode -eq 200) 'Worker credentials stored with isolated DPAPI'
    $record = [pscustomobject]@{ Id = [guid]::NewGuid().ToString(); Status = 'Success'; Storage = 'local'; VMName = $context.Target.ExpectedName
        TaskId = 'UPID:pve:0001:0002:0003:vzdump:9001:backup@pve!pullfixture:'; ErrorCode = $null
        PollCount = 1; UpdatedUtc = [DateTimeOffset]::UtcNow.ToString('o') }
    & $web { param($context, $record); Save-BackupCenterTestRecord $context $record } $context $record
    $watcher = [IO.FileSystemWatcher]::new((Split-Path $context.BackupTestPath -Parent), '*.json')
    $watcher.EnableRaisingEvents = $true
    $request = @{ BackupId = $record.Id; RequestId = [guid]::NewGuid().ToString(); Confirmation = 'TRANSFER 9001' }
    $accepted = Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $request
    Assert-Pull ($accepted.StatusCode -eq 202) 'Continuation accepted by actual Start-Job worker'
    $sameRequest = Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $request
    Assert-Pull ($sameRequest.StatusCode -eq 202 -and $sameRequest.Body.Id -ceq $accepted.Body.Id) 'Duplicate request reuses the admitted transfer'
    $admitted = [IO.File]::ReadAllText($context.BackupTestPath) | ConvertFrom-Json
    Assert-Pull ($null -ne $admitted.Transfer) 'Admitted transfer persisted before observing worker'
    $progressSeen = $false; $clock = [Diagnostics.Stopwatch]::StartNew()
    while (-not $progressSeen -and $clock.Elapsed.TotalSeconds -lt 20) {
        $change = $watcher.WaitForChanged([IO.WatcherChangeTypes]::All, 10000)
        if ($change.TimedOut) { break }
        $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
        Assert-Pull ($dashboard.StatusCode -eq 200) 'Dashboard available while child worker runs'
        Assert-Pull ($null -ne $dashboard.Body.BackupTest -and $null -ne $dashboard.Body.Transfer) 'Concurrent dashboard reads preserve backup and transfer state'
        $progress = $dashboard.Body.Transfer.Progress
        $progressSeen = ($null -ne $progress -and $progress.Step -ceq 'Export/Pull' -and $progress.Bytes -gt 0 -and $progress.BytesPerSecond -gt 0)
        if ($dashboard.Body.Transfer.Status -in @('Failed', 'Success', 'Unknown')) { break }
    }
    Assert-Pull $progressSeen 'Child worker persists live Pull speed to dashboard'
    $finished = Wait-Job -Job $context.BackupWorker -Timeout 45
    Assert-Pull ($null -ne $finished -and $finished.State -ceq 'Completed') 'Transfer worker exits cleanly'
    $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
    Assert-Pull ($dashboard.Body.Transfer.Status -ceq 'Success') ('Worker completes transfer: ' + $dashboard.Body.Transfer.ErrorCode)
    Assert-Pull ($dashboard.Body.BackupTest.TaskId -ceq $record.TaskId) 'Original export UPID preserved, no second vzdump'
    $output = @(Receive-Job -Job $context.BackupWorker -ErrorAction Stop)
    Assert-Pull ($output.Count -eq 0) 'No raw worker output'
    $serialized = ($dashboard.Body | ConvertTo-Json -Depth 8) + [IO.File]::ReadAllText($context.BackupTestPath)
    Assert-Pull ($serialized -notmatch 'TEST-ONLY-PULL-SECRET|TokenSecret') 'No credential leaked in dashboard or state'
    Write-Host ('PASS: ' + $checks + ' Pull assertions; real loopback SFTP/rclone/worker/DPAPI; simulated Proxmox resolver, local upload only.')
}
finally {
    if ($null -ne $context -and $null -ne $context.BackupWorker) { Remove-Job -Job $context.BackupWorker -Force -ErrorAction SilentlyContinue }
    if ($null -ne $watcher) { $watcher.Dispose() }
    if ($null -ne $server) {
        if (-not $server.HasExited) { $server.Kill(); $server.WaitForExit() }
        $server.Dispose()
    }
    if ($null -ne $web) { Remove-Module $web -Force -ErrorAction SilentlyContinue }
    foreach ($variable in @(Get-ChildItem Env:RCLONE_*)) { Remove-Item -LiteralPath ('Env:' + $variable.Name) }
    foreach ($name in $environment.Keys) { Set-Item -LiteralPath ('Env:' + $name) -Value $environment[$name] }
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupCenter.HypervisorTests.' + [Guid]::NewGuid().ToString('N'))
$script:Assertions = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('Assertion failed: ' + $Message) }
    $script:Assertions++
}

try {
    $manifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\Hypervisors.psd1'
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Assert-True ($manifest.ExportedFunctions.Count -eq 7) 'Manifest exposes adapters, status, storage, remote backup test and archive resolver'
    $module = Import-Module $manifestPath -Force -PassThru
    $state = @{
        Mode = 'Good'; Calls = [Collections.Generic.List[string]]::new()
        Waits = [Collections.Generic.List[int]]::new(); TaskCompleted = $false
    }
    & $module {
        param($state)
        $script:TestState = $state
        $script:RealProxmoxRequest = ${function:Invoke-ProxmoxRequest}
        $script:RealHypervisorCommand = ${function:Invoke-HypervisorCommand}
        function script:Invoke-RestMethod {
            [CmdletBinding()]
            param($Uri, $Method, $Headers, $TimeoutSec, $MaximumRedirection, $Body, $ContentType, [switch]$SkipHeaderValidation)
            if ($Headers.Authorization -cne 'PVEAPIToken=backup@pve!worker=TEST-ONLY-TOKEN') { throw 'Incorrect token header' }
            if ($SkipHeaderValidation.IsPresent -ne ($PSVersionTable.PSVersion.Major -ge 6)) { throw 'Incorrect Proxmox header validation mode' }
            $script:TestState.HeaderReference = $Headers
            $script:TestState.Transport = [pscustomobject]@{
                Uri = $Uri; Method = $Method; Timeout = $TimeoutSec; Redirects = $MaximumRedirection
                ContentType = $ContentType; Body = $Body
            }
            if ($script:TestState.Mode -eq 'HttpFailure') { throw 'TEST-ONLY-TOKEN private diagnostic' }
            if ($script:TestState.Mode -eq 'BadEnvelope') { return [pscustomobject]@{ unexpected = 1 } }
            return [pscustomobject]@{ data = 'TEST-ONLY API data' }
        }
        function script:Invoke-HypervisorCommand {
            param($Command, $Parameters)
            $script:TestState.Calls.Add($Command)
            if ($Command -eq 'Hyper-V\Get-VM') {
                $vmState = if ($script:TestState.Mode -eq 'Saved') { 'Saved' } else { 'Running' }
                return [pscustomobject]@{ Id = $Parameters.Id; State = $vmState }
            }
            if ($Command -eq 'Hyper-V\Export-VM') {
                if ($Parameters.CaptureLiveState -ne 'CaptureDataConsistentState') { throw 'Incorrect consistency mode' }
                if ($script:TestState.Mode -eq 'ExportFailure') { throw 'TEST-ONLY vendor error containing sensitive details' }
                if ($script:TestState.Mode -eq 'Empty') { return }
                [IO.File]::WriteAllText((Join-Path $Parameters.Path 'vm.vmcx'), 'TEST-ONLY configuration')
                [IO.File]::WriteAllText((Join-Path $Parameters.Path 'disk.vhdx'), 'TEST-ONLY disk')
                return
            }
            if ($Command -eq 'VMware.VimAutomation.Core\Get-VM') {
                $powerState = if ($script:TestState.Mode -eq 'Running') { 'PoweredOn' } else { 'PoweredOff' }
                return [pscustomobject]@{ Id = $Parameters.Id; PowerState = $powerState }
            }
            if ($Command -eq 'VMware.VimAutomation.Core\Export-VApp') {
                if ($Parameters.Format -ne 'Ovf' -or $Parameters.SHAAlgorithm -ne 'SHA256' -or -not $Parameters.Server.IsConnected) { throw 'Incorrect export options' }
                if ($script:TestState.Mode -eq 'ExportFailure') { throw 'TEST-ONLY vendor error containing sensitive details' }
                if ($script:TestState.Mode -eq 'Empty') { return }
                [IO.File]::WriteAllText((Join-Path $Parameters.Destination 'vm.ovf'), 'TEST-ONLY OVF')
                [IO.File]::WriteAllText((Join-Path $Parameters.Destination 'disk.vmdk'), 'TEST-ONLY disk')
                return
            }
            throw 'Unexpected vendor command'
        }
        function script:Wait-HypervisorPoll {
            param($Milliseconds)
            $script:TestState.Waits.Add($Milliseconds)
        }
        function script:Invoke-ProxmoxRequest {
            param($ApiUri, $TokenId, $TokenSecret, $Path, $Method = 'GET', $Body, $TimeoutSeconds)
            $script:TestState.Calls.Add($Method + ':' + $Path)
            if ($TokenSecret -isnot [Security.SecureString]) { throw 'Expected secure token' }
            if ($Path -eq '/storage/backup') {
                $type = if ($script:TestState.Mode -eq 'PBS') { 'pbs' } else { 'dir' }
                return [pscustomobject]@{ type = $type }
            }
            if ($Path -eq '/nodes/pve/qemu/100/config') { return [pscustomobject]@{ name = 'test' } }
            if ($Path -eq '/nodes/pve/qemu/100/status/current') {
                if ($script:TestState.Mode -eq 'BadVMStatus') { return [pscustomobject]@{ status = 'running' } }
                return [pscustomobject]@{ name = 'test'; status = 'running'; cpu = 0.25; mem = 1024L; maxmem = 4096L; uptime = 60L }
            }
            if ($Path -eq '/nodes/pve/vzdump') {
                if ($Method -ne 'POST' -or $Body.vmid -ne 100 -or $Body.remove -ne 0 -or $Body['prune-backups'] -ne 'keep-all=1') { throw 'Unsafe vzdump request' }
                if ($script:TestState.Mode -eq 'InvalidUPID') { return 'UPID:other:0001:0002:0003:vzdump:100:user@pam:' }
                $script:TestState.Polls = 0
                $script:TestState.TaskCompleted = $false
                return 'UPID:pve:0001:0002:0003:vzdump:100:user@pam:'
            }
            if ($Path -match '/tasks/UPID%3A.*?/status$') {
                $script:TestState.Polls++
                if ($script:TestState.Mode -eq 'NullStatus') { return $null }
                if ($script:TestState.Mode -eq 'MissingStatus') { return [pscustomobject]@{ exitstatus = 'OK' } }
                if ($script:TestState.Mode -eq 'UnknownStatus') { return [pscustomobject]@{ status = 'unknown' } }
                if ($script:TestState.Mode -eq 'MissingExitStatus') { return [pscustomobject]@{ status = 'stopped' } }
                if ($script:TestState.Mode -eq 'StatusHttpFailure') { Stop-HypervisorOperation 'ProxmoxRequestFailed' }
                if ($script:TestState.Mode -eq 'SlowTask' -and $script:TestState.Polls -lt 4) {
                    return [pscustomobject]@{ status = 'running'; exitstatus = 'OK' }
                }
                if ($script:TestState.Polls -eq 1 -or $script:TestState.Mode -eq 'Timeout') { return [pscustomobject]@{ status = 'running' } }
                $exitStatus = if ($script:TestState.Mode -eq 'TaskFailed') { 'ERROR: private diagnostic' } else { 'OK' }
                $script:TestState.TaskCompleted = $exitStatus -ceq 'OK'
                return [pscustomobject]@{ status = 'stopped'; exitstatus = $exitStatus }
            }
            if ($Path -match '/log\?start=') {
                if (-not $script:TestState.TaskCompleted) { throw 'Archive retrieval before task success' }
                if ($script:TestState.Mode -eq 'NoArchive') { return @() }
                $name = if ($script:TestState.Mode -eq 'WrongVM') { 'vzdump-qemu-999-2026_09_07-12_00_00.vma.zst' } else { $script:TestState.ArchiveName }
                if ($script:TestState.Mode -eq 'LogPagination' -and $Path -match 'start=0&') {
                    return @(1..500 | ForEach-Object { [pscustomobject]@{ n = $_; t = 'INFO: backing up' } })
                }
                return [pscustomobject]@{ n = 501; t = "INFO: creating vzdump archive '/var/lib/vz/dump/$name'" }
            }
            if ($Path -match '/content\?') {
                if ($script:TestState.Mode -eq 'Missing') { return @() }
                $size = if ($script:TestState.Mode -eq 'WrongSize') { 999 } else { $script:TestState.ArchiveSize }
                return [pscustomobject]@{ volid = ('backup:backup/' + $script:TestState.ArchiveName); vmid = 100; size = $size }
            }
            throw 'Unexpected API route'
        }
    } $state
    $options = @{
        DestinationDirectory = (Join-Path $root 'Exports'); LogDirectory = (Join-Path $root 'Logs')
        EngineLockPath = (Join-Path $root 'engine.lock')
    }
    $vmId = [Guid]::NewGuid()
    $good = Export-HyperVVM -VMId $vmId @options
    Assert-True ($good.Status -eq 'Success' -and $good.Provider -eq 'HyperV') 'Hyper-V standardized success'
    Assert-True ($good.SourceKind -eq 'Local' -and [IO.Directory]::Exists($good.SourcePath)) 'Local pipeline source exists'
    Assert-True ($good.Files.Count -eq 2 -and $good.Files[0].SHA256.Length -eq 64 -and $good.TotalBytes -gt 0) 'Export inventory and hashes'
    Assert-True ($good.Consistency -eq 'ProductionCheckpoint') 'Production checkpoint requested'
    Assert-True ((Get-Acl -LiteralPath $good.SourcePath).AreAccessRulesProtected) 'Private export ACL'
    foreach ($mode in @('Saved', 'Empty', 'ExportFailure')) {
        $state.Mode = $mode
        $failed = Export-HyperVVM -VMId $vmId @options
        Assert-True ($failed.Status -eq 'Failed' -and $null -eq $failed.SourcePath) ('No usable source after ' + $mode)
    }
    $state.Mode = 'Good'
    $heldLock = [IO.File]::Open($options.EngineLockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        $count = $state.Calls.Count
        $blocked = Export-HyperVVM -VMId $vmId @options
        Assert-True ($blocked.ErrorCode -eq 'LockBusyOrUnavailable' -and $state.Calls.Count -eq $count) 'Shared execution lock prevents vendor calls'
    }
    finally { $heldLock.Dispose() }
    $vmwareOptions = @{ VMId = 'VirtualMachine-vm-42'; Server = [pscustomobject]@{ IsConnected = $true } }
    $vmware = Export-VMwareVM @vmwareOptions @options
    Assert-True ($vmware.Status -eq 'Success' -and $vmware.Consistency -eq 'PoweredOff' -and $vmware.Files.Count -eq 2) 'PowerCLI export standardized and verified locally'
    foreach ($mode in @('Running', 'Empty', 'ExportFailure')) {
        $state.Mode = $mode
        $failed = Export-VMwareVM @vmwareOptions @options
        Assert-True ($failed.Status -eq 'Failed' -and $null -eq $failed.SourcePath) ('VMware rejects ' + $mode)
    }
    $state.Mode = 'Good'
    $disconnected = Export-VMwareVM -VMId $vmwareOptions.VMId -Server ([pscustomobject]@{ IsConnected = $false }) @options
    Assert-True ($disconnected.ErrorCode -eq 'VIServerNotConnected') 'Explicit connected VIServer required'
    $dumpDirectory = Join-Path $root 'dump'
    $null = [IO.Directory]::CreateDirectory($dumpDirectory)
    $state.ArchiveName = 'vzdump-qemu-100-2026_09_07-12_00_00.vma.zst'
    $remoteArchive = Join-Path $dumpDirectory $state.ArchiveName
    [IO.File]::WriteAllText($remoteArchive, 'TEST-ONLY Proxmox archive')
    $state.ArchiveSize = [IO.FileInfo]::new($remoteArchive).Length
    $token = ConvertTo-SecureString 'TEST-ONLY-TOKEN' -AsPlainText -Force
    $proxmoxOptions = @{
        ApiUri = [uri]'https://pve.invalid:8006/'; TokenId = 'backup@pve!worker'; TokenSecret = $token
        Node = 'pve'; VMId = 100; Storage = 'backup'; DumpDirectory = $dumpDirectory
    }
    $proxmox = Export-ProxmoxVM @proxmoxOptions @options
    $statusOptions = $proxmoxOptions.Clone()
    $statusOptions.Remove('Storage')
    $statusOptions.Remove('DumpDirectory')
    $state.Calls.Clear()
    $vmStatus = Get-ProxmoxVMStatus @statusOptions
    Assert-True ($vmStatus.VMId -eq 100 -and $vmStatus.Status -eq 'running' -and $vmStatus.CpuUsage -eq 0.25) 'Read-only VM status is projected'
    Assert-True ($state.Calls.Count -eq 1 -and $state.Calls[0] -eq 'GET:/nodes/pve/qemu/100/status/current') 'VM status never starts vzdump'
    $state.Mode = 'BadVMStatus'
    $invalidStatus = $false
    try { $null = Get-ProxmoxVMStatus @statusOptions }
    catch { $invalidStatus = $_.Exception.Data['HypervisorCode'] -eq 'ProxmoxInvalidResponse' }
    Assert-True $invalidStatus 'Incomplete VM status is rejected'
    $state.Mode = 'Good'
    Assert-True ($proxmox.Status -eq 'Success' -and $proxmox.Provider -eq 'Proxmox' -and $proxmox.TaskId.StartsWith('UPID:pve:')) 'Proxmox task completes and returns UPID'
    Assert-True ($state.Polls -eq 2 -and $proxmox.Files.Count -eq 1 -and $proxmox.TotalBytes -eq $state.ArchiveSize) 'Poll running then OK before retrieval'
    Assert-True ([IO.File]::Exists($remoteArchive) -and $proxmox.SourceKind -eq 'Local') 'Remote backup retained and local source returned'
    $state.Mode = 'SlowTask'
    $state.Calls.Clear()
    $state.Waits.Clear()
    $slow = Export-ProxmoxVM @proxmoxOptions @options -PollIntervalSeconds 2
    Assert-True ($slow.Status -eq 'Success' -and $state.Polls -eq 4) 'Continue polling while running even when exitstatus is OK'
    Assert-True ($state.Waits.Count -eq 3 -and @($state.Waits | Where-Object { $_ -ne 2000 }).Count -eq 0) 'Configured interval separates status requests'
    Assert-True (@($state.Calls | Where-Object { $_ -eq 'POST:/nodes/pve/vzdump' }).Count -eq 1) 'Polling never resubmits vzdump'
    $failedTaskExports = @()
    foreach ($mode in @('NullStatus', 'MissingStatus', 'UnknownStatus', 'MissingExitStatus', 'TaskFailed', 'StatusHttpFailure')) {
        $state.Mode = $mode
        $state.Calls.Clear()
        $failed = Export-ProxmoxVM @proxmoxOptions @options
        $failedTaskExports += $failed
        $expectedCode = switch ($mode) {
            'TaskFailed' { 'ProxmoxTaskFailed' }
            'StatusHttpFailure' { 'ProxmoxRequestFailed' }
            default { 'ProxmoxInvalidTaskStatus' }
        }
        Assert-True ($failed.Status -eq 'Failed' -and $failed.ErrorCode -eq $expectedCode -and $null -eq $failed.SourcePath) ('Explicit polling failure: ' + $mode)
        Assert-True (@($state.Calls | Where-Object { $_ -match '/log\?|/content\?' }).Count -eq 0 -and
            @(Get-ChildItem -LiteralPath $failed.WorkPath -File -Recurse).Count -eq 0) ('No retrieval after ' + $mode)
        Assert-True (@($state.Calls | Where-Object { $_ -eq 'POST:/nodes/pve/vzdump' }).Count -eq 1 -and
            $null -ne $failed.TaskId) ('Preserve task identity without restarting after ' + $mode)
    }
    foreach ($mode in @('PBS', 'InvalidUPID', 'TaskFailed', 'NoArchive', 'WrongVM', 'Missing', 'WrongSize')) {
        $state.Mode = $mode
        $failed = Export-ProxmoxVM @proxmoxOptions @options
        Assert-True ($failed.Status -eq 'Failed' -and $null -eq $failed.SourcePath) ('Proxmox rejects ' + $mode)
    }
    $state.Mode = 'LogPagination'
    $paged = Export-ProxmoxVM @proxmoxOptions @options
    Assert-True ($paged.Status -eq 'Success') 'Archive identified beyond first task log page'
    $state.Mode = 'Timeout'
    $timedOut = Export-ProxmoxVM @proxmoxOptions @options -TaskTimeoutSeconds 1
    Assert-True ($timedOut.ErrorCode -eq 'ProxmoxTaskTimeout' -and $null -ne $timedOut.TaskId) 'Bounded polling preserves task id on timeout'
    Assert-True ($timedOut.TaskState -eq 'Running' -and $proxmox.TaskState -eq 'Stopped') 'Remote last-known task state is distinct from local failure'
    $state.Mode = 'Good'
    $unsafeEndpoint = $proxmoxOptions.Clone()
    $unsafeEndpoint.ApiUri = [uri]'http://pve.invalid:8006/'
    $before = $state.Calls.Count
    $rejected = Export-ProxmoxVM @unsafeEndpoint @options
    Assert-True ($rejected.ErrorCode -eq 'InvalidProxmoxEndpoint' -and $state.Calls.Count -eq $before) 'Reject cleartext API before credentials are used'
    $rejected = Export-ProxmoxVM @proxmoxOptions @options -Mode stop
    Assert-True ($rejected.ErrorCode -eq 'GuestShutdownNotAuthorized') 'Downtime requires explicit authorization'
    $stopped = Export-ProxmoxVM @proxmoxOptions @options -Mode stop -AllowGuestShutdown
    Assert-True ($stopped.Status -eq 'Success' -and $stopped.Consistency -eq 'OrderlyShutdown') 'Explicit stop backup mode'
    Assert-True (($good.PSObject.Properties.Name -join ',') -eq ($proxmox.PSObject.Properties.Name -join ',') -and
        ($good.PSObject.Properties.Name -join ',') -eq ($vmware.PSObject.Properties.Name -join ',')) 'Identical output contract across providers'
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules\BackupEngine.psd1') -Force
    $jobOptions = @{
        Name = 'HypervisorTest'; PrimaryDestination = 'primary:backups'; OffsiteDestination = 'offsite:backups'
        ArchiveDirectory = (Join-Path $root 'Archive'); Recipient = ('age1' + ('q' * 58))
    }
    $remoteFiles = @{}
    $runner = {
        param($Executable, $Arguments)
        if ($Executable -eq 'age.test') {
            $destination = $Arguments[[Array]::IndexOf($Arguments, '--output') + 1]
            [IO.File]::Copy($Arguments[-1], $destination)
            return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
        }
        if ($Arguments[0] -eq 'copyto') {
            $source = Get-Item -LiteralPath $Arguments[-2]
            $remoteFiles[$Arguments[-1]] = @{
                Name = $source.Name; IsDir = $false; Size = $source.Length
                Hashes = @{ 'SHA-256' = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash }
            }
            return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
        }
        if ($Arguments[0] -eq 'lsjson') { return [pscustomobject]@{ ExitCode = 0; Stdout = ($remoteFiles[$Arguments[-1]] | ConvertTo-Json -Depth 5) } }
        throw 'Unexpected pipeline command'
    }.GetNewClosure()
    foreach ($export in @($good, $vmware, $proxmox)) {
        $job = New-BackupJob -ExportResult $export @jobOptions
        Assert-True ($job.SourcePath -eq $export.SourcePath -and $job.SourceKind -eq 'Local') ('Job accepts ' + $export.Provider)
        $pipeline = Start-BackupPipeline -Job $job -WorkDirectory (Join-Path $root 'PipelineWork') -LogDirectory $options.LogDirectory -EngineLockPath $options.EngineLockPath -AgePath 'age.test' -RclonePath 'rclone.test' -CommandRunner $runner
        Assert-True ($pipeline.Status -eq 'Success' -and $pipeline.Steps[5].Status -eq 'Success') ('Full pipeline verifies ' + $export.Provider)
        Assert-True ([IO.Directory]::Exists($export.SourcePath)) 'Original export retained for explicit retention'
    }
    $rejectedExport = $false
    try { $null = New-BackupJob -ExportResult $timedOut @jobOptions } catch { $rejectedExport = $true }
    Assert-True $rejectedExport 'Failed exports cannot become pipeline jobs'
    foreach ($failedTask in $failedTaskExports) {
        $rejectedExport = $false
        try { $null = New-BackupJob -ExportResult $failedTask @jobOptions } catch { $rejectedExport = $true }
        Assert-True $rejectedExport ('Polling failure cannot reach compression: ' + $failedTask.ErrorCode)
    }
    $queuePath = Join-Path $root 'queue.json'
    $queuedJob = New-BackupJob -ExportResult $proxmox @jobOptions
    $null = Add-BackupJob -Job $queuedJob -QueuePath $queuePath -LogDirectory $options.LogDirectory
    $queueResult = @(Start-BackupQueue -QueuePath $queuePath -WorkDirectory (Join-Path $root 'QueueWork') -LogDirectory $options.LogDirectory -EngineLockPath $options.EngineLockPath -AgePath 'age.test' -RclonePath 'rclone.test' -CommandRunner $runner)
    Assert-True ($queueResult.Count -eq 1 -and $queueResult[0].Status -eq 'Success') 'Export-backed job survives JSON queue round trip'
    $transportResult = & $module {
        param($token)
        & $script:RealProxmoxRequest -ApiUri ([uri]'https://pve.invalid:8006/') -TokenId 'backup@pve!worker' -TokenSecret $token -Path '/nodes/pve/vzdump' -Method POST -Body @{ vmid = 100 } -TimeoutSeconds 17
    } $token
    Assert-True ($transportResult -eq 'TEST-ONLY API data') 'REST helper unwraps data envelope'
    Assert-True ($state.Transport.Uri -ceq 'https://pve.invalid:8006/api2/json/nodes/pve/vzdump' -and
        $state.Transport.Redirects -eq 0 -and $state.Transport.Timeout -eq 17 -and $state.Transport.ContentType -eq 'application/x-www-form-urlencoded') 'REST URL, timeout, redirect and body contract'
    Assert-True ($state.HeaderReference.Count -eq 0) 'Authorization header cleared after request'
    foreach ($mode in @('HttpFailure', 'BadEnvelope')) {
        $state.Mode = $mode
        $safeFailure = $false
        try {
            $null = & $module {
                param($token)
                & $script:RealProxmoxRequest -ApiUri ([uri]'https://pve.invalid:8006/') -TokenId 'backup@pve!worker' -TokenSecret $token -Path '/storage/backup'
            } $token
        }
        catch { $safeFailure = $_.Exception.Message -notmatch 'TEST-ONLY-TOKEN|private diagnostic' -and $_.Exception.Data.Contains('HypervisorCode') }
        Assert-True ($safeFailure -and $state.HeaderReference.Count -eq 0) ('REST failure is sanitized: ' + $mode)
    }
    $nativeDate = & $module { & $script:RealHypervisorCommand 'Microsoft.PowerShell.Utility\Get-Date' @{ Date = [datetime]'2026-09-07' } }
    Assert-True ($nativeDate -is [datetime] -and $nativeDate.Year -eq 2026) 'Native dispatcher invokes qualified command with parameters'
    $state.Mode = 'Good'
    $unavailableLog = Join-Path $root 'not-a-log-directory'
    [IO.File]::WriteAllText($unavailableLog, 'TEST-ONLY blocker')
    $badOptions = $options.Clone()
    $badOptions.LogDirectory = $unavailableLog
    $before = $state.Calls.Count
    $auditFailed = $false
    try { $null = Export-HyperVVM -VMId $vmId @badOptions }
    catch { $auditFailed = $_.Exception.Data['HypervisorCode'] -eq 'AuditUnavailable' }
    Assert-True ($auditFailed -and $state.Calls.Count -eq $before) 'Audit outage blocks all hypervisor operations'
    $token.Dispose()
    $audit = (Get-ChildItem -LiteralPath $options.LogDirectory -Filter '*.jsonl' | Get-Content) -join "`n"
    Assert-True ($audit -notmatch 'sensitive details|private diagnostic|TEST-ONLY-TOKEN') 'No raw vendor errors or tokens in audit'
    Write-Output ('PASS: {0} Hypervisors assertions (simulated hypervisors, no live VM).' -f $script:Assertions)
}
finally {
    Remove-Module Hypervisors -Force -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
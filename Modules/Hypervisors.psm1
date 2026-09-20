#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ProjectRoot = Split-Path $PSScriptRoot -Parent

function Stop-HypervisorOperation {
    param([string]$Code)
    $exception = [InvalidOperationException]::new('BackupCenter: ' + $Code)
    $exception.Data['HypervisorCode'] = $Code
    throw $exception
}

function Write-HypervisorEvent {
    param([pscustomobject]$Result, [string]$LogDirectory)
    $stream = $null
    try {
        $null = [IO.Directory]::CreateDirectory($LogDirectory)
        $now = [DateTimeOffset]::UtcNow
        $entry = [ordered]@{
            TimestampUtc = $now.ToString('o'); Component = 'BackupCenter.Hypervisors'
            ExportId = $Result.ExportId; Provider = $Result.Provider
            Phase = $Result.Phase; Status = $Result.Status; ErrorCode = $Result.ErrorCode; ProcessId = $PID
        } | ConvertTo-Json -Compress
        $path = Join-Path $LogDirectory ('hypervisors-{0}.jsonl' -f $now.ToString('yyyy-MM-dd'))
        $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $bytes = [Text.Encoding]::UTF8.GetBytes($entry + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    catch { Stop-HypervisorOperation 'AuditUnavailable' }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function New-HypervisorDirectory {
    param([string]$Path)
    $identity = $null
    try {
        if (Test-Path -LiteralPath $Path) { Stop-HypervisorOperation 'ExportDirectoryAlreadyExists' }
        $null = [IO.Directory]::CreateDirectory($Path)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
            $null = $acl.RemoveAccessRuleSpecific($rule)
        }
        foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl',
                ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [Security.AccessControl.PropagationFlags]::None, 'Allow')
            $null = $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
    finally { if ($null -ne $identity) { $identity.Dispose() } }
}

function Set-HypervisorPhase {
    param([pscustomobject]$Result, [string]$Phase, [string]$LogDirectory)
    $Result.Phase = $Phase
    Write-HypervisorEvent $Result $LogDirectory
}

function Invoke-HypervisorExport {
    param([string]$Provider, [string]$VMId, [string]$DestinationDirectory, [string]$LogDirectory,
        [string]$EngineLockPath, [scriptblock]$Action)
    $result = [pscustomobject][ordered]@{
        SchemaVersion = 1; ExportId = [Guid]::NewGuid().ToString('D'); Provider = $Provider; VMId = $VMId
        Status = 'Running'; Phase = 'Preparing'; SourceKind = 'Local'; SourcePath = $null; WorkPath = $null
        StartedUtc = [DateTimeOffset]::UtcNow.ToString('o'); CompletedUtc = $null; DurationMs = 0L
        TaskId = $null; TaskState = 'NotApplicable'; Consistency = $null; ErrorCode = $null; Files = @(); TotalBytes = 0L
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $lock = $null
    try {
        Write-HypervisorEvent $result $LogDirectory
        $lockPath = [IO.Path]::GetFullPath($EngineLockPath)
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($lockPath))
        try { $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None') }
        catch { Stop-HypervisorOperation 'LockBusyOrUnavailable' }
        $result.WorkPath = Join-Path ([IO.Path]::GetFullPath($DestinationDirectory)) $result.ExportId
        New-HypervisorDirectory $result.WorkPath
        $null = & $Action $result
        Set-HypervisorPhase $result 'Validating' $LogDirectory
        $items = @(Get-ChildItem -LiteralPath $result.WorkPath -Recurse -Force -ErrorAction Stop)
        if (@($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
            Stop-HypervisorOperation 'ExportReparsePointNotAllowed'
        }
        $files = @($items | Where-Object { -not $_.PSIsContainer })
        if ($files.Count -eq 0) { Stop-HypervisorOperation 'EmptyExport' }
        $result.Files = @($files | ForEach-Object {
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($result.WorkPath.Length + 1)
                Size = $_.Length; SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            }
        })
        $result.TotalBytes = [long](($files | Measure-Object Length -Sum).Sum)
        if ($result.TotalBytes -le 0) { Stop-HypervisorOperation 'EmptyExport' }
        $result.SourcePath = $result.WorkPath
        $result.Status = 'Success'
        $result.Phase = 'Completed'
    }
    catch {
        $result.Status = 'Failed'
        $result.SourcePath = $null
        $result.ErrorCode = if ($_.Exception.Data.Contains('HypervisorCode')) { [string]$_.Exception.Data['HypervisorCode'] } else { 'HypervisorExportFailed' }
    }
    finally {
        $timer.Stop()
        $result.DurationMs = $timer.ElapsedMilliseconds
        $result.CompletedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        if ($null -ne $lock) { $lock.Dispose() }
    }
    Write-HypervisorEvent $result $LogDirectory
    return $result
}

function Invoke-HypervisorCommand {
    param([string]$Command, [hashtable]$Parameters)
    & $Command @Parameters -ErrorAction Stop -Verbose:$false -Debug:$false -WarningAction SilentlyContinue
}

function Export-HyperVVM {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][Guid]$VMId,
        [string]$DestinationDirectory = (Join-Path $script:ProjectRoot 'Work\Hypervisors'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock')
    )
    Invoke-HypervisorExport -Provider 'HyperV' -VMId $VMId.ToString('D') -DestinationDirectory $DestinationDirectory -LogDirectory $LogDirectory -EngineLockPath $EngineLockPath -Action {
        param($result)
        $machines = @(Invoke-HypervisorCommand 'Hyper-V\Get-VM' @{ Id = $VMId })
        if ($machines.Count -ne 1) { Stop-HypervisorOperation 'VMNotUnique' }
        $machine = $machines[0]
        if ([string]$machine.State -notin @('Running', 'Off')) { Stop-HypervisorOperation 'UnsupportedVMState' }
        $result.Consistency = if ([string]$machine.State -eq 'Off') { 'PoweredOff' } else { 'ProductionCheckpoint' }
        Set-HypervisorPhase $result 'Exporting' $LogDirectory
        $null = Invoke-HypervisorCommand 'Hyper-V\Export-VM' @{
            VM = $machine; Path = $result.WorkPath; CaptureLiveState = 'CaptureDataConsistentState'; Confirm = $false
        }
        $configs = @(Get-ChildItem -LiteralPath $result.WorkPath -File -Recurse -ErrorAction Stop |
            Where-Object { $_.Extension -in @('.vmcx', '.xml') -and $_.Length -gt 0 })
        if ($configs.Count -eq 0) { Stop-HypervisorOperation 'ExportConfigurationMissing' }
    }
}

function Invoke-ProxmoxRequest {
    param([uri]$ApiUri, [string]$TokenId, [Security.SecureString]$TokenSecret,
        [string]$Path, [string]$Method = 'GET', [hashtable]$Body, [int]$TimeoutSeconds = 60)
    $pointer = [IntPtr]::Zero
    $headers = @{}
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($TokenSecret)
        $headers.Authorization = 'PVEAPIToken=' + $TokenId + '=' + [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $parameters = @{
            Uri = $ApiUri.GetLeftPart([UriPartial]::Authority) + '/api2/json' + $Path
            Method = $Method; Headers = $headers; TimeoutSec = $TimeoutSeconds
            MaximumRedirection = 0; ErrorAction = 'Stop'; Verbose = $false; Debug = $false
        }
        if ($PSVersionTable.PSVersion.Major -ge 6) { $parameters.SkipHeaderValidation = $true }
        if ($null -ne $Body) { $parameters.Body = $Body; $parameters.ContentType = 'application/x-www-form-urlencoded' }
        $response = Invoke-RestMethod @parameters
        if ($null -eq $response -or $null -eq $response.PSObject.Properties['data']) {
            Stop-HypervisorOperation 'ProxmoxInvalidResponse'
        }
        return $response.data
    }
    catch {
        if ($_.Exception.Data.Contains('HypervisorCode')) { throw }
        Stop-HypervisorOperation 'ProxmoxRequestFailed'
    }
    finally {
        $headers.Clear()
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Wait-HypervisorPoll {
    param([int]$Milliseconds)
    [Threading.Thread]::Sleep($Milliseconds)
}

function Get-ProxmoxVMStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uri]$ApiUri,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+\z')][string]$TokenId,
        [Parameter(Mandatory)][Security.SecureString]$TokenSecret,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Node,
        [Parameter(Mandatory)][ValidateRange(100, 999999999)][int]$VMId
    )
    if (-not $ApiUri.IsAbsoluteUri -or $ApiUri.Scheme -cne 'https' -or $ApiUri.UserInfo -or
        $ApiUri.Query -or $ApiUri.Fragment -or $ApiUri.AbsolutePath -ne '/') { Stop-HypervisorOperation 'InvalidProxmoxEndpoint' }
    if ($TokenSecret.Length -eq 0) { Stop-HypervisorOperation 'EmptyProxmoxToken' }
    $status = Invoke-ProxmoxRequest -ApiUri $ApiUri -TokenId $TokenId -TokenSecret $TokenSecret `
        -Path ('/nodes/' + [uri]::EscapeDataString($Node) + '/qemu/' + $VMId + '/status/current') -TimeoutSeconds 15
    if ($null -eq $status) { Stop-HypervisorOperation 'ProxmoxInvalidResponse' }
    foreach ($property in @('name', 'status', 'cpu', 'mem', 'maxmem', 'uptime')) {
        if ($null -eq $status.PSObject.Properties[$property]) { Stop-HypervisorOperation 'ProxmoxInvalidResponse' }
    }
    if ($status.name -isnot [string] -or $status.name.Length -gt 255 -or
        $status.status -cnotin @('running', 'stopped')) { Stop-HypervisorOperation 'ProxmoxInvalidResponse' }
    foreach ($property in @('cpu', 'mem', 'maxmem', 'uptime')) {
        $value = $status.$property
        if (($value -isnot [int] -and $value -isnot [long] -and $value -isnot [double]) -or
            [double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0) {
            Stop-HypervisorOperation 'ProxmoxInvalidResponse'
        }
    }
    [pscustomobject]@{
        Node = $Node; VMId = $VMId; Name = $status.name; Status = $status.status
        CpuUsage = $status.cpu; MemoryBytes = $status.mem; MaxMemoryBytes = $status.maxmem
        UptimeSeconds = $status.uptime; CheckedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Export-ProxmoxVM {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][uri]$ApiUri,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+\z')][string]$TokenId,
        [Parameter(Mandatory)][Security.SecureString]$TokenSecret,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Node,
        [Parameter(Mandatory)][ValidateRange(100, 999999999)][int]$VMId,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Storage,
        [Parameter(Mandatory)][string]$DumpDirectory,
        [ValidateSet('snapshot', 'stop')][string]$Mode = 'snapshot',
        [switch]$AllowGuestShutdown,
        [ValidateRange(1, 86400)][int]$TaskTimeoutSeconds = 3600,
        [ValidateRange(1, 60)][int]$PollIntervalSeconds = 5,
        [string]$DestinationDirectory = (Join-Path $script:ProjectRoot 'Work\Hypervisors'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock')
    )
    Invoke-HypervisorExport -Provider 'Proxmox' -VMId ([string]$VMId) -DestinationDirectory $DestinationDirectory -LogDirectory $LogDirectory -EngineLockPath $EngineLockPath -Action {
        param($result)
        if (-not $ApiUri.IsAbsoluteUri -or $ApiUri.Scheme -cne 'https' -or $ApiUri.UserInfo -or
            $ApiUri.Query -or $ApiUri.Fragment -or $ApiUri.AbsolutePath -ne '/') { Stop-HypervisorOperation 'InvalidProxmoxEndpoint' }
        if ($Mode -eq 'stop' -and -not $AllowGuestShutdown) { Stop-HypervisorOperation 'GuestShutdownNotAuthorized' }
        if ($TokenSecret.Length -eq 0) { Stop-HypervisorOperation 'EmptyProxmoxToken' }
        $dumpRoot = Get-Item -LiteralPath $DumpDirectory -Force -ErrorAction Stop
        if (-not $dumpRoot.PSIsContainer -or ($dumpRoot.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Stop-HypervisorOperation 'InvalidDumpDirectory'
        }
        $request = @{ ApiUri = $ApiUri; TokenId = $TokenId; TokenSecret = $TokenSecret }
        $nodePath = '/nodes/' + [uri]::EscapeDataString($Node)
        $storagePath = $nodePath + '/storage/' + [uri]::EscapeDataString($Storage)
        $configuration = Invoke-ProxmoxRequest @request -Path ('/storage/' + [uri]::EscapeDataString($Storage))
        if ($configuration.type -notin @('dir', 'nfs', 'cifs', 'cephfs')) { Stop-HypervisorOperation 'UnsupportedProxmoxStorage' }
        $null = Invoke-ProxmoxRequest @request -Path ($nodePath + '/qemu/' + $VMId + '/config')
        Set-HypervisorPhase $result 'Exporting' $LogDirectory
        $result.Consistency = if ($Mode -eq 'stop') { 'OrderlyShutdown' } else { 'Snapshot' }
        $taskClock = [Diagnostics.Stopwatch]::StartNew()
        $result.TaskState = 'Unknown'
        $upid = Invoke-ProxmoxRequest @request -Path ($nodePath + '/vzdump') -Method 'POST' -TimeoutSeconds ([Math]::Min(60, $TaskTimeoutSeconds)) -Body @{
            vmid = $VMId; storage = $Storage; mode = $Mode; compress = 'zstd'; remove = 0; 'prune-backups' = 'keep-all=1'
        }
        if ($upid -isnot [string] -or $upid.Length -gt 1024 -or
            $upid -cnotmatch '\AUPID:([^:]+):[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:vzdump:([0-9]*):[^:\r\n]+:\z') {
            Stop-HypervisorOperation 'InvalidTaskUPID'
        }
        if ($Matches[1] -cne $Node -or ($Matches[2] -ne '' -and $Matches[2] -ne [string]$VMId)) {
            Stop-HypervisorOperation 'InvalidTaskUPID'
        }
        $result.TaskId = $upid
        $result.TaskState = 'Running'
        $taskPath = $nodePath + '/tasks/' + [uri]::EscapeDataString($upid)
        Set-HypervisorPhase $result 'WaitingForTask' $LogDirectory
        while ($true) {
            $remaining = $TaskTimeoutSeconds - $taskClock.Elapsed.TotalSeconds
            if ($remaining -le 0) { Stop-HypervisorOperation 'ProxmoxTaskTimeout' }
            $status = Invoke-ProxmoxRequest @request -Path ($taskPath + '/status') -TimeoutSeconds ([int][Math]::Ceiling([Math]::Min(60, $remaining)))
            if ($taskClock.Elapsed.TotalSeconds -ge $TaskTimeoutSeconds) { Stop-HypervisorOperation 'ProxmoxTaskTimeout' }
            if ($null -eq $status -or $null -eq $status.PSObject.Properties['status'] -or
                $status.status -isnot [string] -or $status.status -cnotin @('running', 'stopped')) {
                Stop-HypervisorOperation 'ProxmoxInvalidTaskStatus'
            }
            if ($status.status -ceq 'stopped') {
                $result.TaskState = 'Stopped'
                if ($null -eq $status.PSObject.Properties['exitstatus'] -or
                    $status.exitstatus -isnot [string] -or [string]::IsNullOrWhiteSpace($status.exitstatus)) {
                    Stop-HypervisorOperation 'ProxmoxInvalidTaskStatus'
                }
                if ($status.exitstatus -cne 'OK') { Stop-HypervisorOperation 'ProxmoxTaskFailed' }
                break
            }
            $waitMilliseconds = [int][Math]::Min($PollIntervalSeconds * 1000, [Math]::Max(1, ($TaskTimeoutSeconds - $taskClock.Elapsed.TotalSeconds) * 1000))
            Wait-HypervisorPoll $waitMilliseconds
        }
        Set-HypervisorPhase $result 'Retrieving' $LogDirectory
        $archiveNames = @()
        $offset = 0
        do {
            $lines = @(Invoke-ProxmoxRequest @request -Path ($taskPath + '/log?start=' + $offset + '&limit=500'))
            foreach ($line in $lines) {
                if ([string]$line.t -match "creating (?:vzdump )?archive '([^'\r\n]+)'" ) {
                    $archiveNames += ([string]$Matches[1]).Split('/')[-1]
                }
            }
            $offset += $lines.Count
            if ($offset -ge 100000) { Stop-HypervisorOperation 'ProxmoxTaskLogTooLarge' }
        } while ($lines.Count -eq 500)
        $archiveNames = @($archiveNames | Select-Object -Unique)
        if ($archiveNames.Count -ne 1 -or $archiveNames[0] -cnotmatch ('\Avzdump-qemu-' + $VMId + '-[0-9_]{10}-[0-9_]{8}\.vma\.zst\z')) {
            Stop-HypervisorOperation 'ProxmoxArchiveNotIdentified'
        }
        $fileName = $archiveNames[0]
        $volid = $Storage + ':backup/' + $fileName
        $content = @(Invoke-ProxmoxRequest @request -Path ($storagePath + '/content?content=backup&vmid=' + $VMId))
        $matching = @($content | Where-Object { $_.volid -ceq $volid -and $_.vmid -eq $VMId })
        if ($matching.Count -ne 1 -or ($matching[0].size -isnot [int] -and $matching[0].size -isnot [long]) -or
            $matching[0].size -le 0) { Stop-HypervisorOperation 'ProxmoxArchiveMissing' }
        $sourcePath = Join-Path $dumpRoot.FullName $fileName
        $source = Get-Item -LiteralPath $sourcePath -Force -ErrorAction Stop
        if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $source.Length -ne $matching[0].size) {
            Stop-HypervisorOperation 'ProxmoxArchiveSizeMismatch'
        }
        $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256 -ErrorAction Stop).Hash
        $target = Join-Path $result.WorkPath $fileName
        [IO.File]::Copy($sourcePath, $target, $false)
        if ([IO.FileInfo]::new($target).Length -ne $matching[0].size -or
            (Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash -cne $sourceHash) {
            Stop-HypervisorOperation 'ProxmoxCopyIntegrityMismatch'
        }
    }
}

function Export-VMwareVM {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('\AVirtualMachine-vm-[0-9]+\z')][string]$VMId,
        [Parameter(Mandatory)][object]$Server,
        [string]$DestinationDirectory = (Join-Path $script:ProjectRoot 'Work\Hypervisors'),
        [string]$LogDirectory = (Join-Path $script:ProjectRoot 'Logs'),
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock')
    )
    Invoke-HypervisorExport -Provider 'VMware' -VMId $VMId -DestinationDirectory $DestinationDirectory -LogDirectory $LogDirectory -EngineLockPath $EngineLockPath -Action {
        param($result)
        if (@($Server).Count -ne 1 -or $Server.IsConnected -ne $true) { Stop-HypervisorOperation 'VIServerNotConnected' }
        $machines = @(Invoke-HypervisorCommand 'VMware.VimAutomation.Core\Get-VM' @{ Id = $VMId; Server = $Server })
        if ($machines.Count -ne 1) { Stop-HypervisorOperation 'VMNotUnique' }
        $machine = $machines[0]
        if ([string]$machine.PowerState -cne 'PoweredOff') { Stop-HypervisorOperation 'VMwareRequiresPoweredOff' }
        $result.Consistency = 'PoweredOff'
        Set-HypervisorPhase $result 'Exporting' $LogDirectory
        $null = Invoke-HypervisorCommand 'VMware.VimAutomation.Core\Export-VApp' @{
            VM = $machine; Server = $Server; Destination = $result.WorkPath; Format = 'Ovf'
            Name = 'vm'; CreateSeparateFolder = $false; SHAAlgorithm = 'SHA256'
        }
        $configs = @(Get-ChildItem -LiteralPath $result.WorkPath -File -Recurse -ErrorAction Stop |
            Where-Object { $_.Extension -eq '.ovf' -and $_.Length -gt 0 })
        if ($configs.Count -ne 1) { Stop-HypervisorOperation 'ExportConfigurationMissing' }
    }
}

function Get-ProxmoxBackupStorage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri]$ApiUri, [Parameter(Mandatory)][string]$TokenId,
        [Parameter(Mandatory)][Security.SecureString]$TokenSecret,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Node)
    if (-not $ApiUri.IsAbsoluteUri -or $ApiUri.Scheme -cne 'https' -or $ApiUri.UserInfo -or
        $ApiUri.Query -or $ApiUri.Fragment -or $ApiUri.AbsolutePath -ne '/') { Stop-HypervisorOperation 'InvalidProxmoxEndpoint' }
    $items = @(Invoke-ProxmoxRequest -ApiUri $ApiUri -TokenId $TokenId -TokenSecret $TokenSecret `
        -Path ('/nodes/' + $Node + '/storage?content=backup') -TimeoutSeconds 15)
    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        foreach ($property in @('storage', 'type', 'active', 'enabled', 'content', 'avail')) {
            if ($null -eq $item.PSObject.Properties[$property]) { Stop-HypervisorOperation 'ProxmoxInvalidResponse' }
        }
        if ($item.storage -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]*\z') { Stop-HypervisorOperation 'ProxmoxInvalidResponse' }
        if ($item.active -eq 1 -and $item.enabled -eq 1 -and $item.type -in @('dir', 'nfs', 'cifs', 'cephfs') -and
            'backup' -in ([string]$item.content).Split(',') -and
            ($item.avail -is [int] -or $item.avail -is [long]) -and $item.avail -gt 0) {
            [pscustomobject]@{ Name = $item.storage; AvailableBytes = [long]$item.avail }
        }
    }
}

function Get-ProxmoxBackupArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri]$ApiUri,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+\z')][string]$TokenId,
        [Parameter(Mandatory)][Security.SecureString]$TokenSecret,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Node,
        [Parameter(Mandatory)][ValidateRange(100, 999999999)][int]$VMId,
        [Parameter(Mandatory)][string]$ExpectedName,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Storage,
        [Parameter(Mandatory)][string]$TaskId)
    if ($TaskId.Length -gt 1024 -or
        $TaskId -cnotmatch '\AUPID:([^:]+):[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:vzdump:([0-9]*):([^:\r\n]+):\z' -or
        $Matches[1] -cne $Node -or ($Matches[2] -ne '' -and $Matches[2] -ne [string]$VMId) -or $Matches[3] -cne $TokenId) {
        Stop-HypervisorOperation 'TaskTokenMismatch'
    }
    $request = @{ ApiUri = $ApiUri; TokenId = $TokenId; TokenSecret = $TokenSecret }
    $vm = Get-ProxmoxVMStatus @request -Node $Node -VMId $VMId
    if ($vm.Name -cne $ExpectedName) { Stop-HypervisorOperation 'UnexpectedVM' }
    $taskPath = '/nodes/' + $Node + '/tasks/' + [uri]::EscapeDataString($TaskId)
    $status = Invoke-ProxmoxRequest @request -Path ($taskPath + '/status') -TimeoutSeconds 15
    if ($null -eq $status -or $null -eq $status.PSObject.Properties['exitstatus'] -or
        $status.status -cne 'stopped' -or $status.exitstatus -cne 'OK') { Stop-HypervisorOperation 'ProxmoxTaskNotSuccessful' }
    $paths = @()
    $offset = 0
    do {
        $lines = @(Invoke-ProxmoxRequest @request -Path ($taskPath + '/log?start=' + $offset + '&limit=500') -TimeoutSeconds 15)
        foreach ($line in $lines) {
            if ([string]$line.t -match "creating (?:vzdump )?archive '([^'\r\n]+)'") { $paths += [string]$Matches[1] }
        }
        $offset += $lines.Count
        if ($offset -ge 100000) { Stop-HypervisorOperation 'ProxmoxTaskLogTooLarge' }
    } while ($lines.Count -eq 500)
    $paths = @($paths | Select-Object -Unique)
    if ($paths.Count -ne 1 -or $paths[0] -cnotmatch ('\A/(?:[A-Za-z0-9_.-]+/)*vzdump-qemu-' + $VMId + '-[0-9_]{10}-[0-9_]{8}\.vma\.zst\z') -or
        $paths[0].Split('/') -contains '..' -or $paths[0].Split('/') -contains '.') { Stop-HypervisorOperation 'ProxmoxArchiveNotIdentified' }
    $fileName = $paths[0].Split('/')[-1]
    $volid = $Storage + ':backup/' + $fileName
    $content = @(Invoke-ProxmoxRequest @request -Path ('/nodes/' + $Node + '/storage/' + $Storage + '/content?content=backup&vmid=' + $VMId) -TimeoutSeconds 15)
    $matching = @($content | Where-Object { $_.volid -ceq $volid -and $_.vmid -eq $VMId })
    if ($matching.Count -ne 1 -or ($matching[0].size -isnot [int] -and $matching[0].size -isnot [long]) -or
        $matching[0].size -le 0) { Stop-HypervisorOperation 'ProxmoxArchiveMissing' }
    [pscustomobject]@{ FileName = $fileName; RemotePath = $paths[0]; Size = [long]$matching[0].size; TaskId = $TaskId }
}

function Invoke-ProxmoxBackupTest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri]$ApiUri,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+\z')][string]$TokenId,
        [Parameter(Mandatory)][Security.SecureString]$TokenSecret,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Node,
        [Parameter(Mandatory)][ValidateRange(100, 999999999)][int]$VMId,
        [Parameter(Mandatory)][string]$ExpectedName,
        [Parameter(Mandatory)][ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9_-]*\z')][string]$Storage,
        [Parameter(Mandatory)][scriptblock]$OnProgress,
        [ValidateRange(1, 86400)][int]$TaskTimeoutSeconds = 3600,
        [ValidateRange(1, 60)][int]$PollIntervalSeconds = 5,
        [string]$EngineLockPath = (Join-Path $script:ProjectRoot 'Config\backup-engine.run.lock'))
    $result = [pscustomobject]@{ Status = 'Pending'; TaskId = $null; ErrorCode = $null; PollCount = 0; Storage = $Storage }
    $lock = $null
    $submitted = $false
    try {
        $lock = [IO.File]::Open($EngineLockPath, 'OpenOrCreate', 'ReadWrite', 'None')
        $request = @{ ApiUri = $ApiUri; TokenId = $TokenId; TokenSecret = $TokenSecret }
        $vm = Get-ProxmoxVMStatus @request -Node $Node -VMId $VMId
        if ($vm.Name -cne $ExpectedName) { Stop-HypervisorOperation 'UnexpectedVM' }
        $storages = @(Get-ProxmoxBackupStorage @request -Node $Node)
        if (@($storages | Where-Object { $_.Name -ceq $Storage }).Count -ne 1) { Stop-HypervisorOperation 'BackupStorageUnavailable' }
        $result.Status = 'Submitting'
        $null = & $OnProgress $result
        $submitted = $true
        $upid = Invoke-ProxmoxRequest @request -Path ('/nodes/' + $Node + '/vzdump') -Method POST -Body @{
            vmid = $VMId; storage = $Storage; mode = 'snapshot'; compress = 'zstd'; remove = 0; 'prune-backups' = 'keep-all=1'
        }
        if ($upid -isnot [string] -or $upid.Length -gt 1024 -or
            $upid -cnotmatch '\AUPID:([^:]+):[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:vzdump:([0-9]*):([^:\r\n]+):\z' -or
            $Matches[1] -cne $Node -or ($Matches[2] -ne '' -and $Matches[2] -ne [string]$VMId) -or $Matches[3] -cne $TokenId) {
            Stop-HypervisorOperation 'InvalidTaskUPID'
        }
        $result.TaskId = $upid
        $result.Status = 'Running'
        $null = & $OnProgress $result
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $remaining = $TaskTimeoutSeconds - $clock.Elapsed.TotalSeconds
            if ($remaining -le 0) { Stop-HypervisorOperation 'ProxmoxTaskTimeout' }
            $status = Invoke-ProxmoxRequest @request -Path ('/nodes/' + $Node + '/tasks/' + [uri]::EscapeDataString($upid) + '/status') `
                -TimeoutSeconds ([int][Math]::Ceiling([Math]::Min(15, $remaining)))
            $result.PollCount++
            if ($clock.Elapsed.TotalSeconds -ge $TaskTimeoutSeconds) { Stop-HypervisorOperation 'ProxmoxTaskTimeout' }
            if ($null -eq $status -or $null -eq $status.PSObject.Properties['status'] -or $status.status -cnotin @('running', 'stopped')) {
                Stop-HypervisorOperation 'ProxmoxInvalidTaskStatus'
            }
            if ($status.status -ceq 'stopped') {
                if ($null -eq $status.PSObject.Properties['exitstatus'] -or $status.exitstatus -isnot [string] -or
                    [string]::IsNullOrWhiteSpace($status.exitstatus)) { Stop-HypervisorOperation 'ProxmoxInvalidTaskStatus' }
                $result.Status = if ($status.exitstatus -ceq 'OK') { 'Success' } else { 'Failed' }
                if ($result.Status -eq 'Failed') { $result.ErrorCode = 'ProxmoxTaskFailed' }
                break
            }
            $null = & $OnProgress $result
            Wait-HypervisorPoll ([int][Math]::Min($PollIntervalSeconds * 1000, [Math]::Max(1, ($TaskTimeoutSeconds - $clock.Elapsed.TotalSeconds) * 1000)))
        }
    }
    catch {
        $result.Status = if ($submitted) { 'Unknown' } else { 'Failed' }
        $result.ErrorCode = if ($_.Exception.Data.Contains('HypervisorCode')) { [string]$_.Exception.Data['HypervisorCode'] } else { 'BackupTestUnavailable' }
    }
    finally { if ($null -ne $lock) { $lock.Dispose() } }
    $null = & $OnProgress $result
    return $result
}

Export-ModuleMember -Function Export-ProxmoxVM, Export-HyperVVM, Export-VMwareVM, Get-ProxmoxVMStatus, Get-ProxmoxBackupStorage, Invoke-ProxmoxBackupTest, Get-ProxmoxBackupArtifact
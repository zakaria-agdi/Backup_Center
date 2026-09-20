#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Security.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Hypervisors.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'BackupEngine.psd1') -ErrorAction Stop

function Write-BackupCenterWebAudit {
    param([hashtable]$Context, [string]$Action, [string]$Outcome)
    $stream = $null
    try {
        $entry = [ordered]@{
            TimestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
            Component = 'BackupCenter.Web'; Action = $Action; Outcome = $Outcome; ProcessId = $PID
        } | ConvertTo-Json -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($entry + [Environment]::NewLine)
        $stream = [IO.File]::Open((Join-Path $Context.LogDirectory 'security.log'), 'Append', 'Write', 'Read')
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    catch { throw [InvalidOperationException]::new('WebAuditUnavailable') }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function New-BackupCenterWebContext {
    param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string]$TargetPath,
        [ValidateRange(1024, 65535)][int]$Port = 8080)
    $target = [IO.File]::ReadAllText($TargetPath) | ConvertFrom-Json -ErrorAction Stop
    $uri = [uri]$target.ApiUri
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or $uri.UserInfo -or
        $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/' -or
        $target.Node -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]*\z' -or
        ($target.VMId -isnot [int] -and $target.VMId -isnot [long]) -or $target.VMId -lt 100 -or $target.VMId -gt 999999999 -or
        $target.ExpectedName -isnot [string] -or $target.ExpectedName.Length -gt 255) {
        throw [InvalidOperationException]::new('InvalidProxmoxTarget')
    }
    foreach ($directory in @('Config', 'Logs', 'Temp')) {
        $null = [IO.Directory]::CreateDirectory((Join-Path $ProjectRoot $directory))
    }
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    try { $random.GetBytes($bytes); $nonce = [Convert]::ToBase64String($bytes) }
    finally { $random.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
    $context = @{
        Origin = 'http://127.0.0.1:' + $Port; HostHeader = '127.0.0.1:' + $Port; Nonce = $nonce
        Target = $target; SecretPath = Join-Path $ProjectRoot 'Config\secrets.json'
        BackupTestPath = Join-Path $ProjectRoot 'Config\proxmox-backup-test.json'
        TransferSettingsPath = Join-Path $ProjectRoot 'Config\proxmox-transfer.json'
        WorkDirectory = Join-Path $ProjectRoot 'Temp'
        EngineLockPath = Join-Path $ProjectRoot 'Config\backup-engine.run.lock'
        BackupWorker = $null
        QueuePath = Join-Path $ProjectRoot 'Config\backup-queue.json'; LogDirectory = Join-Path $ProjectRoot 'Logs'
        CredentialsConfigured = $false; LastProbeStarted = [DateTimeOffset]::MinValue
        Probe = @{ State = 'NotConfigured'; VM = $null; CheckedUtc = $null; ErrorCode = $null }
    }
    if ([IO.File]::Exists($context.SecretPath)) {
        $credential = $null
        try {
            $credential = Get-BackupSecret -Name 'Proxmox.Test.ApiToken' -ConfigPath $context.SecretPath -LogDirectory $context.LogDirectory
            $context.CredentialsConfigured = $true
            $context.Probe.State = 'NotChecked'
        }
        catch { $context.Probe.State = 'CredentialsUnavailable' }
        finally { if ($null -ne $credential) { $credential.Dispose() } }
    }
    Write-BackupCenterWebAudit $context 'Server.Start' 'Success'
    return $context
}

function Test-BackupCenterWebRequest {
    param([hashtable]$Context, [string]$RemoteAddress, [string]$HostHeader, [string]$Origin,
        [string]$FetchSite, [string]$Method, [string]$Path, [string]$ClientHeader,
        [string]$Nonce, [string]$ContentType, [long]$ContentLength)
    $address = $null
    if (-not [Net.IPAddress]::TryParse($RemoteAddress, [ref]$address)) { return 403 }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4() }
    if (-not [Net.IPAddress]::IsLoopback($address) -or $HostHeader -cne $Context.HostHeader -or
        ($Origin -and $Origin -cne $Context.Origin) -or $FetchSite -ceq 'cross-site') { return 403 }
    if ($ContentLength -gt 16384) { return 413 }
    if ($Path.StartsWith('/api/', [StringComparison]::OrdinalIgnoreCase)) {
        if ($ClientHeader -cne 'dashboard') { return 403 }
        if ($Method -ceq 'POST' -and ($Origin -cne $Context.Origin -or
            $Nonce -cne $Context.Nonce -or $ContentType -notmatch '\Aapplication/json(?:\s*;\s*charset=utf-8)?\z')) { return 403 }
    }
    return 200
}

function Invoke-BackupCenterStateAccess {
    param([hashtable]$Context, [scriptblock]$Action)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $pathBytes = [Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($Context.BackupTestPath).ToUpperInvariant())
        $name = 'Local\BackupCenter.State.' + ([BitConverter]::ToString($hash.ComputeHash($pathBytes))).Replace('-', '')
    }
    finally { $hash.Dispose() }
    $mutex = [Threading.Mutex]::new($false, $name)
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(5000) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw [InvalidOperationException]::new('StateAccessUnavailable') }
        & $Action
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Read-BackupCenterTestRecord {
    param([hashtable]$Context)
    Invoke-BackupCenterStateAccess $Context {
        if ([IO.File]::Exists($Context.BackupTestPath)) {
            return ([IO.File]::ReadAllText($Context.BackupTestPath) | ConvertFrom-Json -ErrorAction Stop)
        }
        return $null
    }
}

function Save-BackupCenterTestRecord {
    param([hashtable]$Context, $Record)
    Invoke-BackupCenterStateAccess $Context {
        $Record.UpdatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        $temporary = $Context.BackupTestPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes(($Record | ConvertTo-Json -Depth 6 -Compress))
            $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
            try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
            finally { $stream.Dispose() }
            if ([IO.File]::Exists($Context.BackupTestPath)) { [IO.File]::Replace($temporary, $Context.BackupTestPath, [NullString]::Value) }
            else { [IO.File]::Move($temporary, $Context.BackupTestPath) }
        }
        finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    }
}

function Invoke-BackupCenterCredential {
    param([hashtable]$Context, [scriptblock]$Action)
    $stored = $null; $token = $null; $credential = $null; $pointer = [IntPtr]::Zero
    try {
        $stored = Get-BackupSecret -Name 'Proxmox.Test.ApiToken' -ConfigPath $Context.SecretPath -LogDirectory $Context.LogDirectory
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($stored)
        $credential = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) | ConvertFrom-Json -ErrorAction Stop
        $token = ConvertTo-SecureString $credential.TokenSecret -AsPlainText -Force
        $tokenId = $credential.TokenId
        $credential = $null
        & $Action @{ ApiUri = [uri]$Context.Target.ApiUri; TokenId = $tokenId; TokenSecret = $token }
    }
    finally {
        $credential = $null
        if ($null -ne $token) { $token.Dispose() }
        if ($null -ne $stored) { $stored.Dispose() }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Test-BackupCenterTransferActive {
    param($Record)
    return ($null -ne $Record -and $null -ne $Record.PSObject.Properties['Transfer'] -and
        $null -ne $Record.Transfer -and $Record.Transfer.Status -notin @('Success', 'Failed'))
}

function Read-BackupCenterTransferSettings {
    param([hashtable]$Context)
    if (-not [IO.File]::Exists($Context.TransferSettingsPath)) { return $null }
    if ([IO.FileInfo]::new($Context.TransferSettingsPath).Length -gt 16384) { throw 'InvalidTransferConfiguration' }
    $settings = [IO.File]::ReadAllText($Context.TransferSettingsPath) | ConvertFrom-Json -ErrorAction Stop
    $required = @('SftpUser', 'SftpPort', 'KnownHostsFile', 'PrivateKeyFile', 'RclonePath', 'UploadDestination')
    if (@($settings.PSObject.Properties).Count -ne $required.Count) { throw 'InvalidTransferConfiguration' }
    foreach ($name in $required) { if ($null -eq $settings.PSObject.Properties[$name]) { throw 'InvalidTransferConfiguration' } }
    return $settings
}

function Invoke-BackupCenterTransferWorker {
    param([hashtable]$Context, $Record)
    try {
        $settings = Read-BackupCenterTransferSettings $Context
        if ($null -eq $settings) { throw 'TransferConfigurationRequired' }
        $saveRecord = ${function:Save-BackupCenterTestRecord}
        $progress = {
            param($update)
            $Record.Transfer.Status = $update.Status; $Record.Transfer.ErrorCode = $update.ErrorCode
            $Record.Transfer.Steps = $update.Steps; $Record.Transfer.Progress = $update.Progress
            $Record.Transfer.Artifact = $update.Artifact
            & $saveRecord $Context $Record
        }.GetNewClosure()
        Invoke-BackupCenterCredential $Context {
            param($credential)
            $resolveCommand = Get-Command Get-ProxmoxBackupArtifact -ErrorAction Stop
            $resolveOptions = @{ Node = $Context.Target.Node; VMId = $Context.Target.VMId
                ExpectedName = $Context.Target.ExpectedName; Storage = $Record.Storage; TaskId = $Record.TaskId }
            $resolve = {
                & $resolveCommand @credential @resolveOptions
            }.GetNewClosure()
            $null = Invoke-ProxmoxTransferPipeline -ResolveArchive $resolve -SftpHost ([uri]$Context.Target.ApiUri).Host `
                -Settings $settings -OnProgress $progress -WorkDirectory $Context.WorkDirectory -ConfigPath $Context.SecretPath `
                -LogDirectory $Context.LogDirectory -EngineLockPath $Context.EngineLockPath
        }
        Write-BackupCenterWebAudit $Context 'Transfer.Finish' $Record.Transfer.Status
    }
    catch {
        $Record.Transfer.Status = 'Unknown'; $Record.Transfer.ErrorCode = 'TransferWorkerUnavailable'
        try { Save-BackupCenterTestRecord $Context $Record } catch { }
    }
}

function Invoke-BackupCenterBackupWorker {
    param([hashtable]$Context, $Record)
    try {
        Invoke-BackupCenterCredential $Context {
            param($credential)
            $progress = {
                param($update)
                $Record.Status = $update.Status; $Record.TaskId = $update.TaskId
                $Record.ErrorCode = $update.ErrorCode; $Record.PollCount = $update.PollCount
                Save-BackupCenterTestRecord $Context $Record
            }
            $null = Invoke-ProxmoxBackupTest @credential -Node $Context.Target.Node -VMId $Context.Target.VMId `
                -ExpectedName $Context.Target.ExpectedName -Storage $Record.Storage -EngineLockPath $Context.EngineLockPath -OnProgress $progress
        }
        Write-BackupCenterWebAudit $Context 'BackupTest.Finish' $Record.Status
    }
    catch {
        $Record.Status = 'Unknown'; $Record.ErrorCode = 'BackupWorkerUnavailable'
        try { Save-BackupCenterTestRecord $Context $Record } catch { }
    }
}

function Start-BackupCenterBackupWorker {
    param([hashtable]$Context, $Record)
    if ($null -ne $Context.BackupWorker -and $Context.BackupWorker.State -in @('Completed', 'Failed', 'Stopped')) {
        Remove-Job -Job $Context.BackupWorker -Force -ErrorAction SilentlyContinue
    }
    $workerContext = @{
        Target = $Context.Target; SecretPath = $Context.SecretPath; LogDirectory = $Context.LogDirectory
        BackupTestPath = $Context.BackupTestPath; EngineLockPath = $Context.EngineLockPath
        TransferSettingsPath = $Context.TransferSettingsPath; WorkDirectory = $Context.WorkDirectory
    }
    $Context.BackupWorker = Start-Job -ScriptBlock {
        param($modulePath, $workerContext, $record)
        try {
            $module = Import-Module $modulePath -Force -PassThru -ErrorAction Stop
            & $module {
                param($context, $record)
                if ($null -ne $record.PSObject.Properties['Transfer'] -and $null -ne $record.Transfer) { Invoke-BackupCenterTransferWorker $context $record }
                else { Invoke-BackupCenterBackupWorker $context $record }
            } $workerContext $record
        }
        catch { }
    } -ArgumentList (Join-Path $PSScriptRoot 'WebBackend.psm1'), $workerContext, $Record -ErrorAction Stop
}

function Get-BackupCenterDashboard {
    param([hashtable]$Context)
    $jobs = @()
    if ([IO.File]::Exists($Context.QueuePath)) {
        $records = @(Get-BackupQueue -QueuePath $Context.QueuePath -LogDirectory $Context.LogDirectory)
        $jobs = @($records | Select-Object -First 100 | ForEach-Object {
            $steps = @()
            if ($null -ne $_.Result -and $null -ne $_.Result.PSObject.Properties['Steps']) {
                $steps = @($_.Result.Steps | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Status = $_.Status } })
            }
            [pscustomobject]@{ Id = $_.JobId; Name = $_.Job.Name; Status = $_.Status; UpdatedUtc = $_.UpdatedUtc; Steps = $steps }
        })
    }
    $record = Read-BackupCenterTestRecord $Context
    $backupTest = $null
    $transfer = $null
    $transferConfigured = $false
    try { $transferConfigured = $null -ne (Read-BackupCenterTransferSettings $Context) } catch { }
    if ($null -ne $record) {
        $status = $record.Status
        if ($status -in @('Pending', 'Submitting', 'Running') -and
            ([DateTimeOffset]::UtcNow - [DateTimeOffset]$record.UpdatedUtc).TotalSeconds -gt 120) { $status = 'Unknown' }
        $backupTest = [pscustomobject]@{
            Id = $record.Id; Status = $status; Storage = $record.Storage; PollCount = $record.PollCount
            TaskId = $record.TaskId; ErrorCode = $record.ErrorCode
        }
        $stepStatus = if ($status -eq 'Submitting') { 'Running' } else { $status }
        $jobs = @([pscustomobject]@{
            Id = $record.Id; Name = 'vzdump ' + $record.VMName; Status = $stepStatus; UpdatedUtc = $record.UpdatedUtc
            Kind = 'ProxmoxBackupTest'; Steps = @([pscustomobject]@{ Name = 'Export/Pull'; Status = $stepStatus })
        }) + $jobs
        if ($null -ne $record.PSObject.Properties['Transfer'] -and $null -ne $record.Transfer) {
            $transferStatus = $record.Transfer.Status
            if ($transferStatus -in @('Pending', 'Running') -and
                ([DateTimeOffset]::UtcNow - [DateTimeOffset]$record.UpdatedUtc).TotalSeconds -gt 120) { $transferStatus = 'Unknown' }
            $transfer = [pscustomobject]@{
                Id = $record.Transfer.Id; Status = $transferStatus; ErrorCode = $record.Transfer.ErrorCode
                Progress = $record.Transfer.Progress
            }
            $jobs[0].Kind = 'ProxmoxTransfer'; $jobs[0].Status = $transferStatus
            $jobs[0].Steps = @($record.Transfer.Steps | ForEach-Object {
                $projectedStatus = if ($transferStatus -eq 'Unknown' -and $_.Status -eq 'Running') { 'Unknown' } else { $_.Status }
                [pscustomobject]@{ Name = $_.Name; Status = $projectedStatus }
            })
        }
    }
    [pscustomobject]@{
        Mode = 'LocalBackupTest'; ServerUtc = [DateTimeOffset]::UtcNow.ToString('o'); BackupTest = $backupTest
        TransferConfigured = $transferConfigured; Transfer = $transfer
        Target = [pscustomobject]@{ ApiUri = $Context.Target.ApiUri; Node = $Context.Target.Node; VMId = $Context.Target.VMId; Name = $Context.Target.ExpectedName }
        CredentialsConfigured = $Context.CredentialsConfigured; Proxmox = $Context.Probe; Jobs = $jobs
    }
}

function Invoke-BackupCenterApi {
    param([hashtable]$Context, [string]$Method, [string]$Path, $Data)
    $action = 'Request'
    try {
        if ($Method -ceq 'GET' -and $Path -ceq '/api/session') {
            return @{ StatusCode = 200; Body = @{ Nonce = $Context.Nonce } }
        }
        if ($Method -ceq 'GET' -and $Path -ceq '/api/dashboard') {
            $action = 'Dashboard.Read'
            $dashboard = Get-BackupCenterDashboard $Context
            Write-BackupCenterWebAudit $Context $action 'Success'
            return @{ StatusCode = 200; Body = $dashboard }
        }
        if ($Method -ceq 'POST' -and $Path -ceq '/api/proxmox/credentials') {
            $action = 'Credentials.Save'
            $active = Read-BackupCenterTestRecord $Context
            if (($null -ne $active -and $active.Status -notin @('Success', 'Failed')) -or (Test-BackupCenterTransferActive $active)) {
                return @{ StatusCode = 409; Body = @{ ErrorCode = 'BackupTestActive' } }
            }
            if ($Data -isnot [Collections.IDictionary] -or $Data.Count -ne 2 -or
                -not $Data.Contains('TokenId') -or -not $Data.Contains('TokenSecret') -or
                $Data.TokenId -isnot [string] -or $Data.TokenId.Length -gt 128 -or
                $Data.TokenId -cnotmatch '\A[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+\z' -or
                $Data.TokenSecret -isnot [string] -or $Data.TokenSecret -cnotmatch '\A[!-~]{1,512}\z') {
                Write-BackupCenterWebAudit $Context $action 'Rejected'
                return @{ StatusCode = 400; Body = @{ ErrorCode = 'InvalidCredentials' } }
            }
            $secret = $null
            try {
                Write-BackupCenterWebAudit $Context $action 'Prepare'
                $json = @{ TokenId = $Data.TokenId; TokenSecret = $Data.TokenSecret } | ConvertTo-Json -Compress
                $secret = ConvertTo-SecureString $json -AsPlainText -Force
                $json = $null
                Initialize-BackupCenterConfig -ConfigPath $Context.SecretPath -LogDirectory $Context.LogDirectory
                Set-BackupSecret -Name 'Proxmox.Test.ApiToken' -Secret $secret -ConfigPath $Context.SecretPath -LogDirectory $Context.LogDirectory
                $Context.CredentialsConfigured = $true
                $Context.Probe = @{ State = 'NotChecked'; VM = $null; CheckedUtc = $null; ErrorCode = $null }
                Write-BackupCenterWebAudit $Context $action 'Success'
                return @{ StatusCode = 200; Body = @{ Saved = $true } }
            }
            finally { if ($null -ne $secret) { $secret.Dispose() }; $Data.Clear() }
        }
        if ($Method -ceq 'POST' -and $Path -ceq '/api/proxmox/test') {
            $action = 'Proxmox.Test'
            if (-not $Context.CredentialsConfigured) {
                return @{ StatusCode = 409; Body = @{ ErrorCode = 'CredentialsRequired' } }
            }
            if (([DateTimeOffset]::UtcNow - $Context.LastProbeStarted).TotalSeconds -lt 5) {
                return @{ StatusCode = 429; Body = @{ ErrorCode = 'ProbeCooldown' } }
            }
            $Context.LastProbeStarted = [DateTimeOffset]::UtcNow
            $stored = $null
            $token = $null
            $pointer = [IntPtr]::Zero
            try {
                Write-BackupCenterWebAudit $Context $action 'Prepare'
                $stored = Get-BackupSecret -Name 'Proxmox.Test.ApiToken' -ConfigPath $Context.SecretPath -LogDirectory $Context.LogDirectory
                $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($stored)
                $credential = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) | ConvertFrom-Json -ErrorAction Stop
                $token = ConvertTo-SecureString $credential.TokenSecret -AsPlainText -Force
                $tokenId = $credential.TokenId
                $credential = $null
                $vm = Get-ProxmoxVMStatus -ApiUri $Context.Target.ApiUri -Node $Context.Target.Node -VMId $Context.Target.VMId -TokenId $tokenId -TokenSecret $token
                if ($vm.Name -cne $Context.Target.ExpectedName) { throw [InvalidOperationException]::new('UnexpectedVM') }
                Write-BackupCenterWebAudit $Context $action 'Success'
                $Context.Probe = @{ State = 'Connected'; VM = $vm; CheckedUtc = $vm.CheckedUtc; ErrorCode = $null }
                return @{ StatusCode = 200; Body = $Context.Probe }
            }
            catch {
                $code = if ($_.Exception.Message -ceq 'UnexpectedVM') { 'UnexpectedVM' } else { 'ProxmoxConnectionFailed' }
                $Context.Probe = @{ State = 'Failed'; VM = $null; CheckedUtc = [DateTimeOffset]::UtcNow.ToString('o'); ErrorCode = $code }
                Write-BackupCenterWebAudit $Context $action 'Error'
                return @{ StatusCode = 502; Body = @{ ErrorCode = $code } }
            }
            finally {
                if ($null -ne $token) { $token.Dispose() }
                if ($null -ne $stored) { $stored.Dispose() }
                if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
            }
        }
        if ($Method -ceq 'POST' -and $Path -ceq '/api/proxmox/storages') {
            if (-not $Context.CredentialsConfigured) { return @{ StatusCode = 409; Body = @{ ErrorCode = 'CredentialsRequired' } } }
            $storages = @(Invoke-BackupCenterCredential $Context {
                param($credential)
                Get-ProxmoxBackupStorage @credential -Node $Context.Target.Node
            })
            return @{ StatusCode = 200; Body = @{ Storages = $storages } }
        }
        if ($Method -ceq 'POST' -and $Path -ceq '/api/proxmox/backup-test') {
            $action = 'BackupTest.Start'
            if (-not $Context.CredentialsConfigured) { return @{ StatusCode = 409; Body = @{ ErrorCode = 'CredentialsRequired' } } }
            if ($Data -isnot [Collections.IDictionary] -or $Data.Count -ne 4 -or
                -not $Data.Contains('Storage') -or -not $Data.Contains('Confirmation') -or -not $Data.Contains('RequestId') -or -not $Data.Contains('PreviousId') -or
                $Data.Storage -isnot [string] -or $Data.Storage -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]*\z' -or
                $Data.Confirmation -cne ('SNAPSHOT ' + $Context.Target.VMId) -or
                $Data.RequestId -isnot [string] -or $Data.RequestId -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -or
                $Data.PreviousId -isnot [string]) {
                return @{ StatusCode = 400; Body = @{ ErrorCode = 'InvalidBackupTest' } }
            }
            $admission = $null
            try {
                try { $admission = [IO.File]::Open(($Context.BackupTestPath + '.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
                catch { return @{ StatusCode = 409; Body = @{ ErrorCode = 'BackupTestActive' } } }
                $previous = Read-BackupCenterTestRecord $Context
                if ($null -ne $previous -and $previous.Id -ceq $Data.RequestId) {
                    if ($previous.Storage -cne $Data.Storage) { return @{ StatusCode = 409; Body = @{ ErrorCode = 'InvalidBackupTest' } } }
                    return @{ StatusCode = 202; Body = @{ Id = $previous.Id } }
                }
                $previousId = if ($null -eq $previous) { '' } else { $previous.Id }
                if ($Data.PreviousId -cne $previousId -or ($null -ne $previous -and $previous.Status -notin @('Success', 'Failed')) -or (Test-BackupCenterTransferActive $previous)) {
                    return @{ StatusCode = 409; Body = @{ ErrorCode = 'BackupTestActive' } }
                }
                Write-BackupCenterWebAudit $Context $action 'Prepare'
                $record = [pscustomobject]@{
                    Id = $Data.RequestId; VMName = $Context.Target.ExpectedName; Status = 'Pending'; Storage = $Data.Storage
                    TaskId = $null; PollCount = 0; ErrorCode = $null; UpdatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
                }
                Save-BackupCenterTestRecord $Context $record
                Start-BackupCenterBackupWorker $Context $record
                return @{ StatusCode = 202; Body = @{ Id = $record.Id } }
            }
            finally { if ($null -ne $admission) { $admission.Dispose() } }
        }
        if ($Method -ceq 'POST' -and $Path -ceq '/api/proxmox/transfer') {
            $action = 'Transfer.Start'
            if (-not $Context.CredentialsConfigured) { return @{ StatusCode = 409; Body = @{ ErrorCode = 'CredentialsRequired' } } }
            if ($Data -isnot [Collections.IDictionary] -or $Data.Count -ne 3 -or
                -not $Data.Contains('BackupId') -or -not $Data.Contains('RequestId') -or -not $Data.Contains('Confirmation') -or
                $Data.BackupId -isnot [string] -or $Data.RequestId -isnot [string] -or
                $Data.RequestId -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -or
                $Data.Confirmation -cne ('TRANSFER ' + $Context.Target.VMId)) {
                return @{ StatusCode = 400; Body = @{ ErrorCode = 'InvalidTransferRequest' } }
            }
            $admission = $null
            try {
                try { $admission = [IO.File]::Open(($Context.BackupTestPath + '.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
                catch { return @{ StatusCode = 409; Body = @{ ErrorCode = 'BackupTestActive' } } }
                $record = Read-BackupCenterTestRecord $Context
                if ($null -eq $record -or $record.Id -cne $Data.BackupId -or $record.Status -cne 'Success' -or -not $record.TaskId) {
                    return @{ StatusCode = 409; Body = @{ ErrorCode = 'SuccessfulBackupRequired' } }
                }
                if ($null -ne $record.PSObject.Properties['Transfer'] -and $null -ne $record.Transfer) {
                    if ($record.Transfer.Id -ceq $Data.RequestId) { return @{ StatusCode = 202; Body = @{ Id = $record.Transfer.Id } } }
                    return @{ StatusCode = 409; Body = @{ ErrorCode = 'TransferAlreadyRequested' } }
                }
                if ($null -eq (Read-BackupCenterTransferSettings $Context)) {
                    return @{ StatusCode = 409; Body = @{ ErrorCode = 'TransferConfigurationRequired' } }
                }
                Write-BackupCenterWebAudit $Context $action 'Prepare'
                $transfer = [pscustomobject]@{ Id = $Data.RequestId; Status = 'Pending'; ErrorCode = $null; Progress = $null; Artifact = $null
                    Steps = @('Export/Pull', 'Compress & Encrypt', 'Upload', 'Archive', 'Offsite', 'VERIFY') | ForEach-Object {
                        [pscustomobject]@{ Name = $_; Status = $(if ($_ -in @('Archive', 'Offsite', 'VERIFY')) { 'Skipped' } else { 'Pending' }) }
                    } }
                $record | Add-Member -NotePropertyName Transfer -NotePropertyValue $transfer -Force
                Save-BackupCenterTestRecord $Context $record
                Start-BackupCenterBackupWorker $Context $record
                return @{ StatusCode = 202; Body = @{ Id = $transfer.Id } }
            }
            finally { if ($null -ne $admission) { $admission.Dispose() } }
        }
        return @{ StatusCode = 404; Body = @{ ErrorCode = 'NotFound' } }
    }
    catch {
        return @{ StatusCode = 503; Body = @{ ErrorCode = 'OperationUnavailable' } }
    }
}

Export-ModuleMember -Function New-BackupCenterWebContext, Test-BackupCenterWebRequest, Invoke-BackupCenterApi, Write-BackupCenterWebAudit
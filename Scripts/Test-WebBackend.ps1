#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupCenter.WebTests.' + [Guid]::NewGuid().ToString('N'))
$script:Assertions = 0
function Assert-Web {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw ('Assertion failed: ' + $Label) }
    $script:Assertions++
}
try {
    $module = Import-Module (Join-Path $project 'Modules\WebBackend.psm1') -Force -PassThru
    $context = New-BackupCenterWebContext -ProjectRoot $root -TargetPath (Join-Path $project 'Config\proxmox.example.json')
    $request = @{
        Context = $context; RemoteAddress = '127.0.0.1'; HostHeader = '127.0.0.1:8080'
        Origin = $context.Origin; FetchSite = 'same-origin'; Method = 'GET'; Path = '/api/dashboard'
        ClientHeader = 'dashboard'; Nonce = ''; ContentType = ''; ContentLength = 0
    }
    Assert-Web ((Test-BackupCenterWebRequest @request) -eq 200) 'Local same-origin GET allowed'
    foreach ($case in @(
        @{ Key = 'HostHeader'; Value = 'evil.invalid:8080' },
        @{ Key = 'RemoteAddress'; Value = '192.168.1.2' },
        @{ Key = 'Origin'; Value = 'https://evil.invalid' },
        @{ Key = 'Origin'; Value = 'null' },
        @{ Key = 'FetchSite'; Value = 'cross-site' },
        @{ Key = 'ClientHeader'; Value = '' }
    )) {
        $invalid = $request.Clone(); $invalid[$case.Key] = $case.Value
        Assert-Web ((Test-BackupCenterWebRequest @invalid) -eq 403) ('Reject ' + $case.Key)
    }
    $post = $request.Clone(); $post.Method = 'POST'; $post.ContentType = 'application/json'; $post.Nonce = $context.Nonce
    $mixedCase = $request.Clone(); $mixedCase.Path = '/API/dashboard'; $mixedCase.ClientHeader = ''
    Assert-Web ((Test-BackupCenterWebRequest @mixedCase) -eq 403) 'Case-insensitive router cannot bypass API boundary'
    Assert-Web ((Test-BackupCenterWebRequest @post) -eq 200) 'Same-origin POST with nonce allowed'
    $post.Nonce = 'wrong'
    Assert-Web ((Test-BackupCenterWebRequest @post) -eq 403) 'POST nonce required'
    $post.Nonce = $context.Nonce; $post.ContentLength = 16385
    Assert-Web ((Test-BackupCenterWebRequest @post) -eq 413) 'Oversized request rejected'
    $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
    Assert-Web ($dashboard.StatusCode -eq 200 -and $dashboard.Body.Jobs.Count -eq 0 -and
        -not $dashboard.Body.CredentialsConfigured -and $dashboard.Body.Target.VMId -eq 9001) 'Honest unconfigured dashboard'
    & $module {
        param($context, $root)
        $job = New-BackupJob -Name 'Fixture job' -SourcePath (Join-Path $root 'Temp') `
            -PrimaryDestination 'primary:fixture' -OffsiteDestination 'offsite:fixture' `
            -ArchiveDirectory (Join-Path $root 'Archive') -Recipient ('age1' + ('q' * 58))
        $null = Add-BackupJob -Job $job -QueuePath $context.QueuePath -LogDirectory $context.LogDirectory
    } $context $root
    $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
    Assert-Web ($dashboard.StatusCode -eq 200 -and $dashboard.Body.Jobs.Count -eq 1 -and
        $dashboard.Body.Jobs[0].Name -eq 'Fixture job' -and $dashboard.Body.Jobs[0].Status -eq 'Pending') 'Real queue record projected'
    Assert-Web (($dashboard.Body.Jobs | ConvertTo-Json -Depth 8) -notmatch 'SourcePath|Recipient|primary:fixture|offsite:fixture') 'Queue projection excludes execution configuration'
    $probe = Invoke-BackupCenterApi $context POST '/api/proxmox/test'
    Assert-Web ($probe.StatusCode -eq 409) 'No probe without credentials'
    $saved = Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' @{ TokenId = 'invalid'; TokenSecret = 'TEST-ONLY' }
    Assert-Web ($saved.StatusCode -eq 400 -and -not [IO.File]::Exists($context.SecretPath)) 'Invalid credentials do not persist'
    $saved = Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' @{ Other = 'invalid'; TokenSecret = 'TEST-ONLY' }
    Assert-Web ($saved.StatusCode -eq 400) 'Unknown credential fields rejected'
    $fixture = @{ TokenId = 'backup@pve!test'; TokenSecret = 'TEST-ONLY-API-TOKEN' }
    $saved = Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' $fixture
    Assert-Web ($saved.StatusCode -eq 200 -and $context.CredentialsConfigured -and $fixture.Count -eq 0) 'Credentials saved and request data cleared'
    $disk = [IO.File]::ReadAllText($context.SecretPath)
    Assert-Web ($disk -match 'dpapi:v1:' -and $disk -notmatch 'TEST-ONLY|backup@pve') 'Only DPAPI ciphertext on disk'
    Assert-Web ((Get-Acl -LiteralPath $context.SecretPath).AreAccessRulesProtected) 'Secrets have protected Windows ACL'
    & $module {
        $script:TestMode = 'Good'
        function script:Get-ProxmoxVMStatus {
            param($ApiUri, $Node, $VMId, $TokenId, $TokenSecret)
            if ($VMId -ne 9001 -or $Node -ne 'pve' -or $TokenId -ne 'backup@pve!test' -or
                $TokenSecret -isnot [Security.SecureString]) { throw 'Unexpected request' }
            if ($script:TestMode -eq 'Error') { throw 'TEST-ONLY-API-TOKEN vendor diagnostic' }
            $name = if ($script:TestMode -eq 'WrongVM') { 'other-vm' } else { 'srv-app-01' }
            [pscustomobject]@{ Name = $name; VMId = $VMId; Node = $Node; Status = 'running'; CpuUsage = 0.25;
                MemoryBytes = 1024L; MaxMemoryBytes = 2048L; UptimeSeconds = 60L; CheckedUtc = [DateTimeOffset]::UtcNow.ToString('o') }
        }
    }
    $probe = Invoke-BackupCenterApi $context POST '/api/proxmox/test'
    Assert-Web ($probe.StatusCode -eq 200 -and $probe.Body.State -eq 'Connected' -and $probe.Body.VM.VMId -eq 9001) 'Probe uses fixed target and DPAPI token'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/test').StatusCode -eq 429) 'Probe cooldown enforced'
    foreach ($mode in @('Error', 'WrongVM')) {
        & $module { param($mode) $script:TestMode = $mode } $mode
        $context.LastProbeStarted = [DateTimeOffset]::MinValue
        $probe = Invoke-BackupCenterApi $context POST '/api/proxmox/test'
        Assert-Web ($probe.StatusCode -eq 502 -and $null -eq $context.Probe.VM) ('No stale success after ' + $mode)
        Assert-Web (($probe | ConvertTo-Json -Depth 8) -notmatch 'TEST-ONLY|vendor diagnostic') 'No raw diagnostics exposed'
    }
    $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
    Assert-Web (($dashboard | ConvertTo-Json -Depth 8) -notmatch 'TEST-ONLY|backup@pve|dpapi:v1:') 'Dashboard does not disclose credentials'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/backup/start').StatusCode -eq 404) 'No remote execution route'
    $audit = (Get-ChildItem -LiteralPath $context.LogDirectory -File | Get-Content) -join "`n"
    Assert-Web ($audit -notmatch 'TEST-ONLY|vendor diagnostic|backup@pve') 'Logs contain no credentials or native errors'
    $reloaded = New-BackupCenterWebContext -ProjectRoot $root -TargetPath (Join-Path $project 'Config\proxmox.example.json')
    Assert-Web ($reloaded.CredentialsConfigured -and $reloaded.Probe.State -eq 'NotChecked') 'DPAPI configuration survives server restart'
    & $module {
        $script:LaunchCount = 0
        function script:Start-BackupCenterBackupWorker { param($Context, $Record); $script:LaunchCount++ }
        function script:Get-ProxmoxBackupStorage {
            param($ApiUri, $TokenId, $TokenSecret, $Node)
            [pscustomobject]@{ Name = 'local'; AvailableBytes = 123456789L }
        }
    }
    $storages = Invoke-BackupCenterApi $context POST '/api/proxmox/storages' @{}
    Assert-Web ($storages.StatusCode -eq 200 -and $storages.Body.Storages[0].Name -ceq 'local') 'Storage choices available'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' @{}).StatusCode -eq 400) 'Explicit backup confirmation required'
    $start = @{ Storage = 'local'; Confirmation = 'SNAPSHOT 9001'; RequestId = [guid]::NewGuid().ToString(); PreviousId = '' }
    $accepted = Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' $start
    Assert-Web ($accepted.StatusCode -eq 202) 'Backup submitted asynchronously'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' $start).StatusCode -eq 202) 'Duplicate request idempotent'
    Assert-Web ((& $module { $script:LaunchCount }) -eq 1) 'Worker launched once'
    $other = $start.Clone(); $other.RequestId = [guid]::NewGuid().ToString()
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' $other).StatusCode -eq 409) 'Concurrent test rejected'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' @{}).StatusCode -eq 409) 'No credential change during export'
    foreach ($status in @('Running', 'Success', 'Unknown')) {
        & $module {
            param($context, $status)
            $record = Read-BackupCenterTestRecord $context
            $record.Status = $status; $record.PollCount = 3
            Save-BackupCenterTestRecord $context $record
        } $context $status
        $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
        Assert-Web ($dashboard.StatusCode -eq 200 -and $dashboard.Body.Jobs[0].Steps[0].Status -ceq $status) ('Export state visible: ' + $status)
        Assert-Web ($dashboard.Body.Jobs[0].Kind -ceq 'ProxmoxBackupTest' -and $dashboard.Body.BackupTest.PollCount -eq 3) 'Remote-only job distinguished from pipeline'
    }
    $other.PreviousId = $start.RequestId
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' $other).StatusCode -eq 409) 'Unknown remote state blocks relaunch'
    $reloaded = New-BackupCenterWebContext -ProjectRoot $root -TargetPath (Join-Path $project 'Config\proxmox.example.json')
    Assert-Web ((Invoke-BackupCenterApi $reloaded POST '/api/proxmox/backup-test' $other).StatusCode -eq 409) 'Restart cannot duplicate uncertain task'
    $continuation = @{ BackupId = $start.RequestId; RequestId = [guid]::NewGuid().ToString(); Confirmation = 'TRANSFER 9001' }
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' @{}).StatusCode -eq 400) 'Transfer confirmation mandatory'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $continuation).StatusCode -eq 409) 'No transfer of uncertain export'
    & $module {
        param($context)
        $record = Read-BackupCenterTestRecord $context; $record.Status = 'Success'
        $record.TaskId = 'UPID:pve:0001:0002:0003:vzdump:9001:backup@pve!test:'
        Save-BackupCenterTestRecord $context $record
    } $context
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $continuation).Body.ErrorCode -eq 'TransferConfigurationRequired') 'Explicit transport configuration required'
    $settings = @{ SftpUser = 'backup'; SftpPort = 22; KnownHostsFile = 'TEST'; PrivateKeyFile = 'TEST'; RclonePath = 'rclone.test'; UploadDestination = 'cloud:TEST-DESTINATION' }
    [IO.File]::WriteAllText($context.TransferSettingsPath, ($settings | ConvertTo-Json))
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $continuation).StatusCode -eq 202) 'Continuation admitted'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $continuation).StatusCode -eq 202) 'Continuation duplicate idempotent'
    Assert-Web ((& $module { $script:LaunchCount }) -eq 2) 'Only one continuation worker launched'
    $duplicate = $continuation.Clone(); $duplicate.RequestId = [guid]::NewGuid().ToString()
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/transfer' $duplicate).StatusCode -eq 409) 'New request cannot duplicate same transfer'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' $other).StatusCode -eq 409) 'Transfer blocks new vzdump'
    Assert-Web ((Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' @{}).StatusCode -eq 409) 'Transfer blocks token changes'
    $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
    Assert-Web ($dashboard.Body.Transfer.Status -eq 'Pending' -and $dashboard.Body.Jobs[0].Kind -eq 'ProxmoxTransfer') 'Continuation projected'
    Assert-Web (($dashboard.Body | ConvertTo-Json -Depth 8) -notmatch 'TEST-DESTINATION|PrivateKeyFile|SecretName') 'Transport settings remain server-side'
    $reloaded = New-BackupCenterWebContext -ProjectRoot $root -TargetPath (Join-Path $project 'Config\proxmox.example.json')
    Assert-Web ((Invoke-BackupCenterApi $reloaded POST '/api/proxmox/transfer' $duplicate).StatusCode -eq 409) 'Restart cannot duplicate transfer'
    Write-Output ('PASS: {0} WebBackend assertions (isolated DPAPI, simulated Proxmox).' -f $script:Assertions)
}
finally {
    Remove-Module WebBackend -Force -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($root)) { Remove-Item -LiteralPath $root -Recurse -Force }
}
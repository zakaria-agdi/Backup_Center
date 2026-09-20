#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = Split-Path $PSScriptRoot -Parent
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupWorker-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory((Join-Path $root 'Modules'))
$context = $null; $module = $null; $ready = $null; $release = $null
$checks = 0
function Assert-Worker { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message }; $script:checks++ }
try {
    foreach ($file in @('WebBackend.psm1', 'Security.psd1', 'Security.psm1', 'BackupEngine.psd1', 'BackupEngine.psm1')) {
        Copy-Item -LiteralPath (Join-Path $project ('Modules\' + $file)) -Destination (Join-Path $root 'Modules')
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Fixtures\BackupTestHypervisors.psm1') -Destination (Join-Path $root 'Modules\Hypervisors.psm1')
    New-ModuleManifest -Path (Join-Path $root 'Modules\Hypervisors.psd1') -RootModule 'Hypervisors.psm1' -FunctionsToExport 'Invoke-ProxmoxBackupTest'
    $module = Import-Module (Join-Path $root 'Modules\WebBackend.psm1') -Force -PassThru
    $context = New-BackupCenterWebContext -ProjectRoot $root -TargetPath (Join-Path $project 'Config\proxmox.example.json')
    $context.Target.ApiUri = 'https://example.invalid:8006/'
    $context.EngineLockPath = Join-Path $root ([guid]::NewGuid().ToString('N'))
    $eventName = [IO.Path]::GetFileName($context.EngineLockPath)
    $ready = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, ($eventName + '-ready'))
    $release = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, ($eventName + '-release'))
    $saved = Invoke-BackupCenterApi $context POST '/api/proxmox/credentials' @{ TokenId = 'backup@pve!fixture'; TokenSecret = 'TEST-ONLY-SECRET' }
    Assert-Worker ($saved.StatusCode -eq 200) 'Fixture credential persisted with real DPAPI'
    foreach ($storage in @('local', 'failure')) {
        $null = $ready.Reset(); $null = $release.Reset()
        $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
        $previous = if ($null -eq $dashboard.Body.BackupTest) { '' } else { $dashboard.Body.BackupTest.Id }
        $request = @{ Storage = $storage; Confirmation = 'SNAPSHOT 9001'; RequestId = [guid]::NewGuid().ToString(); PreviousId = $previous }
        $accepted = Invoke-BackupCenterApi $context POST '/api/proxmox/backup-test' $request
        Assert-Worker ($accepted.StatusCode -eq 202) 'Real Start-Job accepts work'
        Assert-Worker ($ready.WaitOne(15000)) 'Child process reports Running before release'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
        Assert-Worker ($dashboard.StatusCode -eq 200 -and $dashboard.Body.BackupTest.Status -ceq 'Running' -and $clock.Elapsed.TotalSeconds -lt 2) 'Dashboard responsive while child waits'
        $null = $release.Set()
        $finished = Wait-Job -Job $context.BackupWorker -Timeout 15
        Assert-Worker ($null -ne $finished -and $finished.State -eq 'Completed') 'Worker exits cleanly'
        $dashboard = Invoke-BackupCenterApi $context GET '/api/dashboard'
        $expected = if ($storage -ceq 'local') { 'Success' } else { 'Unknown' }
        Assert-Worker ($dashboard.Body.BackupTest.Status -ceq $expected) ('Durable state: ' + $expected)
        $output = Receive-Job -Job $context.BackupWorker -ErrorAction Stop
        Assert-Worker ($null -eq $output) 'No credential or raw exception on child output'
    }
    $serialized = [IO.File]::ReadAllText($context.BackupTestPath)
    Assert-Worker ($serialized -notmatch 'TEST-ONLY|private failure|TokenSecret') 'Persisted result sanitized'
    Write-Host ('PASS: ' + $checks + ' background worker assertions; real child process, isolated DPAPI, simulated Proxmox.')
}
finally {
    if ($null -ne $release) { $null = $release.Set() }
    if ($null -ne $context -and $null -ne $context.BackupWorker) { Remove-Job -Job $context.BackupWorker -Force -ErrorAction SilentlyContinue }
    if ($null -ne $module) { Remove-Module $module -Force -ErrorAction SilentlyContinue }
    if ($null -ne $ready) { $ready.Dispose() }
    if ($null -ne $release) { $release.Dispose() }
    Remove-Item -LiteralPath $root -Recurse -Force
}
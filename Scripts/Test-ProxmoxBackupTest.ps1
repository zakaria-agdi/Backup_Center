#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupTest-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$token = ConvertTo-SecureString 'TEST-ONLY-TOKEN' -AsPlainText -Force
$checks = 0
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message }; $script:checks++ }
try {
    $module = Import-Module (Join-Path $PSScriptRoot '..\Modules\Hypervisors.psd1') -Force -PassThru
    $state = @{ Mode = 'Good'; Posts = 0; Gets = 0; Progress = [Collections.Generic.List[string]]::new() }
    & $module {
        param($state)
        $script:Fixture = $state
        function script:Wait-HypervisorPoll { param($Milliseconds) }
        function script:Invoke-ProxmoxRequest {
            param($ApiUri, $TokenId, $TokenSecret, $Path, $Method = 'GET', $Body, $TimeoutSeconds)
            if ($Path -like '*/status/current') {
                $name = if ($script:Fixture.Mode -eq 'WrongVM') { 'other' } else { 'srv-app-01' }
                return [pscustomobject]@{ name = $name; status = 'running'; cpu = 0.1; mem = 10L; maxmem = 100L; uptime = 1 }
            }
            if ($Path -like '*/storage?content=backup') {
                return [pscustomobject]@{ storage = 'local'; type = 'dir'; active = 1; enabled = 1; content = 'images,backup'; avail = 100000L }
            }
            if ($Path -like '*/vzdump') {
                $script:Fixture.Posts++
                if ($Method -cne 'POST' -or $Body.vmid -ne 9001 -or $Body.storage -cne 'local' -or $Body.mode -cne 'snapshot' -or
                    $Body.remove -ne 0 -or $Body.'prune-backups' -cne 'keep-all=1') { throw 'Unsafe body' }
                if ($script:Fixture.Mode -eq 'LostResponse') { throw 'TEST-ONLY-TOKEN' }
                $owner = if ($script:Fixture.Mode -eq 'WrongOwner') { 'other@pve!other' } else { $TokenId }
                return ('UPID:pve:0001:0002:0003:vzdump:9001:' + $owner + ':')
            }
            if ($Path -like '*/tasks/*/status') {
                $script:Fixture.Gets++
                if ($script:Fixture.Mode -eq 'BadStatus') { return [pscustomobject]@{ status = 'stopped' } }
                if ($script:Fixture.Gets -lt 3 -or $script:Fixture.Mode -eq 'StillRunning') { return [pscustomobject]@{ status = 'running' } }
                $exit = if ($script:Fixture.Mode -eq 'TaskFailed') { 'ERROR private details' } else { 'OK' }
                return [pscustomobject]@{ status = 'stopped'; exitstatus = $exit }
            }
            if ($Path -like '*/log?*') {
                $archive = '/var/lib/vz/dump/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst'
                if ($script:Fixture.Mode -eq 'Traversal') { $archive = '/var/lib/../dump/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst' }
                if ($script:Fixture.Mode -eq 'Ambiguous') { [pscustomobject]@{ t = "creating archive '/other/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst'" } }
                return [pscustomobject]@{ t = "creating archive '$archive'" }
            }
            if ($Path -like '*/content?*') { return [pscustomobject]@{ volid = 'local:backup/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst'; vmid = 9001; size = 100L } }
            throw 'Unexpected endpoint'
        }
    } $state
    $parameters = @{ ApiUri = 'https://example.invalid:8006/'; TokenId = 'backup@pve!worker'; TokenSecret = $token
        Node = 'pve'; VMId = 9001; ExpectedName = 'srv-app-01'; Storage = 'local'; EngineLockPath = (Join-Path $root 'engine.lock')
        OnProgress = { param($progress); $state.Progress.Add($progress.Status) } }
    foreach ($mode in @('Good', 'WrongVM', 'WrongOwner', 'LostResponse', 'BadStatus', 'TaskFailed')) {
        $state.Mode = $mode; $state.Posts = 0; $state.Gets = 0; $state.Progress.Clear()
        $result = Invoke-ProxmoxBackupTest @parameters
        $expected = switch ($mode) { 'Good' { 'Success' }; 'WrongVM' { 'Failed' }; 'TaskFailed' { 'Failed' }; default { 'Unknown' } }
        Assert-True ($result.Status -ceq $expected) ('Correct state: ' + $mode)
        Assert-True ($state.Posts -eq $(if ($mode -eq 'WrongVM') { 0 } else { 1 })) 'Never duplicate POST'
        Assert-True (($result | ConvertTo-Json -Depth 4) -notmatch 'TEST-ONLY|private details') 'Sanitized result'
        if ($mode -eq 'Good') {
            Assert-True ($state.Gets -eq 3 -and $result.PollCount -eq 3) 'Repeated task polling'
            Assert-True ($state.Progress.Contains('Running') -and $state.Progress[0] -eq 'Submitting' -and $state.Progress[-1] -eq 'Success') 'Visible progress'
        }
    }
    $state.Posts = 0
    $parameters.Storage = 'missing'
    $result = Invoke-ProxmoxBackupTest @parameters
    Assert-True ($result.Status -eq 'Failed' -and $state.Posts -eq 0) 'Reject unavailable storage before POST'
    $parameters.Storage = 'local'
    $held = [IO.File]::Open($parameters.EngineLockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    try { $result = Invoke-ProxmoxBackupTest @parameters }
    finally { $held.Dispose() }
    Assert-True ($result.Status -eq 'Failed' -and $state.Posts -eq 0) 'Shared engine lock enforced'
    $artifactParameters = $parameters.Clone()
    $artifactParameters.Remove('EngineLockPath'); $artifactParameters.Remove('OnProgress')
    $artifactParameters.TaskId = 'UPID:pve:0001:0002:0003:vzdump:9001:backup@pve!worker:'
    $state.Mode = 'Good'; $state.Gets = 3
    $artifact = Get-ProxmoxBackupArtifact @artifactParameters
    Assert-True ($artifact.Size -eq 100 -and $artifact.RemotePath -eq '/var/lib/vz/dump/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst') 'Exact archive from successful UPID'
    foreach ($mode in @('WrongVM', 'StillRunning', 'TaskFailed', 'Ambiguous', 'Traversal')) {
        $state.Mode = $mode; $state.Gets = 3; $failed = $false
        try { $null = Get-ProxmoxBackupArtifact @artifactParameters } catch { $failed = $true }
        Assert-True $failed ('Reject unsafe artifact: ' + $mode)
    }
    $artifactParameters.TokenId = 'different@pve!token'; $failed = $false
    try { $null = Get-ProxmoxBackupArtifact @artifactParameters } catch { $failed = $_.Exception.Data['HypervisorCode'] -eq 'TaskTokenMismatch' }
    Assert-True $failed 'Do not reconstruct UPID with another token'
    Assert-True ($state.Posts -eq 0) 'Archive resolution never launches vzdump'
    Write-Host ('PASS: ' + $checks + ' Proxmox backup test assertions; simulated API only.')
}
finally { $token.Dispose(); Remove-Item -LiteralPath $root -Recurse -Force }
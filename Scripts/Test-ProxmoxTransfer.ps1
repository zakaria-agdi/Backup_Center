#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '..\Modules\BackupEngine.psd1') -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('BackupTransfer-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$checks = 0
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message }; $script:checks++ }
try {
    $sshFile = Join-Path $root 'fake-ssh-file'; [IO.File]::WriteAllText($sshFile, 'TEST ONLY')
    $fixture = @{ Mode = 'Good'; Calls = [Collections.Generic.List[string]]::new(); Progress = [Collections.Generic.List[string]]::new(); Remote = $null }
    $settings = [pscustomobject]@{ SftpUser = 'backup'; SftpPort = 22; KnownHostsFile = $sshFile; PrivateKeyFile = $sshFile; RclonePath = 'rclone.test'; UploadDestination = 'cloud:backups' }
    $runner = {
        param($Executable, $Arguments, $OnProgress)
        $fixture.Calls.Add($Arguments[0])
        if ($Arguments[0] -eq 'copyto') {
            if ($Arguments -notcontains '--sftp-known-hosts-file' -or $Arguments -notcontains '--sftp-key-file' -or $Arguments -contains '--sftp-pass') { throw 'Unsafe SSH parameters' }
            foreach ($option in @(@('--sftp-host', 'example.invalid'), @('--sftp-port', '22'), @('--sftp-user', 'backup'),
                @('--sftp-known-hosts-file', $sshFile), @('--sftp-key-file', $sshFile), @('--sftp-shell-type', 'none'))) {
                $index = [Array]::IndexOf($Arguments, $option[0]); if ($index -lt 0 -or $Arguments[$index + 1] -cne $option[1]) { throw 'Invalid Pull option' }
            }
            if ($Arguments -notcontains '--inplace' -or $Arguments[-3] -cne '--' -or
                $Arguments[-2] -cne ':sftp:/var/lib/vz/dump/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst' -or
                -not $Arguments[-1].EndsWith('.vma.zst.partial')) { throw 'Invalid Pull paths' }
            if ($fixture.Mode -eq 'SSHFailure') { return [pscustomobject]@{ ExitCode = 1; Stdout = '' } }
            $payload = if ($fixture.Mode -eq 'ShortPull') { 'bad' } else { 'test-only-payload' }
            [IO.File]::WriteAllText($Arguments[-1], $payload)
            if ($fixture.Mode -eq 'InterruptedPull') { return [pscustomobject]@{ ExitCode = 1; Stdout = 'PRIVATE-ERROR' } }
            & $OnProgress 17 17 8.0
        }
        elseif ($Arguments[0] -eq 'copy') {
            foreach ($option in @(@('--transfers','8'), @('--checkers','8'), @('--drive-chunk-size','256M'), @('--buffer-size','128M'))) {
                $index = [Array]::IndexOf($Arguments, $option[0]); if ($index -lt 0 -or $Arguments[$index + 1] -cne $option[1]) { throw 'Missing upload option' }
            }
            if ($fixture.Mode -eq 'UploadFailure') { return [pscustomobject]@{ ExitCode = 1; Stdout = '' } }
            $fixture.Remote = [pscustomobject]@{ Name = [IO.Path]::GetFileName($Arguments[-2]); Size = [IO.FileInfo]::new($Arguments[-2]).Length; IsDir = $false; Hashes = @{} }
            & $OnProgress 100 100 50.0
        }
        elseif ($Arguments[0] -eq 'lsjson') {
            if ($fixture.Mode -eq 'VerifyFailure') { $fixture.Remote.Size++ }
            return [pscustomobject]@{ ExitCode = 0; Stdout = ($fixture.Remote | ConvertTo-Json -Compress) }
        }
        else { throw 'Unexpected command' }
        return [pscustomobject]@{ ExitCode = 0; Stdout = '' }
    }.GetNewClosure()
    $options = @{ SftpHost = 'example.invalid'; Settings = $settings; WorkDirectory = (Join-Path $root 'Temp')
        ConfigPath = (Join-Path $root 'secrets.json'); LogDirectory = (Join-Path $root 'Logs'); EngineLockPath = (Join-Path $root 'engine.lock')
        CommandRunner = $runner; OnProgress = { param($state); $fixture.Progress.Add(($state.Steps.Status -join ',')) }
        ResolveArchive = { [pscustomobject]@{ FileName = 'vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst'; RemotePath = '/var/lib/vz/dump/vzdump-qemu-9001-2026_09_07-12_00_00.vma.zst'; Size = 17L } } }
    foreach ($mode in @('Good', 'SSHFailure', 'ShortPull', 'InterruptedPull', 'UploadFailure', 'VerifyFailure')) {
        $fixture.Mode = $mode; $fixture.Calls.Clear(); $fixture.Progress.Clear()
        $result = Invoke-ProxmoxTransferPipeline @options
        Assert-True ($result.Status -eq $(if ($mode -eq 'Good') { 'Success' } else { 'Failed' })) ('Expected outcome ' + $mode + '; code=' + $result.ErrorCode + '; calls=' + ($fixture.Calls -join ','))
        Assert-True (@(Get-ChildItem $options.WorkDirectory -Recurse -File | Where-Object { $_.Extension -in @('.zst', '.partial') }).Count -eq 0) 'Clean plaintext and partial pulls'
        if ($mode -eq 'Good') {
            Assert-True (($fixture.Calls -join ',') -ceq 'copyto,copy,lsjson') 'Pull then encrypted upload then verification'
            Assert-True (($result.Steps.Status -join ',') -ceq 'Success,Success,Success,Skipped,Skipped,Skipped') 'Only requested stages succeed'
            Assert-True ($fixture.Progress.Contains('Success,Running,Skipped,Skipped,Skipped,Skipped')) 'Encryption progress visible'
            $restored = Join-Path $root 'restored.zst'
            Unprotect-BackupArchive -SourcePath $result.Artifact.Path -OutputPath $restored -ConfigPath $options.ConfigPath -LogDirectory $options.LogDirectory
            Assert-True ([IO.File]::ReadAllText($restored) -ceq 'test-only-payload') 'Uploaded artifact is recoverable'
        }
        if ($mode -in @('SSHFailure', 'ShortPull', 'InterruptedPull')) {
            Assert-True ($fixture.Calls.Count -eq 1 -and $null -eq $result.Artifact) 'No encryption or upload after Pull failure'
            Assert-True (($result.Steps.Status -join ',') -ceq 'Failed,Skipped,Skipped,Skipped,Skipped,Skipped') 'Only Pull fails'
            Assert-True (($result | ConvertTo-Json -Depth 6) -notmatch 'PRIVATE-ERROR') 'Raw transfer errors not exposed'
        }
    }
    $settings.KnownHostsFile = Join-Path $root 'missing'; $fixture.Calls.Clear()
    $result = Invoke-ProxmoxTransferPipeline @options
    Assert-True ($result.Status -eq 'Failed' -and $fixture.Calls.Count -eq 0) 'Pinned host file mandatory before transfer'
    Write-Host ('PASS: ' + $checks + ' transfer assertions; simulated rclone, real encryption.')
}
finally { Remove-Item -LiteralPath $root -Recurse -Force }
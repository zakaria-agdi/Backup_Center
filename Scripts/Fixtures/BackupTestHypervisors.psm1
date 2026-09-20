#requires -Version 5.1
function Invoke-ProxmoxBackupTest {
    param($ApiUri, $TokenId, $TokenSecret, $Node, $VMId, $ExpectedName, $Storage, $EngineLockPath, $OnProgress)
    if ($ApiUri.Host -cne 'example.invalid' -or $TokenId -cne 'backup@pve!fixture' -or
        $TokenSecret -isnot [Security.SecureString]) { throw 'Invalid isolated fixture' }
    $result = [pscustomobject]@{ Status = 'Running'; TaskId = 'UPID:pve:0001:0002:0003:vzdump:9001:fixture@pve:'; ErrorCode = $null; PollCount = 1 }
    $null = & $OnProgress $result
    $ready = [Threading.EventWaitHandle]::OpenExisting(([IO.Path]::GetFileName($EngineLockPath) + '-ready'))
    $release = [Threading.EventWaitHandle]::OpenExisting(([IO.Path]::GetFileName($EngineLockPath) + '-release'))
    try {
        $null = $ready.Set()
        if (-not $release.WaitOne(15000)) { throw 'Fixture timeout' }
        if ($Storage -ceq 'failure') { throw 'TEST-ONLY-SECRET private failure' }
        $result.Status = 'Success'; $result.PollCount = 3
        $null = & $OnProgress $result
    }
    finally { $ready.Dispose(); $release.Dispose() }
}
Export-ModuleMember -Function Invoke-ProxmoxBackupTest
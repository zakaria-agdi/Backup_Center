#requires -Version 5.1
function Get-ProxmoxBackupArtifact {
    param($ApiUri, $TokenId, $TokenSecret, $Node, $VMId, $ExpectedName, $Storage, $TaskId)
    if ($ApiUri.Host -cne '127.0.0.1' -or $TokenId -cne 'backup@pve!pullfixture' -or
        $TokenSecret -isnot [Security.SecureString] -or $Node -cne 'pve' -or $VMId -ne 9001 -or
        $Storage -cne 'local' -or $TaskId -cne ('UPID:pve:0001:0002:0003:vzdump:9001:' + $TokenId + ':')) {
        $failure = [InvalidOperationException]::new('Invalid isolated transfer fixture')
        $failure.Data['HypervisorCode'] = 'FixtureMismatch'
        throw $failure
    }
    [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\artifact.json')) | ConvertFrom-Json
}
function Invoke-ProxmoxBackupTest { throw 'A Pull must never launch vzdump' }
Export-ModuleMember -Function Get-ProxmoxBackupArtifact, Invoke-ProxmoxBackupTest
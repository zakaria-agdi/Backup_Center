#requires -Version 5.1
[CmdletBinding()]
param([string]$Value, [int]$ExitCode = 0, [switch]$Block)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$signal = $null
try {
    if ($Block) {
        $signal = [Threading.ManualResetEvent]::new($false)
        $null = $signal.WaitOne()
    }
    [Console]::Error.WriteLine('TEST-ONLY diagnostic on stderr')
    [pscustomobject]@{ Value = $Value } | ConvertTo-Json -Compress
    exit $ExitCode
}
catch { exit 99 }
finally { if ($null -ne $signal) { $signal.Dispose() } }
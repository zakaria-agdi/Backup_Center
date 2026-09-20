#requires -Version 7.0
param([string]$BaseUri = 'http://127.0.0.1:8080')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Assertions = 0
function Assert-Http {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw ('Assertion failed: ' + $Label) }
    $script:Assertions++
}
$headers = @{ 'X-BackupCenter-Client' = 'dashboard' }
$homepage = Invoke-WebRequest -Uri ($BaseUri + '/') -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($homepage.StatusCode -eq 200 -and $homepage.Content -match 'Backup Center') 'Front served'
Assert-Http ($homepage.Headers['Cache-Control'] -contains 'no-store' -and
    $homepage.Headers['X-Frame-Options'] -contains 'DENY' -and $homepage.Headers.ContainsKey('Content-Security-Policy')) 'Security headers present'
$session = Invoke-RestMethod -Uri ($BaseUri + '/api/session') -Headers $headers -TimeoutSec 10
Assert-Http ($session.Nonce.Length -ge 40) 'Session nonce returned to custom-header request'
$dashboard = Invoke-RestMethod -Uri ($BaseUri + '/api/dashboard') -Headers $headers -TimeoutSec 10
Assert-Http ($dashboard.Mode -eq 'LocalBackupTest' -and $dashboard.Target.VMId -eq 9001) 'Fixed backup-test target configured'
Assert-Http (($dashboard | ConvertTo-Json -Depth 10) -notmatch 'dpapi:v1:|TokenSecret|TokenId') 'No credential projection'
foreach ($path in @('/Config/secrets.json', '/Logs/security.log', '/Modules/Security.psm1', '/Scripts/Start-BackupCenter.ps1', '/api/execute')) {
    $response = Invoke-WebRequest -Uri ($BaseUri + $path) -Headers $headers -TimeoutSec 10 -SkipHttpErrorCheck
    Assert-Http ($response.StatusCode -eq 404) ('Private or absent route blocked: ' + $path)
}
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/dashboard') -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($response.StatusCode -eq 403) 'Missing client header rejected'
$response = Invoke-WebRequest -Uri ($BaseUri + '/API/dashboard') -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($response.StatusCode -eq 403) 'Mixed-case API route requires client header'
$foreign = @{ 'X-BackupCenter-Client' = 'dashboard'; Origin = 'https://evil.invalid' }
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/dashboard') -Headers $foreign -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($response.StatusCode -eq 403) 'Foreign origin rejected'
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/dashboard') -Headers @{ Host = 'evil.invalid' } -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($response.StatusCode -eq 403) 'DNS rebinding host rejected'
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/proxmox/test') -Method Post -Headers $headers -ContentType 'application/json' -Body '{}' -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($response.StatusCode -eq 403) 'CSRF-less POST rejected before Proxmox access'
foreach ($path in @('/api/proxmox/backup-test', '/API/proxmox/backup-test', '/api/proxmox/storages')) {
    $response = Invoke-WebRequest -Uri ($BaseUri + $path) -Method Post -Headers $headers -ContentType 'application/json' -Body '{}' -TimeoutSec 10 -SkipHttpErrorCheck
    Assert-Http ($response.StatusCode -eq 403) ('New POST route requires CSRF: ' + $path)
}
$headers.Origin = $BaseUri
$headers['X-BackupCenter-CSRF'] = $session.Nonce
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/proxmox/backup-test') -Method Post -Headers $headers -ContentType 'application/json' -Body '{}' -TimeoutSec 10 -SkipHttpErrorCheck
$expected = if ($dashboard.CredentialsConfigured) { 400 } else { 409 }
Assert-Http ($response.StatusCode -eq $expected) 'No backup without explicit target confirmation and storage'
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/proxmox/credentials') -Method Post -Headers $headers -ContentType 'application/json' -Body '{"TokenId":"invalid","TokenSecret":""}' -TimeoutSec 10 -SkipHttpErrorCheck
$expected = if ($null -ne $dashboard.BackupTest -and $dashboard.BackupTest.Status -notin @('Success', 'Failed')) { 409 } else { 400 }
Assert-Http ($response.StatusCode -eq $expected) 'Invalid credentials rejected without persistence'
$response = Invoke-WebRequest -Uri ($BaseUri + '/api/proxmox/credentials') -Method Post -Headers $headers -ContentType 'application/json' -Body ('x' * 17000) -TimeoutSec 10 -SkipHttpErrorCheck
Assert-Http ($response.StatusCode -eq 413) 'HTTP parser enforces body limit'
Write-Output ('PASS: {0} HTTP assertions; no live Proxmox calls or credentials.' -f $script:Assertions)
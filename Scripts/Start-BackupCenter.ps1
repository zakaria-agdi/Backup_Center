#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1024, 65515)][int]$Port = 8080,
    [string]$TargetPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Config\proxmox.example.json')
)
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
Import-Module Pode -RequiredVersion 2.14.1 -ErrorAction Stop
Import-Module (Join-Path $project 'Modules\WebBackend.psm1') -ErrorAction Stop
$selectedPort = $null
foreach ($candidate in $Port..($Port + 20)) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $candidate)
    try { $listener.Start(); $selectedPort = $candidate; break }
    catch [Net.Sockets.SocketException] { }
    finally { $listener.Stop() }
}
if ($null -eq $selectedPort) { throw 'No available loopback port.' }
$server = {
    $context = New-BackupCenterWebContext -ProjectRoot $project -TargetPath $TargetPath -Port $selectedPort
    Set-PodeState -Name 'BackupCenter' -Value $context -NoPassThru
    Add-PodeEndpoint -Address '127.0.0.1' -Port $selectedPort -Protocol Http
    Add-PodeMiddleware -Name 'LocalBoundary' -ScriptBlock {
        try {
        $context = Get-PodeState -Name 'BackupCenter'
        Set-PodeHeader -Name 'Cache-Control' -Value 'no-store'
        Set-PodeHeader -Name 'X-Content-Type-Options' -Value 'nosniff'
        Set-PodeHeader -Name 'X-Frame-Options' -Value 'DENY'
        Set-PodeHeader -Name 'Referrer-Policy' -Value 'no-referrer'
        Set-PodeHeader -Name 'Cross-Origin-Resource-Policy' -Value 'same-origin'
        Set-PodeHeader -Name 'Content-Security-Policy' -Value "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        $headers = $WebEvent.Request.Headers
        $policy = @{
            Context = $context; RemoteAddress = $WebEvent.Request.RemoteEndPoint.Address.ToString()
            HostHeader = [string]$headers['Host']; Origin = [string]$headers['Origin']
            FetchSite = [string]$headers['Sec-Fetch-Site']; Method = $WebEvent.Method.ToUpperInvariant(); Path = $WebEvent.Path
            ClientHeader = [string]$headers['X-BackupCenter-Client']; Nonce = [string]$headers['X-BackupCenter-CSRF']
            ContentType = [string]$headers['Content-Type']; ContentLength = $WebEvent.Request.ContentLength
        }
        $status = Test-BackupCenterWebRequest @policy
        if ($status -ne 200) {
            try { Write-BackupCenterWebAudit $context 'Request' 'Rejected' }
            catch { $status = 503 }
            Write-PodeJsonResponse -Value @{ ErrorCode = 'RequestRejected' } -StatusCode $status
            return $false
        }
        return $true
        }
        catch {
            Write-PodeJsonResponse -Value @{ ErrorCode = 'OperationUnavailable' } -StatusCode 503
            return $false
        }
    }
    $assets = @(
        @{ Route = '/'; File = 'index.html'; Type = 'text/html; charset=utf-8' },
        @{ Route = '/index.html'; File = 'index.html'; Type = 'text/html; charset=utf-8' },
        @{ Route = '/dashboard.js'; File = 'dashboard.js'; Type = 'application/javascript; charset=utf-8' },
        @{ Route = '/assets/tailwind.css'; File = 'assets\tailwind.css'; Type = 'text/css; charset=utf-8' },
        @{ Route = '/assets/lucide.min.js'; File = 'assets\lucide.min.js'; Type = 'application/javascript; charset=utf-8' }
    )
    foreach ($asset in $assets) {
        Add-PodeRoute -Method Get -Path $asset.Route -ArgumentList @((Join-Path (Join-Path $project 'WebUI') $asset.File), $asset.Type) -ScriptBlock {
            param($file, $contentType)
            Write-PodeFileResponse -Path $file -ContentType $contentType
        }
    }
    foreach ($route in @(
        @{ Method = 'Get'; Path = '/api/session' },
        @{ Method = 'Get'; Path = '/api/dashboard' },
        @{ Method = 'Post'; Path = '/api/proxmox/credentials' },
        @{ Method = 'Post'; Path = '/api/proxmox/test' },
        @{ Method = 'Post'; Path = '/api/proxmox/storages' },
        @{ Method = 'Post'; Path = '/api/proxmox/backup-test' }
        @{ Method = 'Post'; Path = '/api/proxmox/transfer' }
    )) {
        Add-PodeRoute -Method $route.Method -Path $route.Path -ArgumentList @($route.Method.ToUpperInvariant(), $route.Path) -ScriptBlock {
            param($method, $path)
            try {
                $context = Get-PodeState -Name 'BackupCenter'
                $result = Invoke-BackupCenterApi -Context $context -Method $method -Path $path -Data $WebEvent.Data
                Write-PodeJsonResponse -Value $result.Body -StatusCode $result.StatusCode -Depth 8
            }
            catch { Write-PodeJsonResponse -Value @{ ErrorCode = 'OperationUnavailable' } -StatusCode 503 }
            finally { if ($WebEvent.Data -is [Collections.IDictionary]) { $WebEvent.Data.Clear() } }
        }
    }
    Add-PodeRoute -Method Get, Post, Put, Delete, Patch, Options, Head -Path '/*' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ ErrorCode = 'NotFound' } -StatusCode 404
    }
    Write-Host ('Backup Center local: http://127.0.0.1:' + $selectedPort + '/')
}.GetNewClosure()
Start-PodeServer -ScriptBlock $server -Threads 1 -RootPath $project -ConfigFile (Join-Path $project 'Config\web-server.psd1') -DisableConsoleInput -Quiet
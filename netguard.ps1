<#
.SYNOPSIS
    NetGuard Audit for Windows PowerShell (Zero-Dependency)
.DESCRIPTION
    Audits Web HTTP Security Headers (A+ to F Grade), scans local repos for leaked secrets,
    and checks exposed critical TCP ports.
.EXAMPLE
    .\netguard.ps1 -Mode audit-web -Target "https://github.com"
    .\netguard.ps1 -Mode audit-repo -Target "."
    .\netguard.ps1 -Mode audit-ports -Target "127.0.0.1"
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("audit-web", "audit-repo", "audit-ports")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$Target
)

$ErrorActionPreference = "Stop"

function Get-Grade([int]$Score) {
    if ($Score -ge 95) { return "A+" }
    if ($Score -ge 85) { return "A" }
    if ($Score -ge 75) { return "B" }
    if ($Score -ge 60) { return "C" }
    if ($Score -ge 45) { return "D" }
    return "F"
}

if ($Mode -eq "audit-web") {
    $url = if ($Target -match "^https?://") { $Target } else { "https://$Target" }
    $resp = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 10
    $hdrs = @{}
    foreach ($k in $resp.Headers.Keys) { $hdrs[$k.ToLower()] = ($resp.Headers[$k] -join ", ") }

    $required = @(
        @{ Name = "strict-transport-security"; Weight = 20 },
        @{ Name = "content-security-policy"; Weight = 20 },
        @{ Name = "x-content-type-options"; Weight = 15 },
        @{ Name = "x-frame-options"; Weight = 15 },
        @{ Name = "referrer-policy"; Weight = 15 },
        @{ Name = "permissions-policy"; Weight = 15 }
    )

    $score = 0
    $checks = @()
    foreach ($r in $required) {
        if ($hdrs.ContainsKey($r.Name)) {
            $score += $r.Weight
            $checks += [ordered]@{ header = $r.Name; status = "PASS"; value = $hdrs[$r.Name] }
        } else {
            $checks += [ordered]@{ header = $r.Name; status = "MISSING"; value = $null }
        }
    }

    [ordered]@{
        mode        = "audit-web"
        target      = $url
        http_status = [int]$resp.StatusCode
        score       = $score
        grade       = (Get-Grade $score)
        checks      = $checks
    } | ConvertTo-Json -Depth 4
}
elseif ($Mode -eq "audit-repo") {
    $rules = @(
        @{ Name = "AWS Access Key"; Pattern = "\bAKIA[0-9A-Z]{16}\b"; Severity = "CRITICAL" },
        @{ Name = "GitHub PAT"; Pattern = "\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"; Severity = "CRITICAL" },
        @{ Name = "Private Key"; Pattern = "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"; Severity = "CRITICAL" },
        @{ Name = "DB Password URI"; Pattern = "(postgres|mysql|mongodb|redis)://[^:\s/]+:[^@\s/]+@"; Severity = "CRITICAL" }
    )
    $findings = @()
    $files = Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\(\.git|node_modules|venv)\\" -and $_.Length -lt 1500000 }

    foreach ($f in $files) {
        $lineNum = 0
        foreach ($line in (Get-Content -Path $f.FullName -ErrorAction SilentlyContinue)) {
            $lineNum++
            foreach ($r in $rules) {
                if ($line -match $r.Pattern) {
                    $findings += [ordered]@{
                        file     = $f.FullName
                        line     = $lineNum
                        rule     = $r.Name
                        severity = $r.Severity
                    }
                }
            }
        }
    }
    $score = [Math]::Max(0, 100 - ($findings.Count * 25))
    [ordered]@{
        mode          = "audit-repo"
        target        = (Resolve-Path $Target).Path
        files_scanned = $files.Count
        findings      = $findings
        score         = $score
        grade         = (Get-Grade $score)
    } | ConvertTo-Json -Depth 4
}
elseif ($Mode -eq "audit-ports") {
    $ports = @(22, 23, 80, 443, 445, 554, 3306, 3389, 5432, 6379)
    $open = @()
    foreach ($p in $ports) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $tcp.BeginConnect($Target, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(400, $false) -and $tcp.Connected) {
                $open += $p
            }
        } catch {} finally { $tcp.Close() }
    }
    [ordered]@{
        mode       = "audit-ports"
        target     = $Target
        open_ports = $open
    } | ConvertTo-Json -Depth 3
}

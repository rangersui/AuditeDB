param(
    [string]$Case = "help",
    [string]$Base = $env:ELASTIK_BASE,
    [string]$World = $env:ELASTIK_WORLD
)

if (-not $Base) { $Base = "http://127.0.0.1:3105" }
if (-not $World) { $World = "/home/elastik-skill-demo" }

$WriteToken = $env:ELASTIK_WRITE_TOKEN
$ApproveToken = $env:ELASTIK_APPROVE_TOKEN
$ReadToken = $env:ELASTIK_READ_TOKEN
if (-not $ReadToken) { $ReadToken = $WriteToken }
if (-not $ReadToken) { $ReadToken = $ApproveToken }

function Get-ReadAuthArgs {
    if ($ReadToken) { return @("-H", "Authorization: Bearer $ReadToken") }
    return @()
}

function Get-WriteAuthArgs {
    if (-not $WriteToken) {
        Write-Error "missing ELASTIK_WRITE_TOKEN"
        exit 2
    }
    return @("-H", "Authorization: Bearer $WriteToken")
}

function Write-Title {
    param([string]$Text)
    Write-Output ""
    Write-Output "## $Text"
}

function Invoke-Version {
    Write-Title "GET /proc/version"
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -i @auth "$Base/proc/version"
}

function Invoke-Worlds {
    Write-Title "GET /proc/worlds (plain text, not JSON)"
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -i @auth "$Base/proc/worlds"
}

function Invoke-Put {
    Write-Title "PUT world bytes"
    $auth = Get-WriteAuthArgs
    "hello from elastik skill`n" | & curl.exe -sS -i -X PUT @auth `
        -H "Content-Type: text/plain; charset=utf-8" `
        --data-binary "@-" `
        "$Base$World"
}

function Invoke-PutMetadata {
    Write-Title "PUT with representation metadata"
    Write-Output "Note: X-Meta-Summary persists only when ELASTIK_PERSIST_HEADERS includes x-meta-*."
    $auth = Get-WriteAuthArgs
    "<!doctype html><title>Elastik</title><p>Hello.</p>`n" | & curl.exe -sS -i -X PUT @auth `
        -H "Content-Type: text/html; charset=utf-8" `
        -H "Content-Language: en" `
        -H "Cache-Control: no-cache" `
        -H "X-Meta-Summary: Generic Elastik curl example page." `
        --data-binary "@-" `
        "$Base$World"
}

function Invoke-Head {
    Write-Title "HEAD world metadata"
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -i -I @auth "$Base$World"
}

function Invoke-Get {
    Write-Title "GET world body"
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -i @auth "$Base$World"
}

function Invoke-Range {
    Write-Title "Range GET"
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -i @auth -H "Range: bytes=0-15" "$Base$World"
}

function Invoke-Cas {
    Write-Title "CAS with ETag and If-Match"
    $auth = Get-ReadAuthArgs
    $head = & curl.exe -fsSI @auth "$Base$World"
    $etagLine = ($head | Select-String -Pattern '^etag:' | Select-Object -First 1).Line
    if (-not $etagLine) {
        Write-Error "no ETag from HEAD $World; PUT a durable world first"
        exit 1
    }
    $etag = $etagLine.Split(":", 2)[1].Trim()
    $writeAuth = Get-WriteAuthArgs
    "updated by CAS`n" | & curl.exe -sS -i -X PUT @writeAuth `
        -H "If-Match: $etag" `
        -H "Content-Type: text/plain; charset=utf-8" `
        --data-binary "@-" `
        "$Base$World"
}

function Invoke-AuditVerify {
    Write-Title "Verify audit chain"
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -i -I @auth "$Base/proc/audit$World/verify"
}

function Invoke-Listen {
    Write-Title "Listen for changes"
    Write-Output "This is a streaming request; stop it with Ctrl-C."
    $auth = Get-ReadAuthArgs
    & curl.exe -sS -N @auth "$Base/listen$World"
}

switch ($Case) {
    "version" { Invoke-Version }
    "worlds" { Invoke-Worlds }
    "put" { Invoke-Put }
    "put-metadata" { Invoke-PutMetadata }
    "head" { Invoke-Head }
    "get" { Invoke-Get }
    "range" { Invoke-Range }
    "cas" { Invoke-Cas }
    "audit-verify" { Invoke-AuditVerify }
    "listen" { Invoke-Listen }
    "all" {
        Invoke-Version
        Invoke-Worlds
        Invoke-Put
        Invoke-Head
        Invoke-Get
        Invoke-Range
        Invoke-Cas
        Invoke-AuditVerify
    }
    default {
@"
Elastik curl cases:
  .\scripts\curl-cases.ps1 version
  .\scripts\curl-cases.ps1 worlds
  .\scripts\curl-cases.ps1 put
  .\scripts\curl-cases.ps1 put-metadata
  .\scripts\curl-cases.ps1 head
  .\scripts\curl-cases.ps1 get
  .\scripts\curl-cases.ps1 range
  .\scripts\curl-cases.ps1 cas
  .\scripts\curl-cases.ps1 audit-verify
  .\scripts\curl-cases.ps1 listen
  .\scripts\curl-cases.ps1 all
"@
    }
}

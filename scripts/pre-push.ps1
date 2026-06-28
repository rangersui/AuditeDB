Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Step($Name, [scriptblock]$Body) {
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Body
}

function Run([string]$Exe, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Args) {
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe $($Args -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Parse("127.0.0.1"),
        0
    )
    $listener.Start()
    try {
        return [int]$listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Run-JsSdkAgainstCore {
    $root = (Get-Location).Path
    $isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )
    $suffix = if ($isWindowsHost) { ".exe" } else { "" }
    $coreExe = Join-Path $root "bin/target/debug/elastik-core$suffix"
    Run cargo build --manifest-path bin/Cargo.toml

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("elastik-hook-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $temp | Out-Null
    $out = Join-Path $temp "core.out.log"
    $err = Join-Path $temp "core.err.log"
    $port = Get-FreePort

    $oldEnv = @{}
    foreach ($name in @(
        "ELASTIK_DATA", "ELASTIK_KEY", "ELASTIK_READ_TOKEN",
        "ELASTIK_WRITE_TOKEN", "ELASTIK_APPROVE_TOKEN", "ELASTIK_HOST",
        "ELASTIK_PORT", "ELASTIK_NO_DOTENV", "ELASTIK_URL"
    )) {
        $oldEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }

    $p = $null
    try {
        $env:ELASTIK_DATA = $temp
        $env:ELASTIK_KEY = "0123456789abcdef0123456789abcdef"
        $env:ELASTIK_READ_TOKEN = "r"
        $env:ELASTIK_WRITE_TOKEN = "w"
        $env:ELASTIK_APPROVE_TOKEN = "a"
        $env:ELASTIK_HOST = "127.0.0.1"
        $env:ELASTIK_PORT = [string]$port
        $env:ELASTIK_NO_DOTENV = "1"
        $env:ELASTIK_URL = "http://127.0.0.1:$port"

        $p = Start-Process -FilePath $coreExe `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $out `
            -RedirectStandardError $err

        $ready = $false
        for ($i = 0; $i -lt 40; $i++) {
            try {
                $resp = Invoke-WebRequest `
                    -UseBasicParsing `
                    -Uri "http://127.0.0.1:$port/proc/version" `
                    -TimeoutSec 1
                if ($resp.StatusCode -eq 200) {
                    $ready = $true
                    break
                }
            } catch {
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $ready) {
            throw "core did not become ready on port $port"
        }

        Run node sdk-js/test.mjs
    } finally {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force
        }
        foreach ($entry in $oldEnv.GetEnumerator()) {
            if ($null -eq $entry.Value) {
                Remove-Item "Env:$($entry.Key)" -ErrorAction SilentlyContinue
            } else {
                [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
            }
        }
        Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
    }
}

$repoRoot = git rev-parse --show-toplevel
Set-Location $repoRoot
$strict = $env:ELASTIK_HOOK_STRICT -eq "1"

if ($strict) {
    Write-Host "pre-push: strict mode enabled (ELASTIK_HOOK_STRICT=1)" -ForegroundColor Yellow
} else {
    Write-Host "pre-push: fast mode. Set ELASTIK_HOOK_STRICT=1 for release tests + JS e2e." -ForegroundColor Yellow
}

Step "Rust format" {
    Run cargo fmt --manifest-path core/Cargo.toml "--" --check
    Run cargo fmt --manifest-path bin/Cargo.toml "--" --check
    Run cargo fmt --manifest-path ffi/Cargo.toml "--" --check
}

Step "Rust clippy" {
    Run cargo clippy --manifest-path core/Cargo.toml "--" "-D" warnings
    Run cargo clippy --manifest-path bin/Cargo.toml "--" "-D" warnings
    Run cargo clippy --manifest-path ffi/Cargo.toml "--" "-D" warnings
}

Step "Rust tests" {
    Run cargo test --manifest-path core/Cargo.toml
    Run cargo test --manifest-path bin/Cargo.toml
    Run cargo test --manifest-path ffi/Cargo.toml
}

Step "Panic discipline scan" {
    Run python tools/panic_discipline_scan.py core bin ffi
}

Step "Version consistency" {
    Run python tools/version_consistency_check.py
}

if (-not $strict) {
    Step "Rust supply-chain quick audit" {
        Run python tools/supply_chain_check.py prepush
    }
}

if ($strict) {
    Step "Rust release tests" {
        Run cargo test --manifest-path core/Cargo.toml --release
        Run cargo test --manifest-path bin/Cargo.toml --release
        Run cargo test --manifest-path ffi/Cargo.toml --release
    }
}

Step "Python SDK smoke" {
    Run python sdk/tests/test_tools.py
}

Step "Header policy scanner" {
    Run python tools/header_policy_scan.py --self-test
    Run python tools/header_policy_scan.py --offline
}

Step "Header policy missing-baseline negative test" {
    & python tools/header_policy_scan.py --offline --baseline missing-baseline.txt
    if ($LASTEXITCODE -eq 0) {
        throw "missing baseline unexpectedly passed"
    }
    Write-Host "missing baseline rejected as expected"
}

Step "JS syntax" {
    Run node --check sdk-js/index.mjs
    Run node --check sdk-js/start.mjs
    Run node --check sdk-js/test.mjs
}

if ($strict) {
    Step "JS SDK against real Rust core" {
        Run-JsSdkAgainstCore
    }

    Step "Rust supply-chain strict audit" {
        Run python tools/supply_chain_check.py ci
    }
}

Step "Whitespace check" {
    Run git diff --check
}

Write-Host ""
Write-Host "pre-push: all Elastik local gates passed" -ForegroundColor Green

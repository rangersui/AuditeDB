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

$repoRoot = git rev-parse --show-toplevel
Set-Location $repoRoot
$strict = $env:AUDITEDB_HOOK_STRICT -eq "1"

if ($strict) {
    Write-Host "pre-push: strict mode enabled (AUDITEDB_HOOK_STRICT=1)" -ForegroundColor Yellow
} else {
    Write-Host "pre-push: fast mode. Set AUDITEDB_HOOK_STRICT=1 for release tests + strict supply-chain." -ForegroundColor Yellow
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
    Run cargo build --release --manifest-path ffi/Cargo.toml
    New-Item -ItemType Directory -Force sdk/src/l5/_ffi | Out-Null
    $native = Get-ChildItem -LiteralPath ffi/target/release -File |
        Where-Object { $_.Name -in @("l5_ffi.dll", "libl5_ffi.so", "libl5_ffi.dylib") } |
        Select-Object -First 1
    if ($null -eq $native) {
        throw "no L5 FFI native library found under ffi/target/release"
    }
    Copy-Item -LiteralPath $native.FullName -Destination (Join-Path "sdk/src/l5/_ffi" $native.Name) -Force
    Run python -m compileall -q sdk/src
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = "sdk/src"
        Run python tools/l5_python_smoke.py
    } finally {
        if ($null -eq $oldPythonPath) {
            Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
        } else {
            $env:PYTHONPATH = $oldPythonPath
        }
    }
}

if ($strict) {
    Step "Rust supply-chain strict audit" {
        Run python tools/supply_chain_check.py ci
    }
}

Step "Whitespace check" {
    Run git diff --check
}

Write-Host ""
Write-Host "pre-push: all AuditeDB local gates passed" -ForegroundColor Green

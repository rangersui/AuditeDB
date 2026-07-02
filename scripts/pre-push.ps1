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
$strict = $env:ELASTIK_HOOK_STRICT -eq "1"

if ($strict) {
    Write-Host "pre-push: strict mode enabled (ELASTIK_HOOK_STRICT=1)" -ForegroundColor Yellow
} else {
    Write-Host "pre-push: fast mode. Set ELASTIK_HOOK_STRICT=1 for release tests + strict supply-chain." -ForegroundColor Yellow
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

if ($strict) {
    Step "Rust supply-chain strict audit" {
        Run python tools/supply_chain_check.py ci
    }
}

Step "Whitespace check" {
    Run git diff --check
}

Write-Host ""
Write-Host "pre-push: all Elastik local gates passed" -ForegroundColor Green

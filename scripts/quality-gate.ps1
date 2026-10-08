$ErrorActionPreference = "Stop"

function Invoke-NativeGate {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [scriptblock] $Command
    )

    Write-Host "`n=== $Name ===`n"

    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE."
    }
}

Invoke-NativeGate "pytest" {
    uv run pytest -q
}

Invoke-NativeGate "ruff check" {
    uv run ruff check .
}

Invoke-NativeGate "ruff format check" {
    uv run ruff format --check .
}

Invoke-NativeGate "bandit" {
    uv run bandit -q -r src
}

Invoke-NativeGate "pip-audit" {
    uv run pip-audit
}

Write-Host "`n=== detect-secrets ===`n"

$scanFiles = @(
    git ls-files --cached --others --exclude-standard
)

if ($LASTEXITCODE -ne 0) {
    throw "Failed to enumerate repository files for secret scanning."
}

if ($scanFiles.Count -eq 0) {
    throw "Secret scanning received an empty repository file set."
}

Write-Host "Scanning $($scanFiles.Count) repository-eligible files."

$secretScanFile = Join-Path `
    $env:TEMP `
    "kuma-secure-knowledge-pipeline-secrets-$PID.json"

try {
    uv run detect-secrets scan @scanFiles |
        Out-File `
            -FilePath $secretScanFile `
            -Encoding utf8

    if ($LASTEXITCODE -ne 0) {
        throw "detect-secrets scan failed."
    }

    $secretScan = (
        Get-Content $secretScanFile -Raw |
        ConvertFrom-Json
    )

    $findings = @(
        $secretScan.results.PSObject.Properties
    )

    if ($findings.Count -gt 0) {

        Write-Host "`nPotential secrets found:`n"

        foreach ($finding in $findings) {
            Write-Host " - $($finding.Name)"

            foreach ($secret in $finding.Value) {
                Write-Host (
                    "   type={0} line={1}" -f `
                    $secret.type, `
                    $secret.line_number
                )
            }
        }

        throw "Secret scanning gate failed."
    }

    Write-Host "No potential secrets detected."
}
finally {
    if (Test-Path $secretScanFile) {
        Remove-Item $secretScanFile -Force
    }
}

Invoke-NativeGate "git diff check" {
    git diff --check
}

Write-Host "`nGLOBAL QUALITY GATE: GREEN`n"

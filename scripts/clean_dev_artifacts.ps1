param(
    [switch]$IncludeVenv,
    [switch]$RemoveDb
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

$targets = @(
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache"
)

$removed = @()

foreach ($target in $targets) {
    $dirs = Get-ChildItem -Path $repoRoot -Recurse -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq $target -and ($IncludeVenv -or $_.FullName -notmatch "[\\/]\.venv([\\/]|$)")
        }

    foreach ($dir in $dirs) {
        Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $removed += $dir.FullName
    }
}

if ($RemoveDb) {
    $dbPath = Join-Path $repoRoot "kks_dev.db"
    if (Test-Path $dbPath) {
        Remove-Item -Path $dbPath -Force
        $removed += $dbPath
    }
}

if ($removed.Count -eq 0) {
    Write-Output "No matching development artifacts found."
} else {
    Write-Output "Removed:"
    $removed | Sort-Object | ForEach-Object { Write-Output $_ }
}

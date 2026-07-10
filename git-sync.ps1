<#
  git-sync helper for PowerShell on Windows.

  一键脚本：从工作区推到 origin/main。
  调用方：PowerShell -File .git-sync.ps1 "提交说明"

  PowerShell 不能很好地处理多步 git alias，
  所以拆出脚本。
#>

param(
    [string]$Message = "sync: update from local"
)

Set-Location -Path (Resolve-Path (Join-Path $PSScriptRoot ""))

$ErrorActionPreference = "Stop"

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "    git sync: starting" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# 1) \u68c0\u67e5\u5728\u4ed3\u5e93\u4e2d
$inRepo = (& git rev-parse --is-inside-work-tree 2>&1).Trim()
if ($inRepo -ne "true") {
    Write-Host "Not a git repository." -ForegroundColor Red
    exit 1
}

# 2) \u67e5\u770b\u72b6\u6001
Write-Host "[1/5] git status..." -ForegroundColor Yellow
& git status -sb
Write-Host ""

# 3) \u68c0\u6d4b\u662f\u5426\u6709\u4e1a\u52a1\u6539\u52a8
$status = (& git status --porcelain 2>&1)
if (-not $status) {
    Write-Host "Working tree clean. Nothing to commit." -ForegroundColor Green
    Write-Host ""
    Write-Host "    still pulling and pushing (in case remote moved)..." -ForegroundColor Gray
}

# 4) add + commit
Write-Host "[2/5] git add ..." -ForegroundColor Yellow
& git add .
Write-Host ""

if ($status) {
    Write-Host "[3/5] git commit..." -ForegroundColor Yellow
    & git commit -m $Message
    Write-Host ""
}

# 5) pull \u5e76\u63a8
Write-Host "[4/5] git pull --rebase..." -ForegroundColor Yellow
& git pull --rebase origin main
Write-Host ""

Write-Host "[5/5] git push..." -ForegroundColor Yellow
& git push origin main
Write-Host ""

Write-Host "=================================" -ForegroundColor Green
Write-Host "    git sync: DONE" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

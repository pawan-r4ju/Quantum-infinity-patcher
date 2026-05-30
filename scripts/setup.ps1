# QIP Agent Setup Script (Windows)
# Run: .\scripts\setup.ps1

Write-Host "🛡️ Quantum Infinity Patcher — Setup" -ForegroundColor Cyan
Write-Host ""

# Check Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "❌ Python not found. Install Python 3.11+ first." -ForegroundColor Red
    exit 1
}
$pyVersion = python --version 2>&1
Write-Host "✅ $pyVersion" -ForegroundColor Green

# Check Docker
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Host "❌ Docker not found. Install Docker Desktop first." -ForegroundColor Red
    exit 1
}
$dockerVersion = docker --version 2>&1
Write-Host "✅ $dockerVersion" -ForegroundColor Green

# Check Git
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    Write-Host "❌ Git not found. Install Git first." -ForegroundColor Red
    exit 1
}
$gitVersion = git --version 2>&1
Write-Host "✅ $gitVersion" -ForegroundColor Green

# Create QIP home directory
$qipHome = Join-Path $env:USERPROFILE ".qip"
if (-not (Test-Path $qipHome)) {
    New-Item -ItemType Directory -Path $qipHome | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $qipHome "vuln-db") | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $qipHome "skills") | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $qipHome "cache") | Out-Null
    Write-Host "✅ Created ~/.qip/ directory structure" -ForegroundColor Green
} else {
    Write-Host "✅ ~/.qip/ already exists" -ForegroundColor Green
}

# Create default config if not exists
$configPath = Join-Path $qipHome "config.yaml"
if (-not (Test-Path $configPath)) {
    @"
# QIP Global Configuration
# See PRD.md for full reference

agent:
  image: qip-agent:latest
  cpus: 2
  memory: 4g
  timeout: 1800

scan:
  scanners: [grype, trivy, native]
  severity_threshold: medium

review:
  port: 8500
  auto_open_browser: true

deploy:
  create_branch: true
  branch_prefix: "fix/qip-"
  auto_push: false
"@ | Set-Content -Path $configPath -Encoding UTF8
    Write-Host "✅ Created default config at $configPath" -ForegroundColor Green
}

# Install Python package in dev mode
Write-Host ""
Write-Host "📦 Installing QIP in development mode..." -ForegroundColor Yellow
pip install -e ".[dev]"

# Build Docker image
Write-Host ""
Write-Host "🐳 Building QIP agent Docker image..." -ForegroundColor Yellow
docker build -t qip-agent:latest .

Write-Host ""
Write-Host "🎉 Setup complete! Run 'qip doctor' to verify." -ForegroundColor Green

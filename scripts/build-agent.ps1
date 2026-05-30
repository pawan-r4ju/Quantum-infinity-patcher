# Build QIP Agent Docker Image
# Run: .\scripts\build-agent.ps1

Write-Host "🐳 Building QIP Agent image..." -ForegroundColor Cyan
docker build -t qip-agent:latest .
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Image built successfully: qip-agent:latest" -ForegroundColor Green
    docker images qip-agent:latest --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
} else {
    Write-Host "❌ Build failed." -ForegroundColor Red
    exit 1
}

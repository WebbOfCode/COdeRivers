# Deploy script for Safe URL Check
# Usage: ./deploy/deploy.ps1

Write-Host "Deploying Safe URL Check to Vercel..." -ForegroundColor Green

# Check if vercel CLI is installed
try {
    $vercelVersion = vercel --version
    Write-Host "Vercel CLI found: $vercelVersion" -ForegroundColor Gray
} catch {
    Write-Host "Error: Vercel CLI not found. Install with: npm i -g vercel" -ForegroundColor Red
    exit 1
}

# Confirm deployment
$confirm = Read-Host "Deploy to production? (y/N)"
if ($confirm -ne 'y') {
    Write-Host "Deployment cancelled." -ForegroundColor Yellow
    exit 0
}

# Deploy
vercel --prod

Write-Host "Deployment complete!" -ForegroundColor Green
Write-Host "Check your dashboard: https://vercel.com/dashboard" -ForegroundColor Gray

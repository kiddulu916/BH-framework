# Bug Hunting Framework - Frontend Deployment Script (PowerShell)

param(
    [switch]$BuildOnly,
    [switch]$Logs
)

Write-Host "🚀 Starting Bug Hunting Framework Frontend Deployment..." -ForegroundColor Green

# Check if Docker is running
try {
    docker info | Out-Null
} catch {
    Write-Host "❌ Docker is not running. Please start Docker and try again." -ForegroundColor Red
    exit 1
}

# Check if docker-compose is available
try {
    docker-compose --version | Out-Null
} catch {
    Write-Host "❌ docker-compose is not installed. Please install docker-compose and try again." -ForegroundColor Red
    exit 1
}

# Build and start the frontend service
Write-Host "📦 Building and starting frontend service..." -ForegroundColor Yellow
if ($BuildOnly) {
    docker-compose build frontend
    Write-Host "✅ Frontend build completed!" -ForegroundColor Green
    exit 0
}

docker-compose up -d --build frontend

# Wait for the frontend to be healthy
Write-Host "⏳ Waiting for frontend to be healthy..." -ForegroundColor Yellow
$timeout = 60
$counter = 0

while ($counter -lt $timeout) {
    $status = docker-compose ps frontend
    if ($status -match "healthy") {
        Write-Host "✅ Frontend is healthy and ready!" -ForegroundColor Green
        break
    }
    
    Write-Host "⏳ Waiting for frontend to be ready... ($counter/$timeout)" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    $counter += 5
}

if ($counter -ge $timeout) {
    Write-Host "❌ Frontend failed to become healthy within $timeout seconds" -ForegroundColor Red
    Write-Host "📋 Checking frontend logs..." -ForegroundColor Yellow
    docker-compose logs frontend
    exit 1
}

# Show service status
Write-Host "📊 Service Status:" -ForegroundColor Cyan
docker-compose ps

Write-Host "🌐 Frontend is available at: http://localhost:3000" -ForegroundColor Green
Write-Host "🔍 Health check endpoint: http://localhost:3000/health" -ForegroundColor Green

if ($Logs) {
    Write-Host "📋 Showing frontend logs..." -ForegroundColor Yellow
    docker-compose logs -f frontend
} else {
    Write-Host "✅ Frontend deployment completed successfully!" -ForegroundColor Green
} 
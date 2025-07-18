# Install Build Tools for Rust Development
# This script installs CMake and NASM required for building cryptographic dependencies

Write-Host "Installing build tools for Rust development..." -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
    exit 1
}

# Function to check if a command exists
function Test-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# Function to add to PATH if not already present
function Add-ToPath($path) {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($currentPath -notlike "*$path*") {
        $newPath = "$currentPath;$path"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
        Write-Host "Added $path to system PATH" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "$path is already in PATH" -ForegroundColor Green
        return $false
    }
}

# Install CMake
Write-Host "Installing CMake..." -ForegroundColor Cyan
if (Test-Command "cmake") {
    Write-Host "CMake is already installed" -ForegroundColor Green
} else {
    try {
        winget install Kitware.CMake --accept-source-agreements --accept-package-agreements
        Write-Host "CMake installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "Failed to install CMake via winget. Please install manually from https://cmake.org/download/" -ForegroundColor Red
        exit 1
    }
}

# Install NASM
Write-Host "Installing NASM..." -ForegroundColor Cyan
if (Test-Command "nasm") {
    Write-Host "NASM is already installed" -ForegroundColor Green
} else {
    try {
        winget install nasm.nasm --accept-source-agreements --accept-package-agreements
        Write-Host "NASM installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "Failed to install NASM via winget. Please install manually from https://www.nasm.us/" -ForegroundColor Red
        exit 1
    }
}

# Add common installation paths to PATH
Write-Host "Configuring PATH..." -ForegroundColor Cyan

$pathsToAdd = @(
    "C:\Program Files\CMake\bin",
    "C:\Program Files (x86)\CMake\bin",
    "C:\Program Files\NASM",
    "C:\Program Files (x86)\NASM"
)

$pathChanged = $false
foreach ($path in $pathsToAdd) {
    if (Test-Path $path) {
        if (Add-ToPath $path) {
            $pathChanged = $true
        }
    }
}

# Refresh environment variables for current session
if ($pathChanged) {
    Write-Host "Refreshing environment variables..." -ForegroundColor Yellow
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
}

# Verify installations
Write-Host "`nVerifying installations..." -ForegroundColor Cyan

if (Test-Command "cmake") {
    $cmakeVersion = cmake --version | Select-Object -First 1
    Write-Host "✓ CMake: $cmakeVersion" -ForegroundColor Green
} else {
    Write-Host "✗ CMake not found in PATH" -ForegroundColor Red
}

if (Test-Command "nasm") {
    $nasmVersion = nasm -v | Select-Object -First 1
    Write-Host "✓ NASM: $nasmVersion" -ForegroundColor Green
} else {
    Write-Host "✗ NASM not found in PATH" -ForegroundColor Red
}

Write-Host "`nInstallation complete!" -ForegroundColor Green
Write-Host "You may need to restart your terminal or IDE for PATH changes to take effect." -ForegroundColor Yellow
Write-Host "Try running 'cargo check' again in your Rust project." -ForegroundColor Cyan 
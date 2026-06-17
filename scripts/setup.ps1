Write-Host "[*] Initiating UTSU core environment setup for Windows..." -ForegroundColor Cyan

# 1. Python Virtual Environment
if (-Not (Test-Path "venv")) {
    Write-Host "[*] Creating Python virtual environment..." -ForegroundColor Cyan
    python -m venv venv
}

Write-Host "[*] Installing Python dependencies..." -ForegroundColor Cyan
& .\venv\Scripts\python.exe -m pip install --upgrade pip
& .\venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. Rust Native Compilation
Write-Host "[*] Checking for Rust toolchain..." -ForegroundColor Cyan
if (-Not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "[-] CRITICAL: Rust not found." -ForegroundColor Red
    Write-Host "[-] Windows requires manual Rust installation. Download and run rustup-init.exe from https://rustup.rs/" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Compiling utsu_rust_core analysis engine..." -ForegroundColor Cyan
Set-Location -Path "src-rust"
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY="1"
cargo build --release
Set-Location -Path ".."

# Auto-copy the compiled binary for Windows (.dll to .pyd so Python can import it natively)
$rust_dll = "src-rust\target\release\utsu_rust_core.dll"
if (Test-Path $rust_dll) {
    Copy-Item -Path $rust_dll -Destination "utsu_rust_core.pyd" -Force
    Write-Host "[+] Rust engine compiled and linked successfully." -ForegroundColor Green
} else {
    Write-Host "[-] Build failed: Could not find compiled DLL at $rust_dll." -ForegroundColor Red
    exit 1
}

Write-Host "`n[+] Setup complete. To activate the environment, run:" -ForegroundColor Green
Write-Host "    .\venv\Scripts\activate"
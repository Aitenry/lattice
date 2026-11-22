$ErrorActionPreference = 'Continue'
Set-Location 'E:\Development-Warehouse\github\lattice\web'
npx tsc --noEmit --pretty false 2>&1 | Out-String -Width 300
if ($LASTEXITCODE -ne 0) { Write-Output "TSC_FAIL $LASTEXITCODE"; exit 1 }
npx vite build 2>&1 | Out-String -Width 300
Write-Output "BUILD_EXIT $LASTEXITCODE"

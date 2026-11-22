$ErrorActionPreference = 'Continue'
Set-Location 'E:\Development-Warehouse\github\lattice\web'
Write-Output '=== tsc --noEmit ==='
npx tsc --noEmit --pretty false 2>&1 | Out-String -Width 400
Write-Output "=== tsc exit: $LASTEXITCODE ==="
if ($LASTEXITCODE -eq 0) {
  Write-Output '=== vite build ==='
  npx vite build 2>&1 | Out-String -Width 400
  Write-Output "=== build exit: $LASTEXITCODE ==="
}

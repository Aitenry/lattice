$ErrorActionPreference = 'SilentlyContinue'
Set-Location 'E:\Development-Warehouse\github\lattice\web'
if (Test-Path node_modules) {
  $n = (Get-ChildItem node_modules | Measure-Object).Count
  Write-Output "node_modules entries: $n"
} else {
  Write-Output 'NO_NODE_MODULES'
}
Write-Output '--- install.log tail ---'
Get-Content install.log -Tail 15

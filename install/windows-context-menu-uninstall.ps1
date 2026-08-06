$Targets = @(
    "HKCU:\Software\Classes\*\shell\khzip",
    "HKCU:\Software\Classes\Directory\shell\khzip",
    "HKCU:\Software\Classes\Directory\Background\shell\khzip"
)
foreach ($Target in $Targets) {
    Remove-Item $Target -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ".khzip context-menu entries removed."

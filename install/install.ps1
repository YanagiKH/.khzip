$ErrorActionPreference = "Stop"
$Repo = "YanagiKH/.khzip"
$InstallDir = if ($env:KHZIP_INSTALL_DIR) { $env:KHZIP_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\khzip" }
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Version = $Release.tag_name.TrimStart("v")
$Arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "Arm64") { "aarch64" } else { "x86_64" }
$Asset = "khzip-$Version-windows-$Arch.zip"
$Base = "https://github.com/$Repo/releases/download/$($Release.tag_name)"
$Temp = Join-Path ([System.IO.Path]::GetTempPath()) ("khzip-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    Invoke-WebRequest "$Base/$Asset" -OutFile (Join-Path $Temp $Asset)
    Invoke-WebRequest "$Base/$Asset.sha256" -OutFile (Join-Path $Temp "$Asset.sha256")
    $Expected = ((Get-Content (Join-Path $Temp "$Asset.sha256")) -split "\s+")[0].ToLowerInvariant()
    $Actual = (Get-FileHash (Join-Path $Temp $Asset) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Expected -ne $Actual) { throw "SHA-256 checksum mismatch" }
    Expand-Archive (Join-Path $Temp $Asset) -DestinationPath $Temp -Force
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $Temp "khzip.exe") $InstallDir -Force
    if (Test-Path (Join-Path $Temp "khzip-gui.exe")) { Copy-Item (Join-Path $Temp "khzip-gui.exe") $InstallDir -Force }
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($UserPath -split ";") -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable("Path", (($UserPath.TrimEnd(";"), $InstallDir) -join ";"), "User")
    }
    Write-Host "Installed .khzip to $InstallDir"
} finally {
    Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
}

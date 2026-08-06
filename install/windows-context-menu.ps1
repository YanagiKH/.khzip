$ErrorActionPreference = "Stop"
$Gui = (Get-Command khzip-gui.exe -ErrorAction Stop).Source
$Icon = "$Gui,0"
$Targets = @(
    @{ Path = "HKCU:\Software\Classes\*\shell\khzip"; Label = "Open with .khzip"; Arg = '"%1"' },
    @{ Path = "HKCU:\Software\Classes\Directory\shell\khzip"; Label = "Compress with .khzip"; Arg = '"%1"' },
    @{ Path = "HKCU:\Software\Classes\Directory\Background\shell\khzip"; Label = "Open .khzip here"; Arg = '"%V"' }
)
foreach ($Target in $Targets) {
    New-Item -Path $Target.Path -Force | Out-Null
    Set-ItemProperty -Path $Target.Path -Name "(default)" -Value $Target.Label
    Set-ItemProperty -Path $Target.Path -Name "Icon" -Value $Icon
    New-Item -Path "$($Target.Path)\command" -Force | Out-Null
    Set-ItemProperty -Path "$($Target.Path)\command" -Name "(default)" -Value ('"' + $Gui + '" ' + $Target.Arg)
}
Write-Host ".khzip context-menu entries installed for the current user."

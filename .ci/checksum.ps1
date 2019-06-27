param (
    [string]$filename = $(throw "-filename is required.")
)

$ErrorActionPreference="Stop"

(Get-FileHash "${filename}").Hash | Out-File "${filename}.sha256" -NoNewline
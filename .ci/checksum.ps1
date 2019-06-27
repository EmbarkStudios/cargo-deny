param (
    [string]$filename = $(throw "-filename is required.")
)

$ErrorActionPreference="Stop"

(Get-FileHash "${filename}").Hash | Out-File -Encoding ASCII -NoNewline "${filename}.sha256"
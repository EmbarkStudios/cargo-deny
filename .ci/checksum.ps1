param (
    [string]$filename = $(throw "-filename is required.")
)
$ErrorActionPreference="Stop"

echo "filename = ${filename}"
(Get-FileHash "${filename}").Hash | Out-File "${filename}.sha256" -NoNewline
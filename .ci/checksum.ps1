(Get-FileHash "${1}").Hash | Out-File "${1}.sha256" -NoNewline
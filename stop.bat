@echo off
echo Closing project services...

powershell -NoProfile -Command ^
  "Get-NetTCPConnection -LocalPort 8080 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }"

powershell -NoProfile -Command ^
  "Get-NetTCPConnection -LocalPort 8081 | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }"

powershell -NoProfile -Command "Stop-Process -Name ngrok -Force"

echo All project services stopped.

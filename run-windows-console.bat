@echo off
rem Double-click this to run the text-menu version (harden.ps1) as Administrator.
rem Extra arguments are passed through, e.g.:  run-windows-console.bat -AuditOnly
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -NoExit -ExecutionPolicy Bypass -File \"%~dp0harden.ps1\" %*'"

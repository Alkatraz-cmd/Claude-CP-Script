@echo off
rem Double-click this to open the hardening window as Administrator.
rem For the text-menu version instead, use run-windows-console.bat.
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0gui.ps1\"'"

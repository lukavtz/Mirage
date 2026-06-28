@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_and_verify.ps1"
if %errorlevel% neq 0 exit /b %errorlevel%

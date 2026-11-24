<#
  Gera VIGIL-Agent.exe (nao exige Python nos computadores monitorados).
  Execute nesta pasta, em uma maquina com Python 3.9+:
    powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
  Resultado: .\VIGIL-Agent.exe  -> copie junto com install.ps1/uninstall.ps1 (o install.ps1 detecta o .exe).
#>
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Here
if (-not (Test-Path .\vigil_agent.py)) { Copy-Item ..\vigil_agent.py . -ErrorAction Stop }
python -m pip install --upgrade --quiet pyinstaller psutil pywin32
python -m PyInstaller --onefile --name VIGIL-Agent --clean --noconfirm `
  --hidden-import win32timezone --hidden-import servicemanager --hidden-import win32serviceutil `
  --hidden-import pythoncom --hidden-import win32com.client vigil_service.py
Copy-Item .\dist\VIGIL-Agent.exe . -Force
Remove-Item .\build, .\dist, .\VIGIL-Agent.spec -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Gerado: VIGIL-Agent.exe' -ForegroundColor Green

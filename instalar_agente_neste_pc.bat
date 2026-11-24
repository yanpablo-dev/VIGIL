@echo off
title VIGIL - Instalar agente neste computador
net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo   Este instalador precisa de Administrador.
  echo   Feche esta janela, clique com o BOTAO DIREITO neste arquivo
  echo   e escolha "Executar como administrador".
  echo.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0instalar_agente_neste_pc.ps1"
echo.
pause

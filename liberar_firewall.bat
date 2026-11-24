@echo off
title VIGIL - Liberar firewall
net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo   Este arquivo precisa de Administrador.
  echo   Feche esta janela, clique com o BOTAO DIREITO neste arquivo
  echo   e escolha "Executar como administrador".
  echo.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0liberar_firewall.ps1"
pause

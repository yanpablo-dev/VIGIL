@echo off
title VIGIL - Servidor central
cd /d "%~dp0server"
python -c "import cryptography" 2>nul || python -m pip install --quiet cryptography
python vigil_server.py
pause

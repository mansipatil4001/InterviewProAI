@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  py -m venv .venv
  if errorlevel 1 (
    echo Could not create the Python virtual environment.
    pause
    exit /b 1
  )
)
call .venv\Scripts\activate
python -m pip install --upgrade pip
if errorlevel 1 (
  echo Could not upgrade pip.
  pause
  exit /b 1
)
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Could not install project requirements.
  pause
  exit /b 1
)
if not exist .env copy .env.example .env
echo.
echo Open this app on the computer at http://127.0.0.1:8000
echo For a phone on the same Wi-Fi, use the computer IPv4 address shown below:
ipconfig
echo.
echo Use the phone URL http://COMPUTER-IP:8000
echo Only allow Windows Firewall access on trusted private networks.
echo Press Ctrl+C to stop the app.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
pause

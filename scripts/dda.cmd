@echo off
setlocal
set "DDA_ROOT=%~dp0.."
if exist "%DDA_ROOT%\.venv\Scripts\python.exe" (
  "%DDA_ROOT%\.venv\Scripts\python.exe" "%~dp0dda.py" %*
) else (
  python "%~dp0dda.py" %*
)
exit /b %ERRORLEVEL%

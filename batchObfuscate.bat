@echo off
setlocal
rem Keep the original drag-and-drop operation; no arguments opens the new menu.
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
    if not errorlevel 1 goto use_py
)
where python >nul 2>nul
if not errorlevel 1 (
    python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
    if not errorlevel 1 goto use_python
)
echo Python 3.10 or newer is required. Install it from https://www.python.org/
echo Then run: py -3 -m pip install -r "%~dp0requirements.txt"
pause
exit /b 1

:use_py
if "%~1"=="" (
    py -3 "%~dp0bypass.py"
) else (
    py -3 "%~dp0bypass.py" obfuscate "%~1"
)
goto done

:use_python
if "%~1"=="" (
    python "%~dp0bypass.py"
) else (
    python "%~dp0bypass.py" obfuscate "%~1"
)

:done
set "result=%errorlevel%"
if not "%~1"=="" pause
exit /b %result%

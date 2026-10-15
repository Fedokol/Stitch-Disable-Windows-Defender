@echo off
chcp 65001 >nul
REM ============================================================
REM  Windows Defender Toggle - запуск от имени администратора
REM ============================================================
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 defender_toggle.py %*
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        python defender_toggle.py %*
    ) else (
        echo [ОШИБКА] Python не найден. Установите Python 3 с https://python.org
        echo и убедитесь, что галочка "Add Python to PATH" включена.
        pause
        exit /b 1
    )
)

pause

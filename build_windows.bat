@echo off
chcp 65001 >nul
title Сборка MineChecker.exe
cd /d "%~dp0"
setlocal enabledelayedexpansion

echo.
echo  ==========================================================
echo    Сборка Mine Checker в один файл MineChecker.exe
echo    Всё нужное скрипт установит сам. Просто подожди.
echo  ==========================================================
echo.

REM ---------- 1. Python ------------------------------------------------
set "PY="
for %%C in (py python) do (
    if not defined PY (
        %%C -c "import sys;raise SystemExit(0 if sys.version_info>=(3,9) else 1)" >nul 2>nul
        if not errorlevel 1 set "PY=%%C"
    )
)

if not defined PY (
    echo  [1/4] Python не найден — устанавливаю…
    echo.
    where winget >nul 2>nul
    if not errorlevel 1 (
        echo        через winget…
        winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
    ) else (
        echo        скачиваю установщик с python.org…
        curl -L -o "%TEMP%\python-setup.exe" https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe
        if errorlevel 1 (
            powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe' -OutFile '%TEMP%\python-setup.exe'"
        )
        echo        устанавливаю (тихо, без вопросов)…
        "%TEMP%\python-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1 Include_pip=1
        del "%TEMP%\python-setup.exe" >nul 2>nul
    )

    REM обновляем PATH в текущем окне, чтобы не просить перезапуск
    for /f "skip=2 tokens=2,*" %%A in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "USERPATH=%%B"
    set "PATH=!USERPATH!;%PATH%"

    set "PY="
    for %%C in (py python) do (
        if not defined PY (
            %%C -c "import sys;raise SystemExit(0 if sys.version_info>=(3,9) else 1)" >nul 2>nul
            if not errorlevel 1 set "PY=%%C"
        )
    )
)

if not defined PY (
    echo.
    echo  [!] Python установился, но ещё не виден в этом окне.
    echo      Закрой это окно и запусти build_windows.bat ещё раз — всё продолжится.
    echo.
    pause
    exit /b 1
)

echo  [1/4] Python найден:
%PY% --version
echo.

REM ---------- 2. tkinter ------------------------------------------------
%PY% -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo  [!] В этом Python нет tkinter. Переустанови Python с python.org,
    echo      отметив компонент "tcl/tk and IDLE".
    pause
    exit /b 1
)

REM ---------- 3. Зависимости --------------------------------------------
echo  [2/4] Ставлю PyInstaller и customtkinter…
%PY% -m pip install --upgrade --quiet pip
%PY% -m pip install --upgrade --quiet pyinstaller customtkinter
if errorlevel 1 (
    echo  [!] Не удалось установить пакеты. Проверь интернет.
    pause
    exit /b 1
)

REM ---------- 4. Настройки ----------------------------------------------
if not exist config.json (
    copy config.example.json config.json >nul
    echo.
    echo  [3/4] Открываю config.json — впиши webhook Discord и/или токен Telegram,
    echo        сохрани файл (Ctrl+S) и закрой Блокнот. Сборка продолжится сама.
    echo        Можно оставить пустым и настроить прямо в окне программы.
    echo.
    notepad config.json
) else (
    echo  [3/4] config.json на месте.
)

REM ---------- 5. Сборка -------------------------------------------------
echo.
echo  [4/4] Собираю MineChecker.exe — это займёт 1-3 минуты…
echo.
%PY% build.py
if errorlevel 1 (
    echo.
    echo  [!] Сборка не удалась. Скопируй текст ошибки выше.
    pause
    exit /b 1
)

echo.
echo  ==========================================================
echo    Готово: dist\MineChecker.exe
echo    Один файл. Отправляй игроку — Python ему не нужен.
echo  ==========================================================
echo.
if exist dist explorer dist
pause

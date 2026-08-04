#!/bin/bash
# Запуск Mine Checker из исходников на macOS/Linux (двойной клик по файлу).
cd "$(dirname "$0")" || exit 1

PY=""
for c in ./.venv/bin/python python3 /usr/bin/python3; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
        if "$c" -c "import tkinter" >/dev/null 2>&1; then PY="$c"; break; fi
    fi
done

if [ -z "$PY" ]; then
    echo "Не найден Python с поддержкой tkinter."
    echo "Установите его:  brew install python@3.12 python-tk@3.12"
    read -r -p "Нажмите Enter…"
    exit 1
fi

"$PY" main.py "$@"

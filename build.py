#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сборка Mine Checker в ОДИН файл, который игрок просто скачивает и открывает.

    python3 build.py

Что получится:
    Windows :  dist/MineChecker.exe        — один файл, двойной клик, Python не нужен
    macOS   :  dist/MineChecker.app        — обычное приложение (+ dist/MineChecker.zip для отправки)
               dist/MineChecker            — тот же чекер одним бинарником
    Linux   :  dist/MineChecker

    python3 build.py --dir   собирает папку вместо одного файла:
    антивирусы ругаются на неё заметно реже (см. раздел про антивирус в README).

Важно: PyInstaller не умеет собирать под чужую ОС. Чтобы получить .exe,
запустите этот скрипт на Windows; чтобы получить .app — на macOS.

config.json вшивается ВНУТРЬ программы, поэтому игроку ничего настраивать не надо:
webhook Discord и токен Telegram уже будут внутри. Заполните config.json до сборки.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
NAME = "MineChecker"
SEP = ";" if sys.platform.startswith("win") else ":"

# Консоль Windows по умолчанию не в UTF-8, и русские строки роняют сборку
# с UnicodeEncodeError. Переключаем вывод сами, чтобы это не зависело от среды.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HIDDEN = [
    "checker.scanners.traces_windows",
    "checker.scanners.traces_macos",
    "checker.scanners.files",
    "checker.scanners.jars",
    "checker.scanners.minecraft",
    "checker.scanners.processes",
    "tkinter", "tkinter.ttk",
]


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
        return [sys.executable, "-m", "PyInstaller"]
    except ImportError:
        print("[i] Устанавливаю PyInstaller…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"])
        return [sys.executable, "-m", "PyInstaller"]


VERSION = "1.1.0"

# Ресурс версии для .exe. Без него файл выглядит для антивируса как безымянный
# бинарник неизвестного происхождения - это одна из главных причин ложных
# срабатываний Windows Defender на программы, собранные PyInstaller.
VERSION_INFO = """VSVersionInfo(
  ffi=FixedFileInfo(filevers=(1,1,0,0), prodvers=(1,1,0,0), mask=0x3f, flags=0x0,
                    OS=0x40004, fileType=0x1, subtype=0x0, date=(0,0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
        StringStruct('CompanyName', 'Mine Checker'),
        StringStruct('FileDescription', 'Mine Checker - proverka Minecraft na chity'),
        StringStruct('FileVersion', '%s'),
        StringStruct('InternalName', 'MineChecker'),
        StringStruct('LegalCopyright', 'Mine Checker'),
        StringStruct('OriginalFilename', 'MineChecker.exe'),
        StringStruct('ProductName', 'Mine Checker'),
        StringStruct('ProductVersion', '%s')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""" % (VERSION, VERSION)


def write_version_file():
    path = os.path.join(BASE, "version_info.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(VERSION_INFO)
    return path


def main():
    # --dir собирает папку вместо одного файла. Это заметно снижает ложные
    # срабатывания антивирусов: onefile-сборка при каждом запуске распаковывает
    # себя во временную папку и запускает код оттуда, а такое поведение
    # эвристики считают признаком дроппера.
    onedir_flag = "--dir" in sys.argv

    cfg = os.path.join(BASE, "config.json")
    if not os.path.isfile(cfg):
        example = os.path.join(BASE, "config.example.json")
        if os.path.isfile(example):
            shutil.copy(example, cfg)
        print("[!] config.json не найден — создан из примера.")
        print("[!] Впишите в него webhook Discord / токен Telegram и запустите сборку заново.")
        return 1

    # Windows/Linux: настоящий один файл. macOS: .app (иначе система блокирует
    # onefile-приложения с окном), который отдаём игроку одним архивом .zip.
    mode = "--onedir" if (sys.platform == "darwin" or onedir_flag) else "--onefile"

    cmd = ensure_pyinstaller() + [
        "--noconfirm", "--clean",
        mode,
        "--windowed",
        # UPX-сжатие - самый частый повод для антивируса пометить файл как
        # упакованный вредонос, поэтому его отключаем.
        "--noupx",
        "--name", NAME,
        "--add-data", f"{cfg}{SEP}.",
        "--exclude-module", "numpy",
        "--exclude-module", "PIL",
        "--exclude-module", "matplotlib",
    ]
    for h in HIDDEN:
        cmd += ["--hidden-import", h]

    icon = os.path.join(BASE, "assets", "icon.ico" if sys.platform.startswith("win") else "icon.icns")
    if os.path.isfile(icon):
        cmd += ["--icon", icon]

    if sys.platform.startswith("win"):
        cmd += ["--version-file", write_version_file()]

    cmd.append(os.path.join(BASE, "main.py"))

    print("[i] Собираю:", " ".join(cmd[-6:]), "…")
    subprocess.check_call(cmd, cwd=BASE)

    dist = os.path.join(BASE, "dist")

    # onedir на Windows - это папка; пакуем её в zip, чтобы игроку по-прежнему
    # надо было скачать один файл.
    folder = os.path.join(dist, NAME)
    if onedir_flag and sys.platform != "darwin" and os.path.isdir(folder):
        zip_path = os.path.join(dist, NAME + ".zip")
        print("[i] Пакую папку в zip для отправки игроку…")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, files in os.walk(folder):
                for f in files:
                    full = os.path.join(root, f)
                    z.write(full, os.path.relpath(full, dist))

    app = os.path.join(dist, NAME + ".app")
    if sys.platform == "darwin" and os.path.isdir(app):
        zip_path = os.path.join(dist, NAME + ".zip")
        print("[i] Пакую .app в zip для отправки игроку…")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, files in os.walk(app):
                for f in files:
                    full = os.path.join(root, f)
                    z.write(full, os.path.relpath(full, dist))

    print("\n[✓] Готово. Файлы в папке dist:")
    for f in sorted(os.listdir(dist)):
        p = os.path.join(dist, f)
        size = os.path.getsize(p) if os.path.isfile(p) else sum(
            os.path.getsize(os.path.join(r, x)) for r, _d, xs in os.walk(p) for x in xs)
        print(f"    {f:<24} {size/1024/1024:.1f} МБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# -*- coding: utf-8 -*-
"""Автоопределение ОС и путей. Windows / macOS / Linux."""

from __future__ import annotations

import ctypes
import getpass
import glob
import os
import platform
import socket
import sys

from .utils import run_cmd

WINDOWS = sys.platform.startswith("win")
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")

OS_KEY = "windows" if WINDOWS else "macos" if MACOS else "linux" if LINUX else "unknown"
OS_LABEL = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "unknown": "Неизвестно"}[OS_KEY]


# ---------------------------------------------------------------------------
# Сведения о системе
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        if WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def os_version() -> str:
    if WINDOWS:
        v = platform.win32_ver()
        build = platform.version().split(".")[-1] if platform.version() else ""
        name = "Windows 11" if build.isdigit() and int(build) >= 22000 else f"Windows {v[0]}"
        return f"{name} (build {platform.version()})"
    if MACOS:
        return f"macOS {platform.mac_ver()[0]} ({platform.machine()})"
    return f"{platform.system()} {platform.release()}"


def system_info() -> dict:
    info = {
        "os": OS_LABEL,
        "os_key": OS_KEY,
        "os_version": os_version(),
        "arch": platform.machine(),
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "admin": is_admin(),
        "python": platform.python_version(),
        "cpu": platform.processor() or platform.machine(),
    }
    if MACOS:
        info["cpu"] = (run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"]).strip() or info["cpu"])
        mem = run_cmd(["sysctl", "-n", "hw.memsize"]).strip()
        if mem.isdigit():
            info["ram"] = f"{int(mem) / 1024**3:.0f} ГБ"
        info["sip"] = "включён" if "enabled" in run_cmd(["csrutil", "status"]).lower() else "ОТКЛЮЧЁН"
        boot = run_cmd(["sysctl", "-n", "kern.boottime"])
        info["boottime"] = boot.strip()
    elif WINDOWS:
        out = run_cmd(["powershell", "-NoProfile", "-Command",
                       "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"])
        d = "".join(ch for ch in out if ch.isdigit())
        if d:
            info["ram"] = f"{int(d) / 1024**3:.0f} ГБ"
        info["boottime"] = run_cmd(["powershell", "-NoProfile", "-Command",
                                    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"]).strip()
    return info


def java_versions() -> list:
    out = []
    for cmd in (["java", "-version"], ["javaw", "-version"]):
        text = run_cmd(cmd, timeout=8)
        if not text:
            # java пишет версию в stderr
            try:
                import subprocess
                text = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      timeout=8).stdout.decode("utf-8", "replace")
            except Exception:
                text = ""
        if text.strip():
            out.append(f"{cmd[0]}: " + text.strip().splitlines()[0])
            break
    return out


# ---------------------------------------------------------------------------
# Пути
# ---------------------------------------------------------------------------
def home() -> str:
    return os.path.expanduser("~")


def _exists(paths):
    return [p for p in paths if p and os.path.exists(p)]


def minecraft_dirs() -> list:
    """Все каталоги Minecraft/лаунчеров, которые есть на этой машине."""
    h = home()
    cands = []
    if WINDOWS:
        appdata = os.environ.get("APPDATA", os.path.join(h, "AppData", "Roaming"))
        local = os.environ.get("LOCALAPPDATA", os.path.join(h, "AppData", "Local"))
        cands += [
            os.path.join(appdata, ".minecraft"),
            os.path.join(appdata, ".technic"),
            os.path.join(appdata, ".tlauncher"),
            os.path.join(appdata, ".feather"),
            os.path.join(appdata, ".badlion"),
            os.path.join(appdata, ".salwyrrlauncher"),
            os.path.join(appdata, "PrismLauncher"),
            os.path.join(appdata, "PolyMC"),
            os.path.join(appdata, "ATLauncher"),
            os.path.join(appdata, "gdlauncher_next"),
            os.path.join(appdata, "ModrinthApp"),
            os.path.join(h, ".lunarclient"),
            os.path.join(h, "curseforge", "minecraft", "Instances"),
            os.path.join(local, "Packages"),
        ]
        cands += glob.glob(os.path.join(appdata, ".minecraft*"))
        cands += glob.glob(os.path.join(h, ".minecraft*"))
        cands += glob.glob(os.path.join(local, "*inecraft*"))
    elif MACOS:
        appsup = os.path.join(h, "Library", "Application Support")
        cands += [
            os.path.join(appsup, "minecraft"),
            os.path.join(appsup, ".minecraft"),
            os.path.join(appsup, "PrismLauncher"),
            os.path.join(appsup, "PolyMC"),
            os.path.join(appsup, "multimc"),
            os.path.join(appsup, "ModrinthApp"),
            os.path.join(appsup, "ATLauncher"),
            os.path.join(appsup, "tlauncher"),
            os.path.join(appsup, "gdlauncher_next"),
            os.path.join(h, ".lunarclient"),
            os.path.join(h, ".minecraft"),
        ]
        cands += glob.glob(os.path.join(appsup, "*inecraft*"))
    else:
        cands += [os.path.join(h, ".minecraft"),
                  os.path.join(h, ".local", "share", "PrismLauncher"),
                  os.path.join(h, ".local", "share", "multimc")]

    found = _exists(cands)
    # + любые каталоги, похожие на игровые (есть versions + launcher_profiles.json)
    for root in (os.path.join(h, "Desktop"), os.path.join(h, "Downloads"), os.path.join(h, "Documents")):
        if os.path.isdir(root):
            for entry in os.listdir(root)[:400]:
                p = os.path.join(root, entry)
                if os.path.isdir(p) and (os.path.isdir(os.path.join(p, "versions"))
                                         or os.path.isfile(os.path.join(p, "launcher_profiles.json"))):
                    found.append(p)
    seen, out = set(), []
    for p in found:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


def scan_roots() -> list:
    """
    Каталоги для проверки в виде (путь, глубина), в порядке важности.

    Глубина разная не просто так: в .minecraft чит может лежать в подпапке
    десятого уровня, а Рабочий стол и Документы у людей содержат сотни тысяч
    рабочих файлов, где чита заведомо нет — там хватает верхних уровней.
    Порядок важен: если проверка упрётся в лимит времени, главное уже проверено.
    """
    h = home()
    roots = []

    # 1) сама игра — максимальная глубина
    for mc in minecraft_dirs():
        roots.append((mc, 10))

    # 2) куда реально кладут скачанный чит
    for name, depth in (("Downloads", 7), ("Загрузки", 7), ("Desktop", 5), ("Рабочий стол", 5)):
        roots.append((os.path.join(h, name), depth))
    roots += [(p, 4) for p in trash_dirs()]

    # 3) системные места установки
    if WINDOWS:
        appdata = os.environ.get("APPDATA", "")
        local = os.environ.get("LOCALAPPDATA", "")
        roots += [(appdata, 4), (local, 4), (os.environ.get("TEMP", ""), 3),
                  (os.path.join(h, "AppData", "LocalLow"), 3),
                  ("C:\\Program Files", 3), ("C:\\Program Files (x86)", 3),
                  ("C:\\ProgramData", 3), ("C:\\Users\\Public", 3)]
    elif MACOS:
        roots += [(os.path.join(h, "Library", "Application Support"), 3),
                  (os.path.join(h, "Library", "Preferences"), 2),
                  (os.path.join(h, "Library", "LaunchAgents"), 2),
                  ("/Applications", 3), ("/Library/Application Support", 3),
                  ("/Library/LaunchAgents", 2), ("/Library/LaunchDaemons", 2),
                  ("/private/tmp", 3)]
    else:
        roots += [(os.path.join(h, ".local", "share"), 3), ("/tmp", 3), ("/opt", 3)]

    # 4) остальное по верхам — на случай «спрятал в Документах»
    roots += [(os.path.join(h, "Documents"), 4), (os.path.join(h, "Документы"), 4),
              (os.path.join(h, "Videos"), 3), (os.path.join(h, "Music"), 3),
              (os.path.join(h, "Pictures"), 3), (os.path.join(h, "Movies"), 3)]

    seen, out = set(), []
    for path, depth in roots:
        if not path or not os.path.isdir(path):
            continue
        key = os.path.realpath(path)
        if key in seen:
            continue
        seen.add(key)
        out.append((path, depth))
    return out


def trash_dirs() -> list:
    h = home()
    if WINDOWS:
        out = []
        for drive in ("C:", "D:", "E:"):
            p = drive + "\\$Recycle.Bin"
            if os.path.isdir(p):
                out.append(p)
        return out
    if MACOS:
        return _exists([os.path.join(h, ".Trash"), "/Volumes"])
    return _exists([os.path.join(h, ".local", "share", "Trash")])

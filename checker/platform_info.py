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


def all_drives() -> list:
    """Все смонтированные диски. Windows: буквы A–Z, кроме сетевых. Прочие: точки монтирования."""
    out = []
    if WINDOWS:
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if mask & (1 << i):
                    letter = f"{chr(65 + i)}:\\"
                    # 3 = DRIVE_FIXED, 2 = DRIVE_REMOVABLE (USB-флешка) — берём оба
                    t = ctypes.windll.kernel32.GetDriveTypeW(letter)
                    if t in (2, 3):
                        out.append(letter)
        except Exception:
            out = [d + ":\\" for d in "CDEFGH" if os.path.isdir(d + ":\\")]
    elif MACOS:
        out = ["/"] + [os.path.join("/Volumes", v) for v in _safe_listdir("/Volumes")]
    else:
        out = ["/"] + [os.path.join("/media", v) for v in _safe_listdir("/media")] \
                    + [os.path.join("/mnt", v) for v in _safe_listdir("/mnt")]
    return [d for d in dict.fromkeys(out) if os.path.isdir(d)]


def removable_drives() -> list:
    """Только съёмные носители (USB-флешки), подключённые прямо сейчас."""
    out = []
    if WINDOWS:
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if mask & (1 << i):
                    letter = f"{chr(65 + i)}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(letter) == 2:
                        out.append(letter)
        except Exception:
            pass
    elif MACOS:
        # /Volumes/* — но основной том это симлинк на корень «/», он не съёмный
        root_dev = None
        try:
            root_dev = os.stat("/").st_dev
        except OSError:
            pass
        for v in _safe_listdir("/Volumes"):
            p = os.path.join("/Volumes", v)
            try:
                if root_dev is not None and os.stat(p).st_dev == root_dev:
                    continue
            except OSError:
                continue
            out.append(p)
    return [d for d in out if os.path.isdir(d)]


def all_user_homes() -> list:
    """Домашние папки всех пользователей машины."""
    homes = [home()]
    if WINDOWS:
        base = os.path.dirname(home()) or "C:\\Users"
        for name in _safe_listdir(base):
            if name.lower() in ("public", "default", "default user", "all users",
                                 "defaultapppool"):
                continue
            p = os.path.join(base, name)
            if os.path.isdir(p):
                homes.append(p)
    elif MACOS:
        for name in _safe_listdir("/Users"):
            if name.startswith(".") or name == "Shared":
                continue
            p = os.path.join("/Users", name)
            if os.path.isdir(p):
                homes.append(p)
    else:
        for name in _safe_listdir("/home"):
            homes.append(os.path.join("/home", name))
    return [h for h in dict.fromkeys(homes) if os.path.isdir(h)]


def _safe_listdir(path):
    try:
        return os.listdir(path)
    except Exception:
        return []


def _home_roots(h, is_main):
    """Приоритетные подпапки внутри одного домашнего каталога."""
    r = []
    if is_main:
        for mc in minecraft_dirs():
            r.append((mc, 10))
    else:
        # у чужого пользователя проверяем игру по стандартным путям
        for sub in (os.path.join(h, "AppData", "Roaming", ".minecraft"),
                    os.path.join(h, ".minecraft"),
                    os.path.join(h, "Library", "Application Support", "minecraft"),
                    os.path.join(h, ".lunarclient")):
            if os.path.isdir(sub):
                r.append((sub, 10))
    for name, depth in (("Downloads", 7), ("Загрузки", 7), ("Desktop", 5), ("Рабочий стол", 5),
                        ("Documents", 4), ("Документы", 4)):
        r.append((os.path.join(h, name), depth))
    return r


def scan_roots(cfg=None) -> list:
    """
    Каталоги для проверки в виде (путь, глубина), в порядке важности.

    Флаги в cfg["scan"]: all_users, all_drives, usb — расширяют охват.
    Глубина разная: в .minecraft чит бывает в подпапке 10-го уровня, а Рабочий
    стол содержит сотни тысяч рабочих файлов — там хватает верхних уровней.
    Порядок важен: если упрёмся в лимит времени, главное уже проверено.
    """
    scan = (cfg or {}).get("scan", {}) if cfg else {}
    h = home()
    roots = []

    # 1) домашние папки: своя всегда, чужие — по флагу all_users
    homes = [h]
    if scan.get("all_users", True):
        homes = all_user_homes()
    for hh in homes:
        roots += _home_roots(hh, is_main=(hh == h))

    # 2) корзины
    roots += [(p, 4) for p in trash_dirs()]

    # 3) съёмные носители (USB) — их проверяем целиком, туда прячут читы
    if scan.get("usb", True):
        for d in removable_drives():
            roots.append((d, 8))

    # 4) все диски целиком по флагу all_drives (медленно, но полно)
    if scan.get("all_drives", False):
        for d in all_drives():
            roots.append((d, 6))

    # 5) системные места установки
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

    # 6) остальные медиапапки своего профиля по верхам
    roots += [(os.path.join(h, "Videos"), 3), (os.path.join(h, "Music"), 3),
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

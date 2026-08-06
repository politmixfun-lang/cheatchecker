# -*- coding: utf-8 -*-
"""
Следы удалённых читов в Windows.

Даже если .jar удалён, система помнит имя файла в:
  Корзине ($I-файлы), Prefetch, Recent/LNK, JumpLists, реестре (BAM, UserAssist,
  MUICache, RecentDocs, RunMRU, Compatibility Assistant), журнале USN.
"""

from __future__ import annotations

import glob
import os
import struct
from datetime import datetime, timedelta

from .. import signatures as sig
from ..utils import Finding, SignatureMatcher, file_stat, fmt_time, human_size, run_cmd


def _filetime(ft: int) -> str:
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return "—"


# ---------------------------------------------------------------------------
def recycle_bin(matcher, findings):
    """Разбор $I-файлов: имя, размер и время удаления."""
    entries = []
    for drive in ("C:", "D:", "E:", "F:"):
        root = drive + "\\$Recycle.Bin"
        if not os.path.isdir(root):
            continue
        for ipath in glob.glob(os.path.join(root, "*", "$I*")):
            try:
                with open(ipath, "rb") as f:
                    data = f.read(1024)
                if len(data) < 24:
                    continue
                version = struct.unpack("<Q", data[0:8])[0]
                size = struct.unpack("<Q", data[8:16])[0]
                deleted = struct.unpack("<Q", data[16:24])[0]
                if version == 2:
                    nlen = struct.unpack("<I", data[24:28])[0]
                    name = data[28:28 + nlen * 2].decode("utf-16-le", "replace").rstrip("\x00")
                else:
                    name = data[24:24 + 520].decode("utf-16-le", "replace").rstrip("\x00")
                entries.append((name, size, deleted, ipath))
            except Exception:
                continue

    for name, size, deleted, ipath in entries:
        for hit, sev, cat in matcher.match(name):
            findings.append(Finding(
                title=f"{hit} — удалён в Корзину: {os.path.basename(name)}",
                severity=sev, category=sig.CAT_TRACE,
                detail="Файл с сигнатурой чита лежит в Корзине. Полный путь и время удаления ниже.",
                path=name,
                evidence=[f"Исходный путь: {name}",
                          f"Размер: {human_size(size)}",
                          f"Удалён: {_filetime(deleted)}",
                          f"Запись Корзины: {ipath}"]))
    if entries:
        recent = sorted(entries, key=lambda e: e[2], reverse=True)[:25]
        findings.append(Finding(
            title=f"Содержимое Корзины ({len(entries)} записей)",
            severity="info", category=sig.CAT_TRACE,
            detail="Последние удалённые файлы — сверьте со временем начала проверки.",
            evidence=[f"{_filetime(d)} | {human_size(s)} | {n}" for n, s, d, _ in recent]))


# ---------------------------------------------------------------------------
def prefetch(matcher, findings):
    root = r"C:\Windows\Prefetch"
    if not os.path.isdir(root):
        return
    try:
        files = os.listdir(root)
    except PermissionError:
        findings.append(Finding(
            title="Prefetch недоступен (нужны права администратора)",
            severity="info", category=sig.CAT_SYS,
            detail="Запустите чекер от имени администратора, чтобы прочитать историю запусков программ.",
            path=root))
        return
    except OSError:
        return
    if len(files) < 5:
        findings.append(Finding(
            title="Prefetch пуст или очищен",
            severity="high", category=sig.CAT_CLEANER,
            detail="Windows хранит здесь историю запуска программ. Пустая папка = историю стёрли.",
            path=root, evidence=[f"Файлов: {len(files)}"]))
    for name in files:
        for hit, sev, cat in matcher.match(name):
            p = os.path.join(root, name)
            st = file_stat(p)
            findings.append(Finding(
                title=f"{hit} — запускался (Prefetch: {name})",
                severity=sev, category=sig.CAT_TRACE,
                detail="Windows зафиксировала запуск этой программы, даже если файл уже удалён.",
                path=p, evidence=[f"Последний запуск: {fmt_time(st['mtime'])}",
                                  f"Файл Prefetch: {p}"]))


# ---------------------------------------------------------------------------
def recent_and_jumplists(matcher, findings):
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return
    recent = os.path.join(appdata, "Microsoft", "Windows", "Recent")
    for pattern in (os.path.join(recent, "*.lnk"),
                    os.path.join(recent, "AutomaticDestinations", "*"),
                    os.path.join(recent, "CustomDestinations", "*")):
        for p in glob.glob(pattern):
            base = os.path.basename(p)
            hits = matcher.match(base)
            # внутри .lnk лежит целевой путь — читаем строки
            target = ""
            if p.lower().endswith(".lnk"):
                try:
                    raw = open(p, "rb").read(8000)
                    target = raw.decode("utf-16-le", "ignore") + " " + raw.decode("latin-1", "ignore")
                except Exception:
                    target = ""
                hits += [h for h in matcher.match(target) if h not in hits]
            for hit, sev, cat in hits:
                st = file_stat(p)
                findings.append(Finding(
                    title=f"{hit} — след в «Недавние документы» ({base})",
                    severity=sev, category=sig.CAT_TRACE,
                    detail="Ярлык/запись о недавно открытом файле с сигнатурой чита.",
                    path=p, evidence=[f"Запись: {p}", f"Изменена: {fmt_time(st['mtime'])}"]))


# ---------------------------------------------------------------------------
def registry_traces(matcher, findings):
    try:
        import winreg
    except ImportError:
        return

    def walk_values(hive, subkey, decode_rot13=False, label=""):
        out = []
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    text = name
                    if decode_rot13:
                        text = _rot13(name)
                    out.append((text, str(value)[:200]))
        except OSError:
            pass
        return out

    sources = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", False, "RunMRU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched", False, "AppSwitched"),
        (winreg.HKEY_CURRENT_USER, r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", False, "MUICache"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", False, "CompatStore"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", False, "OpenSaveMRU"),
    ]
    for hive, path, rot, label in sources:
        for name, value in walk_values(hive, path, rot, label):
            for hit, sev, cat in matcher.match(name + " " + value):
                findings.append(Finding(
                    title=f"{hit} — след в реестре ({label})",
                    severity=sev, category=sig.CAT_TRACE,
                    detail="Windows сохранила запись о запуске/открытии файла. Удаление файла её не стирает.",
                    path=path, evidence=[f"Ключ: {label}", f"Запись: {name[:300]}"]))

    # UserAssist — имена в ROT13
    ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua) as key:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                for name, _ in walk_values(winreg.HKEY_CURRENT_USER,
                                           ua + "\\" + guid + r"\Count", True, "UserAssist"):
                    for hit, sev, cat in matcher.match(name):
                        findings.append(Finding(
                            title=f"{hit} — след в UserAssist",
                            severity=sev, category=sig.CAT_TRACE,
                            detail="UserAssist хранит историю запусков программ пользователем.",
                            path=ua, evidence=[f"Запись: {name[:300]}"]))
    except OSError:
        pass

    # BAM — время последнего запуска исполняемых файлов
    for base in (r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                 r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    i += 1
                    for name, _ in walk_values(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sid):
                        for hit, sev, cat in matcher.match(name):
                            findings.append(Finding(
                                title=f"{hit} — запускался (BAM)",
                                severity=sev, category=sig.CAT_TRACE,
                                detail="Служба BAM фиксирует запуск программ с точным временем.",
                                path=base, evidence=[f"Путь: {name[:300]}"]))
        except OSError:
            continue


def _rot13(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
def usn_journal(matcher, findings, enabled=True):
    """Журнал USN помнит имена всех созданных/удалённых файлов тома."""
    if not enabled:
        return
    out = run_cmd(["fsutil", "usn", "readjournal", "C:", "csv"],
                  timeout=45, max_output=48 * 1024 * 1024)
    if not out.strip():
        findings.append(Finding(
            title="Журнал USN недоступен",
            severity="info", category=sig.CAT_SYS,
            detail="Нужны права администратора. Журнал показывает имена удалённых файлов.",
            path="C:"))
        return
    seen = set()
    for line in out.splitlines():
        low = line.lower()
        if ".jar" not in low and ".exe" not in low and ".dll" not in low:
            continue
        for hit, sev, cat in matcher.match(line):
            key = (hit, line[:120])
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"{hit} — запись в журнале USN",
                severity=sev, category=sig.CAT_TRACE,
                detail="Файловая система зафиксировала операцию с этим файлом (создание/удаление).",
                path="C:", evidence=[line[:400]]))
            if len(seen) > 200:
                return


def journal_deleted(findings):
    out = run_cmd(["fsutil", "usn", "queryjournal", "C:"], timeout=30)
    if out and "Идентификатор" not in out and "Journal ID" not in out and "ID" not in out:
        findings.append(Finding(
            title="Журнал USN отсутствует или был удалён",
            severity="high", category=sig.CAT_CLEANER,
            detail="Удаление журнала (fsutil usn deletejournal) стирает историю файловых операций — "
                   "классический способ спрятать следы перед проверкой.",
            path="C:", evidence=[out[:300] or "пустой ответ"]))


# ---------------------------------------------------------------------------
def usb_history(matcher, findings):
    """
    Все USB-накопители, которые когда-либо подключались, — даже если сейчас
    отключены. Windows хранит их в реестре USBSTOR: модель, серийник, время.
    """
    try:
        import winreg
    except ImportError:
        return
    devices = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Enum\USBSTOR") as key:
            i = 0
            while True:
                try:
                    cls = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                # cls вида Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00
                model = cls.replace("Disk&", "").replace("Ven_", "").replace("Prod_", " ")\
                           .replace("Rev_", " rev ").replace("&", " ").strip()
                try:
                    with winreg.OpenKey(key, cls) as sub:
                        j = 0
                        while True:
                            try:
                                serial = winreg.EnumKey(sub, j)
                            except OSError:
                                break
                            j += 1
                            friendly = model
                            try:
                                with winreg.OpenKey(sub, serial) as inst:
                                    friendly = winreg.QueryValueEx(inst, "FriendlyName")[0]
                            except OSError:
                                pass
                            devices.append((friendly, model, serial))
                except OSError:
                    continue
    except OSError:
        return

    if devices:
        ev = [f"{fr}  (серийник: {ser[:40]})" for fr, mdl, ser in devices[:40]]
        findings.append(Finding(
            title=f"История USB-накопителей: {len(devices)} устройств",
            severity="info", category=sig.CAT_SYS,
            detail="Все флешки и внешние диски, подключавшиеся к этому компьютеру. "
                   "Если чит запускали с флешки, она осталась в списке даже после отключения.",
            path=r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            evidence=ev))


# ---------------------------------------------------------------------------
def scan(progress, deep_usn=True):
    matcher = SignatureMatcher()
    findings = []
    progress.step(0.76, "Корзина и следы удалённых файлов…")
    recycle_bin(matcher, findings)
    progress.step(0.79, "История запуска программ (Prefetch)…")
    prefetch(matcher, findings)
    progress.step(0.82, "Недавние документы и JumpLists…")
    recent_and_jumplists(matcher, findings)
    progress.step(0.85, "Реестр: BAM / UserAssist / MUICache…")
    registry_traces(matcher, findings)
    progress.step(0.87, "История подключённых USB-накопителей…")
    usb_history(matcher, findings)
    progress.step(0.89, "Журнал файловой системы USN…")
    journal_deleted(findings)
    usn_journal(matcher, findings, enabled=deep_usn)
    return findings, {}

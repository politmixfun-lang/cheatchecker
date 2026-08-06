# -*- coding: utf-8 -*-
"""Оркестратор проверки: выбирает набор сканеров под текущую ОС и собирает отчёт."""

from __future__ import annotations

import os
import time

from . import platform_info as pi
from . import signatures as sig
from .report import Report
from .utils import Progress, Finding, exclude_path
from .scanners import files as files_scanner
from .scanners import minecraft as mc_scanner
from .scanners import processes as proc_scanner


def run_check(player: str, admin: str, cfg: dict, progress_cb=None) -> Report:
    progress = Progress(progress_cb)
    started = time.time()
    findings, stats = [], {}

    rep_dir = cfg.get("report", {}).get("dir", "")
    if rep_dir and os.path.isabs(rep_dir):
        exclude_path(rep_dir)

    scan_cfg = cfg.get("scan", {})
    deep_jars = scan_cfg.get("deep_jar_scan", True)
    max_depth = int(scan_cfg.get("max_depth", 6))
    max_jar_mb = int(scan_cfg.get("max_jar_size_mb", 400))

    # --- 0. Система -------------------------------------------------------
    progress.step(0.02, f"Определяю систему…")
    sysinfo = pi.system_info()
    progress.log(f"Обнаружено: {sysinfo['os_version']}")
    if not sysinfo["admin"]:
        findings.append(Finding(
            title="Чекер запущен без прав администратора",
            severity="info", category=sig.CAT_SYS,
            detail=("Часть системных журналов (Prefetch, USN, BAM в Windows) читается только "
                    "с повышенными правами. Для полной проверки перезапустите от администратора."),
            evidence=[f"Пользователь: {sysinfo['user']}"]))
    jv = pi.java_versions()
    if jv:
        sysinfo["java"] = "; ".join(jv)

    # --- 1. Каталоги игры -------------------------------------------------
    progress.step(0.06, "Ищу установки Minecraft…")
    mc_dirs = list(pi.minecraft_dirs())
    if mc_dirs:
        findings.append(Finding(
            title=f"Найдено установок Minecraft: {len(mc_dirs)}",
            severity="info", category=sig.CAT_MC,
            detail="Все эти каталоги проверены отдельно.",
            evidence=mc_dirs[:20]))
    else:
        findings.append(Finding(
            title="Каталоги Minecraft не найдены",
            severity="medium", category=sig.CAT_MC,
            detail="Игра не установлена в стандартных местах либо папку перенесли/удалили.",
            evidence=["Проверены стандартные пути для " + sysinfo["os"]]))

    # --- 2. Файловая система ---------------------------------------------
    roots = pi.scan_roots(cfg)
    roots += [(p, 6) for p in scan_cfg.get("extra_paths", []) if p and os.path.isdir(p)]
    progress.step(0.10, f"Сканирую диск ({len(roots)} корней)…")
    f, s = files_scanner.scan_filesystem(
        roots, progress, deep_jars=deep_jars, max_depth=max_depth, max_jar_mb=max_jar_mb,
        time_budget=int(scan_cfg.get("time_budget", 330)),
        max_findings=int(scan_cfg.get("max_findings", 5000)))
    findings += f
    stats.update({"каталогов": s["dirs"], "файлов": s["files"],
                  "jar-файлов": s["jars"], "маскировок": s["disguised"]})
    if s.get("stopped"):
        findings.append(Finding(
            title=f"Обход диска остановлен: {s['stopped']}",
            severity="info", category=sig.CAT_SYS,
            detail="Сканирование прервано по защитному лимиту, часть каталогов не просмотрена. "
                   "Увеличьте лимиты в config.json (scan.time_budget) или проверьте вручную.",
            evidence=[f"Просмотрено каталогов: {s['dirs']}, файлов: {s['files']}"]))

    # --- 3. Minecraft -----------------------------------------------------
    progress.step(0.55, "Проверяю папки Minecraft…")
    f, s = mc_scanner.scan_minecraft(mc_dirs, progress, deep_jars=deep_jars, max_jar_mb=max_jar_mb)
    findings += f
    stats.update({"модов": s["mods"], "версий": s["versions"], "ресурспаков": s["packs"]})

    # --- 4. Процессы ------------------------------------------------------
    f, s = proc_scanner.scan_processes(progress)
    findings += f
    stats.update({"процессов": s.get("processes", 0)})

    # --- 5. Следы удалённых файлов (зависит от ОС) ------------------------
    progress.step(0.75, "Ищу следы удалённых читов…")
    try:
        if pi.WINDOWS:
            from .scanners import traces_windows as tw
            f, _ = tw.scan(progress, deep_usn=scan_cfg.get("usn_journal", True))
            findings += f
        elif pi.MACOS:
            from .scanners import traces_macos as tm
            f, _ = tm.scan(progress, deep_spotlight=scan_cfg.get("spotlight", True))
            findings += f
        else:
            progress.log("Linux: расширенный поиск следов недоступен, проверены только файлы.")
    except Exception as exc:
        findings.append(Finding(
            title="Ошибка при поиске следов",
            severity="info", category=sig.CAT_SYS,
            detail="Часть проверок не выполнилась.", evidence=[repr(exc)]))

    # --- 6. Время проверки vs изменения файлов ---------------------------
    progress.step(0.92, "Сверяю время изменений…")
    findings += _recent_activity(findings, started)

    progress.step(0.96, "Формирую отчёт…")
    findings = _dedup(findings)
    _classify(findings)
    findings = _group(findings)
    finished = time.time()
    return Report(player, admin, sysinfo, findings, stats, started, finished)


def _dedup(findings):
    """Один и тот же файл видят несколько сканеров — оставляем самую содержательную находку."""
    best, order = {}, []
    for f in findings:
        name = f.title.split(" — ")[0].strip()
        key = (os.path.normcase(f.path or ""), name, f.category)
        prev = best.get(key)
        if prev is None:
            best[key] = f
            order.append(key)
        elif (f.weight, len(f.evidence)) > (prev.weight, len(prev.evidence)):
            best[key] = f
    return [best[k] for k in order]


def _recent_activity(findings, started, window_min=30):
    """Если читерский файл трогали прямо перед проверкой — это важный сигнал."""
    out = []
    hot = []
    for f in findings:
        if f.weight < 3 or not f.path or not os.path.exists(f.path):
            continue
        try:
            mtime = os.path.getmtime(f.path)
        except OSError:
            continue
        age = (started - mtime) / 60
        if 0 <= age <= window_min:
            hot.append(f"{f.title} — изменён {age:.0f} мин назад ({f.path})")
    if hot:
        out.append(Finding(
            title=f"Файлы трогали прямо перед проверкой ({len(hot)})",
            severity="high", category=sig.CAT_TRACE,
            detail=f"Эти объекты изменялись в последние {window_min} минут — "
                   "вероятна попытка спрятать или удалить чит перед проверкой.",
            evidence=hot[:20]))
    return out


LOCATION_RU = {"disk": "На компьютере", "deleted": "Удалённые",
               "renamed": "Переименованные", "trace": "Следы"}

_DELETED_MARKS = ("$recycle.bin", "/.trash", "\\.trash", ".trashes")
_REMOVABLE_ROOTS = None


def _is_removable(path):
    """Лежит ли путь на съёмном носителе (USB-флешке)."""
    global _REMOVABLE_ROOTS
    if not path:
        return False
    if _REMOVABLE_ROOTS is None:
        try:
            _REMOVABLE_ROOTS = [r.lower() for r in pi.removable_drives()]
        except Exception:
            _REMOVABLE_ROOTS = []
    low = path.lower()
    return any(low.startswith(r.lower()) for r in _REMOVABLE_ROOTS)


def _classify(findings):
    """Проставляет каждой находке, где именно объект: на диске, удалён, переименован."""
    for f in findings:
        low = (f.path or "").lower()
        title = f.title.lower()

        on_usb = _is_removable(f.path)

        if f.meta.get("renamed") or "замаскированн" in title or "чужим расширением" in title:
            f.location = "renamed"
        elif any(m in low for m in _DELETED_MARKS) or "удалён" in title or "корзин" in title:
            f.location = "deleted"
        elif on_usb and f.path and os.path.exists(f.path):
            f.location = "usb"
        elif f.category == sig.CAT_TRACE:
            f.location = "deleted" if ("удал" in title or "корзин" in title) else "trace"
        elif f.path and os.path.exists(f.path):
            f.location = "disk"
        elif f.path:
            f.location = "deleted"     # путь есть, а файла нет - значит его убрали
        else:
            f.location = "trace"

        # для удалённых вытаскиваем время удаления в отдельное поле
        for e in f.evidence:
            if isinstance(e, str) and e.startswith("Удалён:"):
                f.meta["deleted_at"] = e.split(":", 1)[1].strip()
                break


# Категории, где десяток одинаковых находок - это шум, а не улики
_GROUPABLE = {sig.CAT_GREY, sig.CAT_MACRO, sig.CAT_SYS, sig.CAT_PROC, sig.CAT_MC}


def _group(findings, min_group=3):
    """
    Схлопывает повторы одной сигнатуры в одну находку со списком путей.

    Двадцать строк «Logitech G HUB» по разным файлам ничего не добавляют —
    админу нужен один пункт со списком, а не двадцать одинаковых карточек.
    """
    buckets, order = {}, []
    for f in findings:
        name = f.title.split(" — ")[0].strip()
        key = (name, f.category, f.severity, f.location)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(f)

    out = []
    for key in order:
        group = buckets[key]
        name, category, severity, location = key
        threshold = min_group if category in _GROUPABLE else min_group * 2
        if len(group) < threshold:
            out.extend(group)
            continue
        paths = [g.path or g.title for g in group]
        merged = Finding(
            title=f"{name} — найдено объектов: {len(group)}",
            severity=severity, category=category,
            detail=(group[0].detail or "") + f" Совпадений: {len(group)}, все перечислены ниже.",
            path=group[0].path,
            evidence=[f"{i}. {p}" for i, p in enumerate(paths[:60], 1)]
                     + ([f"… и ещё {len(paths) - 60}"] if len(paths) > 60 else []),
            meta={"grouped": len(group), "paths": paths[:200]})
        merged.location = location
        out.append(merged)
    return out

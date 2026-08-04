# -*- coding: utf-8 -*-
"""Сканер файловой системы: имена файлов/папок + разбор всех найденных .jar."""

from __future__ import annotations

import os
import time

from .. import signatures as sig
from ..utils import (Finding, SignatureMatcher, walk_limited, file_stat,
                     human_size, fmt_time, sha256_file)
from . import jars

INTERESTING_EXTS = {".jar", ".exe", ".dll", ".app", ".dmg", ".pkg", ".zip", ".rar", ".7z",
                    ".ahk", ".lua", ".bat", ".cmd", ".ps1", ".sh", ".command", ".vbs",
                    ".litemod", ".mrpack", ".apk", ".py", ".js"}


def scan_filesystem(roots, progress, deep_jars=True, max_depth=10, max_jar_mb=400,
                    time_budget=330, max_findings=5000, max_deep_jars=8000):
    """
    Возвращает (findings, stats).

    roots — список (путь, глубина) в порядке важности; принимаются и обычные строки.

    Проверка обязана укладываться в отведённое время, поэтому бюджет делится
    между оставшимися корнями динамически: если .minecraft просканировался за
    секунду, весь остаток времени достаётся следующим папкам, а гигантский
    Рабочий стол не может съесть чужое время.
    """
    matcher = SignatureMatcher()
    findings = []
    seen_paths = set()
    stats = {"dirs": 0, "files": 0, "jars": 0, "disguised": 0, "started": time.time(),
             "stopped": "", "skipped": []}
    deep_count = 0

    _hash_budget[0] = HASH_MAX_COUNT
    norm_roots = [(r, max_depth) if isinstance(r, str) else (r[0], min(r[1], max_depth))
                  for r in roots]
    total_roots = max(len(norm_roots), 1)
    deadline = stats["started"] + time_budget

    def out_of_budget():
        if time.time() > deadline:
            stats["stopped"] = "лимит времени"
            return True
        if len(findings) >= max_findings:
            stats["stopped"] = "лимит числа находок"
            return True
        return False

    for i, (root, depth) in enumerate(norm_roots):
        if out_of_budget():
            stats["skipped"] += [r for r, _d in norm_roots[i:]]
            break
        remaining = max(1.0, deadline - time.time())
        per_root_budget = min(110.0, max(4.0, remaining / (total_roots - i)))
        base_pct = 0.10 + 0.45 * (i / total_roots)
        next_pct = 0.10 + 0.45 * ((i + 1) / total_roots)
        progress.step(base_pct, f"Сканирую: {root}")
        root_started = time.time()
        root_dirs = 0

        for dirpath, dirnames, filenames in walk_limited(root, max_depth=depth):
            stats["dirs"] += 1
            root_dirs += 1

            # живой прогресс: без него длинная папка выглядит как зависшая программа
            if root_dirs % 25 == 0:
                spent = time.time() - root_started
                frac = min(0.97, spent / per_root_budget)
                progress.step(base_pct + (next_pct - base_pct) * frac,
                              f"{os.path.basename(root) or root}: {stats['files']} файлов, "
                              f"{stats['jars']} jar · {dirpath[-70:]}")
                if spent > per_root_budget:
                    progress.log(f"«{root}» — слишком большая папка, проверены верхние уровни "
                                 f"({root_dirs} каталогов за {spent:.0f} с)")
                    stats["skipped"].append(root)
                    dirnames[:] = []
                    break
                if out_of_budget():
                    dirnames[:] = []
                    break

            # 1) подозрительные имена папок
            for d in dirnames:
                _check_name(os.path.join(dirpath, d), d, matcher, findings, seen_paths, is_dir=True)

            for fname in filenames:
                stats["files"] += 1
                full = os.path.join(dirpath, fname)
                ext = os.path.splitext(fname)[1].lower()

                # 2) подозрительные имена файлов
                if ext in INTERESTING_EXTS or "." not in fname:
                    _check_name(full, fname, matcher, findings, seen_paths, is_dir=False)

                # 3) глубокий разбор архивов Java
                if ext in (".jar", ".litemod"):
                    stats["jars"] += 1
                    if deep_jars and deep_count < max_deep_jars:
                        deep_count += 1
                        for f in jars.jar_findings(full, deep=True, max_size_mb=max_jar_mb):
                            _add(findings, seen_paths, f)

                # 4) маскировка: jar под другим расширением
                elif ext in (".txt", ".png", ".jpg", ".dat", ".log", ".cfg", ".bin", ".tmp",
                             ".old", ".bak", ".mp4", ".pdf", ".dll", ".exe", "") and \
                        _size_ok(full):
                    if jars.looks_like_jar(full):
                        stats["disguised"] += 1
                        st = file_stat(full)
                        _add(findings, seen_paths, Finding(
                            title=f"Замаскированный Java-архив: «{fname}»",
                            severity="critical", category=sig.CAT_MOD,
                            detail="Внутри файла лежит .jar с классами Java, но расширение другое. "
                                   "Так прячут чит-клиенты от беглого осмотра папки.",
                            path=full,
                            evidence=[f"Размер: {human_size(st['size'])}",
                                      f"Изменён: {fmt_time(st['mtime'])}",
                                      f"Создан: {fmt_time(st['ctime'])}",
                                      f"SHA-256: {sha256_file(full)}"]))
                        for f in jars.jar_findings(full, origin="замаскированный файл",
                                                   deep=True, max_size_mb=max_jar_mb):
                            f.severity = "critical"
                            _add(findings, seen_paths, f)
    stats["elapsed"] = time.time() - stats["started"]
    return findings, stats


def _size_ok(path, min_kb=20, max_mb=400):
    try:
        s = os.path.getsize(path)
        return min_kb * 1024 <= s <= max_mb * 1024 * 1024
    except OSError:
        return False


# Хеширование - самая дорогая операция сканера: гигабайтный файл читается
# целиком. Чит-клиент столько не весит, поэтому хешируем только небольшие
# файлы и ограничиваем общее число хешей за проверку.
HASH_MAX_BYTES = 64 * 1024 * 1024
HASH_MAX_COUNT = 400
_hash_budget = [HASH_MAX_COUNT]


def _maybe_hash(path, size):
    if size > HASH_MAX_BYTES or _hash_budget[0] <= 0:
        return None
    _hash_budget[0] -= 1
    return sha256_file(path, limit_mb=64)


def _check_name(full, name, matcher, findings, seen, is_dir):
    hits = matcher.match(name)
    if not hits:
        return
    st = file_stat(full)
    kind = "Папка" if is_dir else "Файл"
    digest = None if is_dir else _maybe_hash(full, st["size"])
    for sig_name, sev, cat in hits:
        ev = [f"{kind}: {full}",
              f"Изменён: {fmt_time(st['mtime'])}",
              f"Создан: {fmt_time(st['ctime'])}",
              f"Последний доступ: {fmt_time(st['atime'])}"]
        if not is_dir:
            ev.insert(1, f"Размер: {human_size(st['size'])}")
            if digest:
                ev.append(f"SHA-256: {digest}")
        _add(findings, seen, Finding(
            title=f"{sig_name} — совпадение по имени ({name})",
            severity=sev, category=cat,
            detail=f"{kind} на диске совпадает с известной сигнатурой «{sig_name}».",
            path=full, evidence=ev))


def _add(findings, seen, finding: Finding):
    key = (finding.title, finding.path)
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)

# -*- coding: utf-8 -*-
"""
Следы удалённых читов в macOS.

Смотрим: Корзину, базу карантина (что скачивали через браузер), Spotlight (mdfind),
недавние документы, историю оболочки, автозагрузку (LaunchAgents), .app-бандлы.
"""

from __future__ import annotations

import glob
import os
import plistlib
import sqlite3
import time

from .. import signatures as sig
from ..utils import Finding, SignatureMatcher, file_stat, fmt_time, human_size, run_cmd


def trash(matcher, findings):
    home = os.path.expanduser("~")
    roots = [os.path.join(home, ".Trash")] + glob.glob("/Volumes/*/.Trashes/*")
    total = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            p = os.path.join(root, name)
            st = file_stat(p)
            total.append((name, st, p))
            for hit, sev, cat in matcher.match(name):
                findings.append(Finding(
                    title=f"{hit} — лежит в Корзине: {name}",
                    severity=sev, category=sig.CAT_TRACE,
                    detail="Файл с сигнатурой чита не удалён окончательно — он в Корзине.",
                    path=p,
                    evidence=[f"Путь: {p}", f"Размер: {human_size(st['size'])}",
                              f"Изменён: {fmt_time(st['mtime'])}"]))
    if total:
        recent = sorted(total, key=lambda t: t[1]["mtime"], reverse=True)[:25]
        findings.append(Finding(
            title=f"Содержимое Корзины ({len(total)} объектов)",
            severity="info", category=sig.CAT_TRACE,
            detail="Последние перемещённые в Корзину объекты.",
            evidence=[f"{fmt_time(st['mtime'])} | {human_size(st['size'])} | {n}"
                      for n, st, _ in recent]))


def quarantine_db(matcher, findings):
    """LaunchServices помнит всё, что скачивалось через браузер/мессенджер."""
    home = os.path.expanduser("~")
    cands = glob.glob(os.path.join(home, "Library", "Preferences",
                                   "com.apple.LaunchServices.QuarantineEventsV*"))
    cands += glob.glob(os.path.join(home, "Library", "Preferences", "com.apple.LaunchServices",
                                    "com.apple.LaunchServices.QuarantineEventsV*"))
    rows_seen = 0
    for db in cands:
        try:
            con = sqlite3.connect(f"file:{db}?immutable=1", uri=True)
            cur = con.execute(
                "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                "LSQuarantineDataURLString, LSQuarantineOriginURLString "
                "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 3000")
            for ts, agent, url, origin in cur.fetchall():
                rows_seen += 1
                blob = " ".join(str(x or "") for x in (url, origin))
                hits = matcher.match(blob)
                if not hits:
                    continue
                when = fmt_time((ts or 0) + 978307200)  # Core Data epoch -> unix
                for hit, sev, cat in hits:
                    findings.append(Finding(
                        title=f"{hit} — скачивался на этот компьютер",
                        severity=sev, category=sig.CAT_TRACE,
                        detail="Запись в базе карантина macOS: файл был загружен из интернета. "
                               "Запись остаётся даже после удаления файла.",
                        path=db,
                        evidence=[f"Когда: {when}", f"Через: {agent}",
                                  f"Ссылка: {str(url)[:300]}",
                                  f"Страница: {str(origin)[:300]}"]))
            con.close()
        except Exception:
            continue
    if not rows_seen and cands:
        findings.append(Finding(
            title="База карантина пуста",
            severity="medium", category=sig.CAT_CLEANER,
            detail="История загрузок из интернета отсутствует — возможно, её очистили.",
            path=cands[0]))


def spotlight(matcher, findings, progress, budget=30.0):
    """
    Поиск по всему диску через индекс Spotlight, включая внешние тома.

    Имена собираются в один запрос пачками: 150 отдельных вызовов mdfind
    занимали бы минуты, а один запрос с OR отрабатывает за доли секунды.
    """
    names = set()
    for group in (sig.CLIENTS, sig.CHEAT_MODS, sig.INJECTORS, sig.MACRO_TOOLS):
        for data in group.values():
            for a in data.get("aliases", []):
                if len(a) >= 5 and " " not in a and a.isascii():
                    names.add(a)
    names = sorted(names)
    chunks = [names[i:i + 25] for i in range(0, len(names), 25)]
    matched = {}
    started = time.time()

    for i, chunk in enumerate(chunks):
        if time.time() - started > budget:
            progress.log("Spotlight: достигнут лимит времени, проверены не все имена")
            break
        progress.step(0.80 + 0.05 * (i / max(len(chunks), 1)),
                      f"Spotlight: поиск по диску ({i * 25}/{len(names)} имён)")
        query = " || ".join(f'kMDItemFSName == "*{t}*"c' for t in chunk)
        out = run_cmd(["mdfind", query], timeout=12)
        for line in out.splitlines():
            line = line.strip()
            if not line or "/mine checker" in line.lower():
                continue
            for hit, sev, cat in matcher.match(os.path.basename(line)):
                matched.setdefault((hit, sev, cat), set()).add(line)
    for (hit, sev, cat), paths in matched.items():
        plist = sorted(paths)[:12]
        findings.append(Finding(
            title=f"{hit} — найден через Spotlight ({len(paths)} шт.)",
            severity=sev, category=cat,
            detail="Поиск по всему диску (включая внешние носители) нашёл объекты с этим именем.",
            path=plist[0],
            evidence=[f"{p} | изменён {fmt_time(file_stat(p)['mtime'])}" for p in plist]))


def recent_items(matcher, findings):
    home = os.path.expanduser("~")
    patterns = [
        os.path.join(home, "Library", "Application Support", "com.apple.sharedfilelist", "*"),
        os.path.join(home, "Library", "Preferences", "com.apple.recentitems.plist"),
    ]
    for pattern in patterns:
        for p in glob.glob(pattern):
            try:
                raw = open(p, "rb").read(400_000)
            except Exception:
                continue
            text = raw.decode("utf-8", "ignore") + " " + raw.decode("utf-16-le", "ignore")
            for hit, sev, cat in matcher.match(text):
                findings.append(Finding(
                    title=f"{hit} — след в списке недавних файлов",
                    severity=sev, category=sig.CAT_TRACE,
                    detail="macOS сохранила запись о недавно открытом файле.",
                    path=p, evidence=[f"Файл списка: {p}",
                                      f"Изменён: {fmt_time(file_stat(p)['mtime'])}"]))


def shell_history(matcher, findings):
    home = os.path.expanduser("~")
    for name in (".zsh_history", ".bash_history", ".zsh_sessions"):
        p = os.path.join(home, name)
        if not os.path.isfile(p):
            continue
        try:
            text = open(p, encoding="utf-8", errors="replace").read()[-400_000:]
        except Exception:
            continue
        interesting = []
        for line in text.splitlines():
            low = line.lower()
            if any(w in low for w in ("rm -rf", "srm ", "shred", "xattr -d", "mdutil",
                                      "codesign --remove", "java -javaagent", "sudo rm")):
                interesting.append(line.strip()[:200])
            for hit, sev, cat in matcher.match(line):
                findings.append(Finding(
                    title=f"{hit} — упоминание в истории терминала",
                    severity=sev, category=sig.CAT_TRACE,
                    detail="Команда с сигнатурой чита сохранилась в истории оболочки.",
                    path=p, evidence=[line.strip()[:300]]))
        if interesting:
            findings.append(Finding(
                title="Команды удаления/зачистки в истории терминала",
                severity="high", category=sig.CAT_CLEANER,
                detail="В истории есть команды безвозвратного удаления или снятия атрибутов.",
                path=p, evidence=interesting[-15:]))


def launch_agents(matcher, findings):
    for root in (os.path.expanduser("~/Library/LaunchAgents"),
                 "/Library/LaunchAgents", "/Library/LaunchDaemons"):
        if not os.path.isdir(root):
            continue
        for name in os.listdir(root):
            p = os.path.join(root, name)
            try:
                with open(p, "rb") as f:
                    data = plistlib.load(f)
                blob = str(data)
            except Exception:
                blob = name
            for hit, sev, cat in matcher.match(name + " " + blob):
                findings.append(Finding(
                    title=f"{hit} — в автозагрузке macOS ({name})",
                    severity=sev, category=sig.CAT_SYS,
                    detail="Объект с сигнатурой чита стартует вместе с системой.",
                    path=p, evidence=[blob[:400]]))


def sip_and_gatekeeper(findings):
    csr = run_cmd(["csrutil", "status"]).strip()
    if "disabled" in csr.lower():
        findings.append(Finding(
            title="SIP отключён",
            severity="high", category=sig.CAT_SYS,
            detail="Защита целостности системы выключена. Это позволяет инжектить код в процессы "
                   "и часто делается ради читов.",
            evidence=[csr]))
    gk = run_cmd(["spctl", "--status"]).strip()
    if "disabled" in gk.lower():
        findings.append(Finding(
            title="Gatekeeper отключён",
            severity="medium", category=sig.CAT_SYS,
            detail="Разрешён запуск неподписанных приложений из любых источников.",
            evidence=[gk]))


def scan(progress, deep_spotlight=True):
    matcher = SignatureMatcher()
    findings = []
    progress.step(0.76, "Корзина macOS…")
    trash(matcher, findings)
    progress.step(0.78, "История загрузок (карантин)…")
    quarantine_db(matcher, findings)
    if deep_spotlight:
        spotlight(matcher, findings, progress)
    progress.step(0.86, "Недавние файлы…")
    recent_items(matcher, findings)
    progress.step(0.88, "История терминала и автозагрузка…")
    shell_history(matcher, findings)
    launch_agents(matcher, findings)
    sip_and_gatekeeper(findings)
    return findings, {}

# -*- coding: utf-8 -*-
"""Запущенные процессы: сам чит, инжектор, автокликер, java-агент в командной строке."""

from __future__ import annotations

from .. import platform_info as pi
from .. import signatures as sig
from ..utils import Finding, SignatureMatcher, run_cmd, SELF_DIR

PS_CMD = ("Get-CimInstance Win32_Process | "
          "Select-Object ProcessId,Name,ExecutablePath,CommandLine | "
          "ConvertTo-Csv -NoTypeInformation")


def list_processes():
    """[(pid, имя, командная строка)]"""
    rows = []
    if pi.WINDOWS:
        out = run_cmd(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS_CMD],
                      timeout=45)
        import csv
        import io
        try:
            for r in csv.DictReader(io.StringIO(out)):
                rows.append((r.get("ProcessId", "?"), r.get("Name", ""),
                             (r.get("CommandLine") or r.get("ExecutablePath") or "")))
        except Exception:
            pass
        if not rows:  # запасной путь
            out = run_cmd(["tasklist", "/FO", "CSV"], timeout=30)
            for line in out.splitlines()[1:]:
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    rows.append((parts[1], parts[0], parts[0]))
    else:
        out = run_cmd(["ps", "-axo", "pid=,comm=,args="], timeout=30)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) == 3:
                rows.append((parts[0], parts[1].split("/")[-1], parts[2]))
    return rows


def scan_processes(progress):
    progress.step(0.72, "Проверяю запущенные процессы…")
    matcher = SignatureMatcher()
    findings = []
    rows = list_processes()

    for pid, name, cmdline in rows:
        if SELF_DIR in cmdline:
            continue   # не детектим сам чекер
        if not name and cmdline:
            name = cmdline.split()[0].replace("\\", "/").split("/")[-1]
        haystack = f"{name} {cmdline}"
        for hit, sev, cat in matcher.match(haystack):
            findings.append(Finding(
                title=f"{hit} — запущенный процесс ({name})",
                severity=sev, category=sig.CAT_PROC,
                detail="Программа работает прямо сейчас.",
                path=name,
                evidence=[f"PID: {pid}", f"Имя: {name}", f"Командная строка: {cmdline[:600]}"]))

        low = cmdline.lower()
        for bad in sig.BAD_JVM_ARGS:
            if bad in low:
                findings.append(Finding(
                    title=f"Инъекция в запущенной игре: {bad}",
                    severity="critical", category=sig.CAT_INJECT,
                    detail="Java запущена с подключением внешнего кода — так работает ghost-клиент.",
                    path=name, evidence=[f"PID: {pid}", f"Командная строка: {cmdline[:800]}"]))
                break

        if ("java" in name.lower() or "javaw" in low) and ".minecraft" not in low and "minecraft" in low:
            pass  # обычный запуск, шум не создаём

    # java-процессы отдельно — админу полезно видеть, откуда запущена игра
    java_procs = [f"PID {p} | {n} | {c[:400]}" for p, n, c in rows
                  if "java" in n.lower() or "minecraft" in c.lower()]
    if java_procs:
        findings.append(Finding(
            title=f"Java/Minecraft процессы ({len(java_procs)})",
            severity="info", category=sig.CAT_PROC,
            detail="Полные строки запуска игры — проверьте путь к клиенту и аргументы вручную.",
            path="", evidence=java_procs[:15]))
    return findings, {"processes": len(rows)}

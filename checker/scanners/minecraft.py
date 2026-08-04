# -*- coding: utf-8 -*-
"""Прицельная проверка каталогов Minecraft: моды, версии, профили, ресурспаки, логи."""

from __future__ import annotations

import glob
import gzip
import json
import os
import re

from .. import signatures as sig
from ..utils import (Finding, SignatureMatcher, file_stat, fmt_time, human_size,
                     sha256_file, normalize)
from . import jars


def scan_minecraft(mc_dirs, progress, deep_jars=True, max_jar_mb=400):
    matcher = SignatureMatcher()
    findings = []
    stats = {"dirs": len(mc_dirs), "mods": 0, "versions": 0, "packs": 0}

    for i, mc in enumerate(mc_dirs):
        progress.step(0.55 + 0.15 * (i / max(len(mc_dirs), 1)), f"Minecraft: {mc}")
        findings += _scan_mods(mc, matcher, stats, deep_jars, max_jar_mb)
        findings += _scan_versions(mc, matcher, stats, deep_jars, max_jar_mb)
        findings += _scan_profiles(mc)
        findings += _scan_resourcepacks(mc, matcher, stats)
        findings += _scan_options(mc)
        findings += _scan_logs(mc)
        findings += _scan_empty_traces(mc)
    return findings, stats


# ---------------------------------------------------------------------------
def _iter_mod_dirs(mc):
    """mods/, а также mods/<версия>/ и инстансы Prism/MultiMC/CurseForge."""
    cands = [os.path.join(mc, "mods"), os.path.join(mc, "coremods")]
    cands += glob.glob(os.path.join(mc, "instances", "*", ".minecraft", "mods"))
    cands += glob.glob(os.path.join(mc, "instances", "*", "minecraft", "mods"))
    cands += glob.glob(os.path.join(mc, "*", "mods"))
    out = []
    for c in cands:
        if os.path.isdir(c):
            out.append(c)
            for sub in glob.glob(os.path.join(c, "*")):
                if os.path.isdir(sub):
                    out.append(sub)
    return list(dict.fromkeys(out))


def _scan_mods(mc, matcher, stats, deep, max_jar_mb):
    found = []
    for mods_dir in _iter_mod_dirs(mc):
        try:
            entries = os.listdir(mods_dir)
        except OSError:
            continue
        for name in entries:
            path = os.path.join(mods_dir, name)
            if not os.path.isfile(path):
                continue
            stats["mods"] += 1
            ext = os.path.splitext(name)[1].lower()
            if ext in (".jar", ".litemod") and deep:
                found += jars.jar_findings(path, origin="папка mods", deep=True,
                                           max_size_mb=max_jar_mb)
            elif ext not in (".jar", ".litemod", ".txt", ".json", ".disabled"):
                if jars.looks_like_jar(path):
                    found.append(Finding(
                        title=f"Мод с чужим расширением в mods: «{name}»",
                        severity="critical", category=sig.CAT_MOD,
                        detail="В папке mods лежит Java-архив под другим расширением.",
                        path=path, evidence=[f"Размер: {human_size(file_stat(path)['size'])}",
                                             f"SHA-256: {sha256_file(path)}"]))
                    found += jars.jar_findings(path, origin="mods (маскировка)", deep=True,
                                               max_size_mb=max_jar_mb)
            if ext == ".disabled" or name.lower().endswith(".jar.disabled"):
                found.append(Finding(
                    title=f"Отключённый мод: «{name}»",
                    severity="low", category=sig.CAT_MC,
                    detail="Мод отключён переименованием — возможно, спрятан перед проверкой.",
                    path=path, evidence=[f"Изменён: {fmt_time(file_stat(path)['mtime'])}"]))
            for hit, sev, cat in matcher.match(name):
                found.append(Finding(
                    title=f"{hit} — мод в папке mods ({name})",
                    severity=sev, category=cat,
                    detail="Имя файла в папке модов совпадает с сигнатурой чита.",
                    path=path,
                    evidence=[f"Размер: {human_size(file_stat(path)['size'])}",
                              f"Изменён: {fmt_time(file_stat(path)['mtime'])}",
                              f"SHA-256: {sha256_file(path)}"]))
    return found


# ---------------------------------------------------------------------------
def _scan_versions(mc, matcher, stats, deep, max_jar_mb):
    found = []
    vroot = os.path.join(mc, "versions")
    if not os.path.isdir(vroot):
        return found
    try:
        versions = os.listdir(vroot)
    except OSError:
        return found
    for ver in versions:
        vdir = os.path.join(vroot, ver)
        if not os.path.isdir(vdir):
            continue
        stats["versions"] += 1

        for hit, sev, cat in matcher.match(ver):
            found.append(Finding(
                title=f"{hit} — версия игры «{ver}»",
                severity=sev, category=cat,
                detail="Имя версии в .minecraft/versions совпадает с сигнатурой чит-клиента.",
                path=vdir, evidence=[f"Изменена: {fmt_time(file_stat(vdir)['mtime'])}"]))

        jpath = os.path.join(vdir, ver + ".json")
        if os.path.isfile(jpath):
            try:
                data = json.load(open(jpath, encoding="utf-8", errors="replace"))
            except Exception:
                data = {}
            blob = json.dumps(data, ensure_ascii=False).lower()
            main_class = str(data.get("mainClass", ""))
            if main_class and not main_class.startswith(("net.minecraft", "cpw.mods", "net.fabricmc",
                                                         "org.multimc", "net.minecraftforge",
                                                         "io.github.zekerzhayard", "net.neoforged")):
                found.append(Finding(
                    title=f"Нестандартный mainClass в версии «{ver}»",
                    severity="high", category=sig.CAT_MC,
                    detail="Версия запускается через чужой класс — типично для чит-клиентов, "
                           "которые ставят себя отдельной версией.",
                    path=jpath, evidence=[f"mainClass: {main_class}"]))
            for hit, sev, cat in matcher.match(blob[:200000]):
                found.append(Finding(
                    title=f"{hit} — упоминание в версии «{ver}»",
                    severity=sev, category=cat,
                    detail="Сигнатура найдена в JSON-описании версии (библиотеки/аргументы).",
                    path=jpath, evidence=[f"Файл версии: {jpath}"]))
            for bad in sig.BAD_JVM_ARGS:
                if bad in blob:
                    found.append(Finding(
                        title=f"Опасный JVM-аргумент в версии «{ver}»: {bad}",
                        severity="critical", category=sig.CAT_INJECT,
                        detail="Аргумент подключает внешний код к игре (инъекция чита).",
                        path=jpath, evidence=[f"Аргумент: {bad}"]))

        # jar версии + сторонние jar-ы рядом
        for jar in glob.glob(os.path.join(vdir, "*.jar")):
            if deep:
                found += jars.jar_findings(jar, origin=f"versions/{ver}", deep=True,
                                           max_size_mb=max_jar_mb)
    return found


# ---------------------------------------------------------------------------
def _scan_profiles(mc):
    found = []
    for fname in ("launcher_profiles.json", "launcher_accounts.json", "profiles.json"):
        p = os.path.join(mc, fname)
        if not os.path.isfile(p):
            continue
        try:
            raw = open(p, encoding="utf-8", errors="replace").read()
            data = json.loads(raw)
        except Exception:
            continue
        profiles = data.get("profiles", {}) if isinstance(data, dict) else {}
        for pid, prof in (profiles.items() if isinstance(profiles, dict) else []):
            args = str(prof.get("javaArgs", "")) if isinstance(prof, dict) else ""
            name = str(prof.get("name", pid)) if isinstance(prof, dict) else pid
            low = args.lower()
            for bad in sig.BAD_JVM_ARGS:
                if bad in low:
                    found.append(Finding(
                        title=f"Инъекция в профиле лаунчера «{name}»",
                        severity="critical", category=sig.CAT_INJECT,
                        detail="В аргументах запуска игры подключается внешний агент/библиотека. "
                               "Через это работает большинство ghost-клиентов.",
                        path=p, evidence=[f"Профиль: {name}", f"javaArgs: {args[:500]}"]))
            gd = str(prof.get("gameDir", "")) if isinstance(prof, dict) else ""
            if gd and ".minecraft" not in gd.lower().replace("/", "\\"):
                found.append(Finding(
                    title=f"Профиль «{name}» указывает на посторонний каталог",
                    severity="medium", category=sig.CAT_MC,
                    detail="Игра запускается из другой папки — там может лежать вторая сборка с читом.",
                    path=p, evidence=[f"gameDir: {gd}"]))
    return found


# ---------------------------------------------------------------------------
XRAY_PACK_WORDS = ("xray", "x-ray", "x_ray", "seethrough", "cave", "oremask", "ores", "рентген")


def _scan_resourcepacks(mc, matcher, stats):
    found = []
    for sub in ("resourcepacks", "texturepacks", "shaderpacks"):
        root = os.path.join(mc, sub)
        if not os.path.isdir(root):
            continue
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for name in entries:
            stats["packs"] += 1
            path = os.path.join(root, name)
            low = normalize(name)
            if any(w.replace("-", "").replace("_", "") in low for w in XRAY_PACK_WORDS):
                found.append(Finding(
                    title=f"Возможный X-Ray ресурспак: «{name}»",
                    severity="high", category=sig.CAT_MOD,
                    detail="Название пака указывает на прозрачные блоки / подсветку руды.",
                    path=path, evidence=[f"Изменён: {fmt_time(file_stat(path)['mtime'])}"]))
            for hit, sev, cat in matcher.match(name):
                found.append(Finding(
                    title=f"{hit} — ресурспак «{name}»",
                    severity=sev, category=cat,
                    detail="Имя ресурспака совпадает с сигнатурой.",
                    path=path, evidence=[path]))
    return found


# ---------------------------------------------------------------------------
def _scan_options(mc):
    found = []
    p = os.path.join(mc, "options.txt")
    if os.path.isfile(p):
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            return found
        m = re.search(r"^gamma:([\-\d.]+)", txt, re.M)
        if m:
            try:
                if float(m.group(1)) > 1.5:
                    found.append(Finding(
                        title=f"Аномальная яркость (gamma={m.group(1)})",
                        severity="medium", category=sig.CAT_MC,
                        detail="Значение выше 1.0 недостижимо через настройки игры — "
                               "правка вручную или мод Fullbright.",
                        path=p, evidence=[f"gamma: {m.group(1)}"]))
            except ValueError:
                pass
        for line in txt.splitlines():
            if line.startswith("key_key.") and "keyboard.unknown" not in line:
                key = line.split(":", 1)[0][8:]
                if any(w in key.lower() for w in ("aura", "fly", "esp", "xray", "click", "hack")):
                    found.append(Finding(
                        title=f"Читерская клавиша в options.txt: {key}",
                        severity="high", category=sig.CAT_MC,
                        detail="Игра сохранила бинд от мода с читерским названием.",
                        path=p, evidence=[line]))
    return found


# ---------------------------------------------------------------------------
def _scan_logs(mc):
    found = []
    logs_dir = os.path.join(mc, "logs")
    files = []
    if os.path.isdir(logs_dir):
        files += glob.glob(os.path.join(logs_dir, "*.log"))
        files += glob.glob(os.path.join(logs_dir, "*.log.gz"))
    files += glob.glob(os.path.join(mc, "crash-reports", "*.txt"))
    files = sorted(files, key=lambda p: file_stat(p)["mtime"], reverse=True)[:40]

    for path in files:
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                    text = f.read(1_500_000)
            else:
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read(1_500_000)
        except Exception:
            continue
        low = text.lower()
        hits = {}
        for kw in sig.LOG_KEYWORDS:
            idx = low.find(kw)
            if idx == -1:
                continue
            line = text[max(0, text.rfind("\n", 0, idx) + 1): text.find("\n", idx)][:300]
            hits.setdefault(kw, line.strip())
        if hits:
            sev = "critical" if any(k in hits for k in
                                    ("wurst", "meteor", "impact", "liquidbounce", "vape",
                                     "killaura", "javaagent", "premain", "nursultan",
                                     "expensive", "rockstar")) else "medium"
            found.append(Finding(
                title=f"Следы чита в логе: {os.path.basename(path)}",
                severity=sev, category=sig.CAT_TRACE,
                detail="Лог игры сохранил упоминание чита. Логи остаются даже после удаления самого чита.",
                path=path,
                evidence=[f"Изменён: {fmt_time(file_stat(path)['mtime'])}"]
                         + [f"[{k}] {v}" for k, v in list(hits.items())[:12]]))
    return found


# ---------------------------------------------------------------------------
def _scan_empty_traces(mc):
    """Признаки того, что папку модов только что почистили."""
    found = []
    mods = os.path.join(mc, "mods")
    if not os.path.isdir(mods):
        return found
    st = file_stat(mods)
    try:
        n = len([x for x in os.listdir(mods) if not x.startswith(".")])
    except OSError:
        return found
    import time
    age_min = (time.time() - st["mtime"]) / 60
    if n == 0 and age_min < 180:
        found.append(Finding(
            title="Папка mods пуста и изменена только что",
            severity="high", category=sig.CAT_TRACE,
            detail=f"Каталог модов пуст, но был изменён {age_min:.0f} мин назад — "
                   "содержимое удалили незадолго до проверки.",
            path=mods, evidence=[f"Изменена: {fmt_time(st['mtime'])}", "Файлов внутри: 0"]))
    elif age_min < 15 and n:
        found.append(Finding(
            title="Папка mods изменена перед самой проверкой",
            severity="medium", category=sig.CAT_TRACE,
            detail=f"Содержимое менялось {age_min:.0f} мин назад.",
            path=mods, evidence=[f"Изменена: {fmt_time(st['mtime'])}", f"Файлов внутри: {n}"]))
    return found

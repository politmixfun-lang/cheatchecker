# -*- coding: utf-8 -*-
"""
Глубокий разбор .jar — главное оружие против переименованных читов.

Что смотрим внутри архива:
  * имена пакетов/классов/ресурсов -> сигнатуры конкретных клиентов;
  * строковые константы в .class -> те же сигнатуры + имена модулей;
  * fabric.mod.json / mods.toml / mcmod.info -> заявленное имя мода;
  * MANIFEST.MF -> Premain-Class/Agent-Class (java-агент = ghost-инъекция);
  * количество найденных читерских модулей -> эвристика для неизвестных читов;
  * признаки обфускации.
"""

from __future__ import annotations

import json
import os
import re
import zipfile

from .. import signatures as sig
from ..utils import Finding, human_size, fmt_time, file_stat, sha256_file, is_whitelisted_jar

MARKERS = sig.marker_index()
_ascii_re = re.compile(rb"[ -~]{4,}")
MAX_ENTRIES = 6000                   # сколько записей архива смотрим
MAX_CLASS_BYTES = 25 * 1024 * 1024   # общий бюджет чтения ради строковых констант
MAX_ENTRY_BYTES = 2 * 1024 * 1024    # потолок на ОДНУ запись архива


def _read_capped(zf, name, cap=MAX_ENTRY_BYTES):
    """
    Читает не больше cap байт распакованной записи.

    zf.read() развернул бы запись целиком: один раздутый .class (или zip-бомба)
    съел бы всю память процесса, поэтому читаем потоком с ограничением.
    """
    try:
        with zf.open(name) as fh:
            return fh.read(cap)
    except Exception:
        return b""


class JarVerdict:
    def __init__(self):
        self.client_hits = {}     # имя клиента -> [где нашли]
        self.modules = set()      # найденные читерские модули
        self.agent = []           # ключи java-агента
        self.declared_name = ""   # имя из fabric.mod.json / mods.toml
        self.obfuscated = False
        self.entry_count = 0
        self.error = ""


def analyze_jar(path: str, max_size_mb: int = 400) -> JarVerdict:
    v = JarVerdict()
    try:
        if os.path.getsize(path) > max_size_mb * 1024 * 1024:
            v.error = "файл слишком большой для глубокого анализа"
            return v
    except OSError:
        pass

    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        v.error = f"не открывается как архив: {e}"
        return v

    read_budget = MAX_CLASS_BYTES
    short_names = 0
    total_classes = 0

    with zf:
        try:
            names = zf.namelist()[:MAX_ENTRIES]
        except Exception as e:
            v.error = str(e)
            return v
        v.entry_count = len(names)

        joined = "\n".join(names).lower()
        for marker, (client, _sev, _cat) in MARKERS.items():
            if marker in joined:
                v.client_hits.setdefault(client, []).append(f"пакет/ресурс: {marker}")

        for mod in sig.HEUR_MODULES:
            if mod in joined:
                v.modules.add(mod)

        for name in names:
            base = os.path.basename(name).lower()
            low = name.lower()

            if low.endswith(".class"):
                total_classes += 1
                stem = os.path.splitext(base)[0]
                if len(stem) <= 2 or re.fullmatch(r"[a-z]{1,3}\d*", stem or ""):
                    short_names += 1

            # метаданные мода
            if base in ("fabric.mod.json", "quilt.mod.json", "mods.toml", "mcmod.info",
                        "neoforge.mods.toml"):
                raw = _read_capped(zf, name, 200_000).decode("utf-8", "replace")
                if not raw:
                    continue
                v.declared_name = v.declared_name or _extract_mod_name(base, raw)
                _scan_text(raw, v, f"метаданные {base}")

            elif base == "manifest.mf":
                raw = _read_capped(zf, name, 100_000).decode("utf-8", "replace")
                low_raw = raw.lower()
                for key in sig.AGENT_MANIFEST_KEYS:
                    if key in low_raw:
                        line = next((l.strip() for l in raw.splitlines() if key in l.lower()), key)
                        v.agent.append(line)
                _scan_text(raw, v, "MANIFEST.MF")

            elif low.endswith((".json", ".txt", ".cfg", ".properties", ".toml", ".yml", ".yaml")):
                if read_budget <= 0:
                    continue
                raw = _read_capped(zf, name, 60_000).decode("utf-8", "replace")
                read_budget -= len(raw)
                _scan_text(raw, v, f"ресурс {name}")

            elif low.endswith(".class") and read_budget > 0:
                data = _read_capped(zf, name)
                read_budget -= len(data)
                text = b"\n".join(_ascii_re.findall(data)[:4000]).decode("ascii", "replace")
                _scan_text(text, v, f"строки в {name}")

    if total_classes >= 40 and short_names / max(total_classes, 1) > 0.55:
        v.obfuscated = True
    return v


def _extract_mod_name(base: str, raw: str) -> str:
    try:
        if base.endswith(".json"):
            data = json.loads(raw)
            return str(data.get("name") or data.get("id") or "")
        m = re.search(r'displayName\s*=\s*"([^"]+)"', raw) or re.search(r'"name"\s*:\s*"([^"]+)"', raw)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _scan_text(text: str, v: JarVerdict, where: str):
    low = text.lower()
    for marker, (client, _s, _c) in MARKERS.items():
        if marker in low:
            hits = v.client_hits.setdefault(client, [])
            if len(hits) < 6:
                hits.append(f"{where}: {marker}")
    for mod in sig.HEUR_MODULES:
        if mod in low:
            v.modules.add(mod)


def jar_findings(path: str, origin: str = "", deep: bool = True, max_size_mb: int = 400):
    """Превращает разбор jar в список находок."""
    out = []
    st = file_stat(path)
    base = os.path.basename(path)
    if not deep:
        return out

    v = analyze_jar(path, max_size_mb=max_size_mb)
    if v.error and not v.client_hits:
        return out

    whitelisted = is_whitelisted_jar(base)
    common = {
        "Файл": path,
        "Размер": human_size(st["size"]),
        "Изменён": fmt_time(st["mtime"]),
        "Создан": fmt_time(st["ctime"]),
        "SHA-256": sha256_file(path, limit_mb=64),
        "Записей в архиве": str(v.entry_count),
    }
    if v.declared_name:
        common["Имя мода внутри"] = v.declared_name
    if origin:
        common["Источник"] = origin

    # 1) точное совпадение внутренних сигнатур конкретного клиента
    real_clients = {c: w for c, w in v.client_hits.items() if c in sig.CLIENTS}
    mod_hits = {c: w for c, w in v.client_hits.items() if c not in sig.CLIENTS}

    for client, where in real_clients.items():
        data = sig.CLIENTS[client]
        renamed = client.lower().split()[0] not in base.lower()
        detail = ("Внутренние сигнатуры клиента найдены в архиве. "
                  + ("ФАЙЛ ПЕРЕИМЕНОВАН: имя не совпадает с содержимым — это попытка скрыть чит."
                     if renamed else "Имя файла совпадает с содержимым."))
        out.append(Finding(
            title=f"{client} — найден внутри файла «{base}»",
            severity=data["sev"], category=data["cat"], detail=detail, path=path,
            evidence=[f"{k}: {val}" for k, val in common.items()] + where[:6],
            meta={"renamed": renamed, "client": client}))

    # читерские функции, привязанные к конкретным модам: группируем, чтобы не шуметь
    if mod_hits and not whitelisted:
        worst = max(mod_hits, key=lambda c: sig.SEVERITY_ORDER[
            (sig.CHEAT_MODS.get(c) or sig.GREY_MODS.get(c) or {"sev": "medium"})["sev"]])
        sev = (sig.CHEAT_MODS.get(worst) or sig.GREY_MODS.get(worst) or {"sev": "medium"})["sev"]
        cat = (sig.CHEAT_MODS.get(worst) or sig.GREY_MODS.get(worst) or {"cat": sig.CAT_MOD})["cat"]
        if len(mod_hits) >= 3:
            out.append(Finding(
                title=f"Читерские функции в «{base}»: {', '.join(sorted(mod_hits))}",
                severity=sev, category=cat,
                detail="В архиве найдены реализации сразу нескольких читерских функций.",
                path=path,
                evidence=[f"{k}: {val}" for k, val in common.items()]
                         + [w for hits in mod_hits.values() for w in hits[:2]][:12]))
        else:
            for name, where in mod_hits.items():
                d = sig.CHEAT_MODS.get(name) or sig.GREY_MODS.get(name) or {"sev": sev, "cat": cat}
                out.append(Finding(
                    title=f"{name} — найден внутри файла «{base}»",
                    severity=d["sev"], category=d["cat"],
                    detail="Внутренние сигнатуры найдены в архиве.",
                    path=path,
                    evidence=[f"{k}: {val}" for k, val in common.items()] + where[:6]))

    # 2) эвристика: набор читерских модулей при неизвестном имени
    if not real_clients and len(v.modules) >= sig.HEUR_THRESHOLD and not whitelisted:
        strong = len(v.modules) >= sig.HEUR_THRESHOLD_STRONG
        mods = sorted(v.modules)
        out.append(Finding(
            title=f"Неизвестный чит-клиент в «{base}» ({len(mods)} читерских модулей)",
            severity="critical" if strong else "high",
            category=sig.CAT_CLIENT,
            detail=("В архиве найдены названия читерских функций, хотя в базе такого клиента нет. "
                    "Так выглядят приватные, новые или переименованные читы."),
            path=path,
            evidence=[f"{k}: {val}" for k, val in common.items()]
                     + ["Модули: " + ", ".join(mods[:30])],
            meta={"modules": mods}))

    # 3) java-агент
    if v.agent and not whitelisted:
        out.append(Finding(
            title=f"Java-агент в «{base}» (инъекция в игру)",
            severity="critical", category=sig.CAT_INJECT,
            detail=("В манифесте объявлен Premain/Agent-Class. Такой .jar подключается к уже "
                    "запущенной игре через -javaagent и подменяет код — типичный ghost-клиент."),
            path=path,
            evidence=[f"{k}: {val}" for k, val in common.items()] + v.agent[:6]))

    # 4) обфускация без легитимной причины
    if v.obfuscated and not whitelisted and not v.client_hits:
        out.append(Finding(
            title=f"Обфусцированный .jar «{base}»",
            severity="medium", category=sig.CAT_MOD,
            detail="Классы имеют однобуквенные имена — архив умышленно запутан. "
                   "Обычные моды так не собирают; требуется ручная проверка.",
            path=path,
            evidence=[f"{k}: {val}" for k, val in common.items()]))
    return out


def looks_like_jar(path: str) -> bool:
    """Файл — ZIP с .class внутри, но расширение НЕ архивное => маскировка."""
    ext = os.path.splitext(path)[1].lower()
    if ext in sig.ARCHIVE_EXTS:
        return False
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"PK\x03\x04":
                return False
    except Exception:
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()[:600]
        return any(n.lower().endswith(".class") for n in names)
    except Exception:
        return False

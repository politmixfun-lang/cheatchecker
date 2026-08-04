# -*- coding: utf-8 -*-
"""Общие утилиты: находки, нормализация имён, матчер сигнатур, безопасный обход ФС."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime

from . import signatures as sig

# Алиасы короче этой длины ищем только по границам слова -> меньше ложных срабатываний
STRICT_LEN = 8
_norm_re = re.compile(r"[^a-z0-9а-яё]+")

# Собственный каталог чекера: он содержит базу сигнатур и отчёты с именами читов,
# поэтому исключается из проверки, иначе чекер найдёт сам себя.
SELF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXCLUDED = [SELF_DIR]


def exclude_path(path: str):
    if path:
        _EXCLUDED.append(os.path.abspath(path))


def is_self_path(path: str) -> bool:
    if not path:
        return False
    try:
        ap = os.path.abspath(path)
    except Exception:
        return False
    return any(ap == ex or ap.startswith(ex + os.sep) for ex in _EXCLUDED)


def normalize(text: str) -> str:
    return _norm_re.sub("", (text or "").lower())


def human_size(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} ГБ"


def fmt_time(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return "—"


@dataclass
class Finding:
    title: str                       # что нашли
    severity: str                    # critical/high/medium/low/info
    category: str                    # к какой группе относится
    detail: str = ""                 # пояснение для админа
    path: str = ""                   # где найдено
    evidence: list = field(default_factory=list)   # доказательства (строки)
    meta: dict = field(default_factory=dict)

    @property
    def weight(self) -> int:
        return sig.SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return asdict(self)


class SignatureMatcher:
    """Сопоставление произвольной строки (имя файла, процесса, ключ реестра) с базой."""

    def __init__(self):
        self.plain = []   # (needle, name, sev, cat)  - подстрока в нормализованном виде
        self.strict = []  # (regex,  name, sev, cat)  - по границам слова
        for group in sig.all_signature_groups():
            for name, data in group.items():
                for alias in data.get("aliases", []):
                    a = alias.lower().strip()
                    if len(a) >= STRICT_LEN and " " not in a:
                        self.plain.append((normalize(a), name, data["sev"], data["cat"]))
                    else:
                        pattern = re.escape(a).replace(r"\ ", r"[\s._\-]*")
                        self.strict.append((
                            re.compile(r"(?<![a-zа-яё0-9])" + pattern + r"(?![a-zа-яё0-9])", re.I),
                            name, data["sev"], data["cat"],
                        ))
        self.launchers = [l.lower() for l in sig.LAUNCHERS]

    def match(self, text: str):
        """Возвращает список (имя, severity, категория) для всех совпавших сигнатур."""
        if not text:
            return []
        low = text.lower()
        norm = normalize(text)
        hits, seen = [], set()
        for needle, name, sev, cat in self.plain:
            if needle and needle in norm and name not in seen:
                seen.add(name)
                hits.append((name, sev, cat))
        for rx, name, sev, cat in self.strict:
            if name not in seen and rx.search(low):
                seen.add(name)
                hits.append((name, sev, cat))
        return hits

    def match_launcher(self, text: str):
        low = (text or "").lower()
        return [l for l in self.launchers if l in low]


def is_whitelisted_jar(filename: str) -> bool:
    low = os.path.basename(filename or "").lower()
    return any(low.startswith(p) for p in sig.WHITELIST_JAR_PREFIXES)


def sha256_file(path: str, limit_mb: int = 200) -> str:
    """SHA-256 файла (для файлов больше limit_mb - хеш первых limit_mb)."""
    h = hashlib.sha256()
    try:
        size = os.path.getsize(path)
        cap = limit_mb * 1024 * 1024
        with open(path, "rb") as f:
            read = 0
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
                if read >= cap:
                    break
        return h.hexdigest() + ("" if size <= cap else " (первые %d МБ)" % limit_mb)
    except Exception:
        return "—"


def walk_limited(root: str, max_depth: int = 6, max_entries: int = 400_000, follow_links=False):
    """Обход каталога с ограничением глубины и пропуском системного/приватного мусора."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return
    base_depth = root.rstrip(os.sep).count(os.sep)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=follow_links):
        if is_self_path(dirpath):
            dirnames[:] = []
            continue
        depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in sig.SKIP_DIR_NAMES and not d.startswith("$")
                       and not is_self_path(os.path.join(dirpath, d))]
        yield dirpath, dirnames, filenames
        count += len(filenames) + len(dirnames)
        if count > max_entries:
            return


def file_stat(path: str) -> dict:
    try:
        st = os.stat(path)
        return {
            "size": st.st_size,
            "mtime": st.st_mtime,
            "ctime": getattr(st, "st_birthtime", st.st_ctime),
            "atime": st.st_atime,
        }
    except Exception:
        return {"size": 0, "mtime": 0, "ctime": 0, "atime": 0}


def run_cmd(args, timeout=25, shell=False, max_output=32 * 1024 * 1024):
    """
    Тихий запуск команды, возвращает stdout (или '').

    max_output обязателен: например `fsutil usn readjournal` на большом диске
    отдаёт гигабайты, и без потолка процесс просто съест всю память.
    """
    try:
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kwargs["startupinfo"] = si
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        proc = subprocess.Popen(args, shell=shell, **kwargs)
        deadline = time.time() + timeout
        chunks, total = [], 0
        try:
            while True:
                if time.time() > deadline:
                    proc.kill()
                    break
                chunk = proc.stdout.read(1024 * 256) if proc.stdout else b""
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_output:
                    proc.kill()
                    break
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return ""


class Progress:
    """Прокидывает прогресс и лог в GUI."""

    def __init__(self, callback=None):
        self.callback = callback
        self.value = 0.0
        self.started = time.time()

    def step(self, value: float, text: str = ""):
        self.value = max(0.0, min(1.0, value))
        if self.callback:
            try:
                self.callback(self.value, text)
            except Exception:
                pass

    def log(self, text: str):
        if self.callback:
            try:
                self.callback(self.value, text)
            except Exception:
                pass

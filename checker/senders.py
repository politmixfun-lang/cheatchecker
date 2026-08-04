# -*- coding: utf-8 -*-
"""Отправка отчёта боту в Discord (webhook) и Telegram. Только стандартная библиотека."""

from __future__ import annotations

import json
import mimetypes
import os
import urllib.error
import urllib.request
import uuid

from . import signatures as sig
from .report import Report

UA = "MineChecker/1.0"
COLORS = {"clean": 0x2ECC71, "grey": 0x5AC8FA, "suspicious": 0xFFD23F,
          "traces": 0xFF8B3D, "cheats": 0xFF4D5E}


# ---------------------------------------------------------------------------
def _multipart(fields: dict, files: list):
    """fields: {имя: строка}; files: [(имя_поля, имя_файла, bytes)]"""
    boundary = "----MineChecker" + uuid.uuid4().hex
    body = bytearray()
    for name, value in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += str(value).encode("utf-8") + b"\r\n"
    for field, filename, data in files:
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        body += f"--{boundary}\r\n".encode()
        body += (f'Content-Disposition: form-data; name="{field}"; '
                 f'filename="{filename}"\r\n').encode()
        body += f"Content-Type: {ctype}\r\n\r\n".encode()
        body += data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _post(url, data, content_type, timeout=60):
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": content_type, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")[:400]


def _read(path, limit_mb=8):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) > limit_mb * 1024 * 1024:
        head = data[: limit_mb * 1024 * 1024 - 200]
        data = head + b"\n\n[... otchet obrezan po limitu razmera ...]"
    return data


# ---------------------------------------------------------------------------
def send_discord(report: Report, cfg: dict, attachments: list):
    url = (cfg.get("webhook_url") or "").strip()
    if not url:
        return False, "Webhook Discord не указан в config.json"

    top = report.top(10)
    lines = []
    for f in top:
        mark = "🔴" if f.severity == "critical" else "🟠"
        title = f.title if len(f.title) <= 110 else f.title[:107] + "…"
        lines.append(f"{mark} **{title}**\n`{(f.path or '—')[:110]}`")
    body = "\n".join(lines) or "Ничего критичного не найдено."
    if len(report.findings) > len(top):
        body += f"\n\n… и ещё {len(report.findings) - len(top)} находок — смотрите файл отчёта."

    counts = report.counts
    embed = {
        "title": f"Проверка на читы — {report.verdict_label}",
        "description": report.verdict_text,
        "color": COLORS.get(report.verdict, 0x5865F2),
        "fields": [
            {"name": "👤 Игрок", "value": f"```{report.player}```", "inline": True},
            {"name": "🛡 Администратор", "value": f"```{report.admin}```", "inline": True},
            {"name": "💻 Система", "value": f"```{report.sysinfo.get('os_version','—')[:60]}```",
             "inline": False},
            {"name": "📊 Находки",
             "value": (f"🔴 Критично: **{counts.get('critical',0)}**\n"
                       f"🟠 Высокий: **{counts.get('high',0)}**\n"
                       f"🟡 Средний: **{counts.get('medium',0)}**\n"
                       f"🔵 Низкий: **{counts.get('low',0)}**"),
             "inline": True},
            {"name": "⏱ Проверка",
             "value": (f"Длительность: **{report.duration}**\n"
                       f"Файлов: **{report.stats.get('файлов', 0)}**\n"
                       f"JAR: **{report.stats.get('jar-файлов', 0)}**"),
             "inline": True},
            {"name": "🔍 Главное", "value": body[:1020], "inline": False},
        ],
        "footer": {"text": "Mine Checker"},
        "timestamp": __import__("datetime").datetime.utcfromtimestamp(report.finished).isoformat() + "Z",
    }
    content = ""
    role = str(cfg.get("mention_role_id") or "").strip()
    if role and report.verdict in ("cheats", "traces"):
        content = f"<@&{role}>"

    payload = {"username": cfg.get("username", "Mine Checker"),
               "content": content, "embeds": [embed],
               "allowed_mentions": {"parse": [], "roles": [role] if role else []}}

    files = []
    for i, path in enumerate(attachments):
        if os.path.isfile(path):
            files.append((f"files[{i}]", os.path.basename(path), _read(path)))
    try:
        data, ctype = _multipart({"payload_json": json.dumps(payload, ensure_ascii=False)}, files)
        status, text = _post(url + ("?wait=true" if "?" not in url else "&wait=true"), data, ctype)
        return (200 <= status < 300), f"Discord: HTTP {status}"
    except urllib.error.HTTPError as e:
        return False, f"Discord: HTTP {e.code} — {e.read()[:200].decode('utf-8','replace')}"
    except Exception as e:
        return False, f"Discord: {e}"


# ---------------------------------------------------------------------------
def send_telegram(report: Report, cfg: dict, attachments: list):
    token = (cfg.get("bot_token") or "").strip()
    chat_id = str(cfg.get("chat_id") or "").strip()
    if not token or not chat_id:
        return False, "Токен бота или chat_id Telegram не указаны в config.json"

    icon = {"clean": "✅", "grey": "🔵", "suspicious": "🟡", "traces": "🟠", "cheats": "🔴"}[report.verdict]
    c = report.counts
    lines = [
        f"{icon} <b>ПРОВЕРКА НА ЧИТЫ — {_esc(report.verdict_label)}</b>",
        "",
        f"👤 <b>Игрок:</b> <code>{_esc(report.player)}</code>",
        f"🛡 <b>Администратор:</b> <code>{_esc(report.admin)}</code>",
        f"💻 <b>Система:</b> {_esc(report.sysinfo.get('os_version','—'))}",
        f"🕐 <b>Дата:</b> {_esc(report.summary_dict()['date'])} · {_esc(report.duration)}",
        "",
        f"📊 <b>Находки:</b> 🔴 {c.get('critical',0)} · 🟠 {c.get('high',0)} · "
        f"🟡 {c.get('medium',0)} · 🔵 {c.get('low',0)}",
    ]
    top = report.top(8)
    if top:
        lines += ["", "<b>Главное:</b>"]
        for f in top:
            mark = "🔴" if f.severity == "critical" else "🟠"
            lines.append(f"{mark} {_esc(f.title[:110])}")
            if f.path:
                lines.append(f"    <code>{_esc(f.path[:100])}</code>")
    else:
        lines += ["", "Критичных находок нет."]
    lines += ["", f"📄 Полный отчёт — во вложении ({len(report.findings)} находок)."]
    text = "\n".join(lines)[:4000]

    base = f"https://api.telegram.org/bot{token}"
    ok_all, msgs = True, []
    try:
        payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                              "disable_web_page_preview": True}).encode()
        status, _ = _post(base + "/sendMessage", payload, "application/json")
        ok_all &= 200 <= status < 300
        msgs.append(f"сообщение: HTTP {status}")
    except urllib.error.HTTPError as e:
        ok_all = False
        msgs.append(f"сообщение: HTTP {e.code} — {e.read()[:180].decode('utf-8','replace')}")
    except Exception as e:
        ok_all = False
        msgs.append(f"сообщение: {e}")

    for path in attachments:
        if not os.path.isfile(path):
            continue
        try:
            data, ctype = _multipart(
                {"chat_id": chat_id,
                 "caption": f"Отчёт: {report.player} — {report.verdict_label}"},
                [("document", os.path.basename(path), _read(path, limit_mb=45))])
            status, _ = _post(base + "/sendDocument", data, ctype)
            ok_all &= 200 <= status < 300
            msgs.append(f"{os.path.basename(path)}: HTTP {status}")
        except urllib.error.HTTPError as e:
            ok_all = False
            msgs.append(f"{os.path.basename(path)}: HTTP {e.code}")
        except Exception as e:
            ok_all = False
            msgs.append(f"{os.path.basename(path)}: {e}")
    return ok_all, "Telegram: " + "; ".join(msgs)


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ---------------------------------------------------------------------------
def deliver(report: Report, cfg: dict, paths: dict):
    """Отправляет отчёт во все включённые каналы. Возвращает список (канал, ok, сообщение)."""
    results = []
    attach_ext = cfg.get("report", {}).get("attach", ["txt", "html"])
    attachments = [paths[e] for e in attach_ext if e in paths]

    d = cfg.get("discord", {})
    if d.get("enabled"):
        ok, msg = send_discord(report, d, attachments)
        results.append(("Discord", ok, msg))
    t = cfg.get("telegram", {})
    if t.get("enabled"):
        ok, msg = send_telegram(report, t, attachments)
        results.append(("Telegram", ok, msg))
    if not results:
        results.append(("—", False, "Ни один канал не включён в config.json"))
    return results

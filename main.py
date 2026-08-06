#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mine Checker — точка входа.

  python3 main.py                       окно с интерфейсом
  python3 main.py --cli --player Steve --admin Notch     без окна (консоль)
  python3 main.py --no-send             не отправлять отчёт боту
"""

from __future__ import annotations

import argparse
import json
import os
import sys

FROZEN = getattr(sys, "frozen", False)          # запущено как готовая программа (.exe / .app)
if FROZEN:
    BASE = os.path.dirname(os.path.abspath(sys.executable))     # папка рядом с программой
    BUNDLE = getattr(sys, "_MEIPASS", BASE)                     # ресурсы внутри программы
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
    BUNDLE = BASE
    sys.path.insert(0, BASE)

CONFIG_PATH = os.path.join(BASE, "config.json")
DEFAULT_CONFIG = {
    "discord": {"enabled": False, "webhook_url": "", "username": "Mine Checker", "mention_role_id": ""},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    "report": {"dir": "reports", "attach": ["txt", "html"]},
    "scan": {
        "deep_jar_scan": True,
        "max_jar_size_mb": 400,
        "max_depth": 10,
        "time_budget": 330,          # секунд на обход диска: вся проверка укладывается в 5-7 минут
        "max_findings": 5000,
        "usn_journal": False,        # журнал USN даёт больше следов, но добавляет минуты
        "spotlight": True,
        "all_users": True,           # проверять все учётные записи компьютера
        "usb": True,                 # проверять подключённые USB + историю флешек
        "all_drives": False,         # обходить все диски целиком (медленно) — по желанию
        "extra_paths": [],
    },
}


def _merge(cfg, user):
    for k, v in user.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


def load_config():
    """
    Порядок поиска настроек:
      1. config.json рядом с программой (можно поменять без пересборки);
      2. config.json, вшитый в саму программу при сборке (игроку ничего настраивать не нужно);
      3. значения по умолчанию.
    """
    from checker.settings import USER_CONFIG

    candidates = [CONFIG_PATH]
    if FROZEN and sys.platform == "darwin" and ".app/Contents/MacOS" in BASE:
        # рядом с самим .app, а не внутри бандла
        candidates.append(os.path.join(os.path.dirname(BASE.split(".app")[0]), "config.json"))
    candidates += [USER_CONFIG, os.path.join(BUNDLE, "config.json")]

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    loaded = False
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    _merge(cfg, json.load(f))
                loaded = True
                break
            except Exception as e:
                print(f"[!] {path} прочитать не удалось ({e}).")
    if not loaded and not FROZEN:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[i] Создан {CONFIG_PATH} — впишите туда webhook Discord и/или токен Telegram.")
    return cfg


def reports_dir(cfg):
    """Куда складывать отчёты. У готовой программы папка рядом может быть только для чтения."""
    d = cfg.get("report", {}).get("dir", "reports")
    if os.path.isabs(d):
        return d
    if FROZEN:
        return os.path.join(os.path.expanduser("~"), "MineChecker", d)
    return os.path.join(BASE, d)


def main():
    ap = argparse.ArgumentParser(description="Mine Checker — проверка Minecraft на читы")
    ap.add_argument("--cli", action="store_true", help="без графического окна")
    ap.add_argument("--player", default="", help="никнейм игрока")
    ap.add_argument("--admin", default="", help="никнейм администратора")
    ap.add_argument("--no-send", action="store_true", help="не отправлять отчёт в Discord/Telegram")
    args = ap.parse_args()

    cfg = load_config()
    out_dir = reports_dir(cfg)

    if args.cli or not _gui_available():
        return run_cli(cfg, out_dir, args)

    from checker.gui import launch
    launch(cfg, out_dir)
    return 0


def _gui_available():
    try:
        import tkinter  # noqa: F401
        return True
    except Exception:
        print("[!] tkinter недоступен — запускаю консольный режим.")
        return False


def run_cli(cfg, out_dir, args):
    from checker import report as report_mod
    from checker import senders
    from checker.engine import run_check

    player = args.player or input("Никнейм игрока: ").strip()
    admin = args.admin or input("Никнейм администратора: ").strip()
    if not player or not admin:
        print("Нужны оба ника.")
        return 2
    print("\nИгрок подтверждает согласие на проверку компьютера и отправку отчёта администратору.")
    if input("Согласен? (да/нет): ").strip().lower() not in ("да", "d", "y", "yes", "+"):
        print("Проверка отменена.")
        return 1

    last = [""]

    def cb(value, text):
        if text and text != last[0]:
            last[0] = text
            print(f"[{value*100:5.1f}%] {text}")

    rep = run_check(player, admin, cfg, progress_cb=cb)
    paths = report_mod.save_reports(rep, out_dir)
    print("\n" + rep.to_text()[:4000])
    print(f"\nОтчёты: {paths['txt']}\n         {paths['html']}\n         {paths['json']}")

    if not args.no_send:
        for name, ok, msg in senders.deliver(rep, cfg, paths):
            print(("[✓] " if ok else "[✗] ") + f"{name}: {msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

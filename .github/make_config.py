#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Готовит config.json для сборки, беря токены из секретов репозитория.

Секреты не попадают ни в один коммит и не печатаются в лог — сюда они
приходят только переменными окружения на время сборки.
"""

import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE, "config.example.json"), encoding="utf-8") as f:
    cfg = json.load(f)

tg_token = os.environ.get("TG_TOKEN", "").strip()
tg_chat = os.environ.get("TG_CHAT", "").strip()
webhook = os.environ.get("DISCORD_WEBHOOK", "").strip()

cfg["telegram"] = {"enabled": bool(tg_token and tg_chat),
                   "bot_token": tg_token, "chat_id": tg_chat}
cfg["discord"] = {"enabled": bool(webhook), "webhook_url": webhook,
                  "username": "Mine Checker", "mention_role_id": ""}

with open(os.path.join(BASE, "config.json"), "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)

print("config.json собран. Telegram: %s, Discord: %s"
      % ("настроен" if cfg["telegram"]["enabled"] else "пусто",
         "настроен" if cfg["discord"]["enabled"] else "пусто"))

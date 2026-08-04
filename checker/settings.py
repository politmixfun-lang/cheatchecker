# -*- coding: utf-8 -*-
"""Пользовательские настройки готовой программы (без правки файлов рядом с ней)."""

from __future__ import annotations

import json
import os

USER_DIR = os.path.join(os.path.expanduser("~"), "MineChecker")
USER_CONFIG = os.path.join(USER_DIR, "config.json")


def save_user_config(cfg: dict) -> str:
    os.makedirs(USER_DIR, exist_ok=True)
    with open(USER_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return USER_CONFIG


def load_user_config():
    if os.path.isfile(USER_CONFIG):
        try:
            with open(USER_CONFIG, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None

# -*- coding: utf-8 -*-
"""Окно Mine Checker: ввод ников -> проверка -> результат + отправка боту."""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser

from . import platform_info as pi
from . import report as report_mod
from . import senders
from . import signatures as sig
from . import ui_kit as ui
from .engine import run_check

PAD = 22


class MineCheckerApp:
    def __init__(self, cfg: dict, out_dir: str):
        self.cfg = cfg
        self.out_dir = out_dir
        self.queue = queue.Queue()
        self.report = None
        self.paths = {}
        self.win = ui.root_window("Mine Checker — проверка на читы", 1000, 720)
        self.container = ui.frame(self.win, color=ui.BG, radius=0)
        self.container.pack(fill="both", expand=True)
        self.screen_setup()

    # ------------------------------------------------------------------
    def clear(self):
        for child in self.container.winfo_children():
            child.destroy()

    def run(self):
        self.win.mainloop()

    # ==================================================================
    # ЭКРАН 1 — ввод данных
    # ==================================================================
    def screen_setup(self):
        self.clear()
        root = ui.frame(self.container, color=ui.BG, radius=0)
        root.pack(fill="both", expand=True, padx=40, pady=28)

        ui.label(root, "MINE CHECKER", size=34, weight="bold").pack(anchor="w")
        ui.label(root, "Проверка компьютера игрока на читы для Minecraft",
                 size=14, color=ui.MUTED).pack(anchor="w", pady=(2, 18))

        # --- карточка с определённой ОС --------------------------------
        oscard = ui.frame(root, color=ui.CARD, border=1)
        oscard.pack(fill="x", pady=(0, 14))
        inner = ui.frame(oscard, color=ui.CARD, radius=0)
        inner.pack(fill="x", padx=18, pady=14)

        info = pi.system_info()
        self.sysinfo = info
        icon = {"windows": "🪟", "macos": "🍎", "linux": "🐧"}.get(info["os_key"], "💻")
        ui.label(inner, f"{icon}  Система определена автоматически",
                 size=12, color=ui.MUTED, bg=ui.CARD).pack(anchor="w")
        ui.label(inner, info["os_version"], size=18, weight="bold", bg=ui.CARD).pack(anchor="w", pady=(2, 6))

        row = ui.frame(inner, color=ui.CARD, radius=0)
        row.pack(fill="x")
        admin_ok = info["admin"]
        ui.badge(row, "АДМИН ✔" if admin_ok else "БЕЗ ПРАВ АДМИНА",
                 ui.OK if admin_ok else "#ffd23f", bg=ui.CARD).pack(side="left", padx=(0, 10))
        note = ("Полный доступ к системным журналам."
                if admin_ok else
                ("Часть журналов Windows (Prefetch, USN, BAM) недоступна — "
                 "перезапустите от администратора для полной проверки."
                 if pi.WINDOWS else
                 "Для полного доступа к системным журналам запустите с sudo."))
        ui.label(row, note, size=12, color=ui.MUTED, bg=ui.CARD, wraplength=620).pack(side="left")

        # --- ввод ников -------------------------------------------------
        fields = ui.frame(root, color=ui.BG, radius=0)
        fields.pack(fill="x", pady=(4, 14))

        left = ui.frame(fields, color=ui.BG, radius=0)
        left.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ui.label(left, "НИКНЕЙМ ИГРОКА", size=11, weight="bold", color=ui.MUTED).pack(anchor="w", pady=(0, 6))
        self.e_player = ui.entry(left, "Например: Steve", height=46)
        self.e_player.pack(fill="x")

        right = ui.frame(fields, color=ui.BG, radius=0)
        right.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ui.label(right, "НИКНЕЙМ АДМИНИСТРАТОРА", size=11, weight="bold", color=ui.MUTED).pack(anchor="w", pady=(0, 6))
        self.e_admin = ui.entry(right, "Кто проводит проверку", height=46)
        self.e_admin.pack(fill="x")

        # --- согласие ---------------------------------------------------
        consent = ui.frame(root, color=ui.CARD, border=1)
        consent.pack(fill="x", pady=(6, 16))
        ci = ui.frame(consent, color=ui.CARD, radius=0)
        ci.pack(fill="x", padx=18, pady=14)
        ui.label(ci, "Что делает проверка", size=12, weight="bold", bg=ui.CARD).pack(anchor="w")
        ui.label(ci,
                 "• читает имена файлов в игровых папках, на рабочем столе, в загрузках и корзине;\n"
                 "• разбирает .jar-файлы и ищет внутри сигнатуры читов (в т.ч. переименованных);\n"
                 "• смотрит системные журналы запуска программ и следы удалённых файлов;\n"
                 "• отправляет отчёт с находками администратору в Discord/Telegram.\n"
                 "Личные документы, переписки и пароли не читаются и никуда не отправляются.",
                 size=12, color=ui.MUTED, bg=ui.CARD, wraplength=860).pack(anchor="w", pady=(6, 10))
        self.var_consent = tk.IntVar(value=0)
        ui.checkbox(ci, "Я, игрок, согласен на проверку моего компьютера и отправку отчёта администратору",
                    self.var_consent, bg=ui.CARD).pack(anchor="w")

        # --- запуск -----------------------------------------------------
        self.err = ui.label(root, "", size=12, color="#ff4d5e")
        self.err.pack(anchor="w", pady=(0, 8))

        bar = ui.frame(root, color=ui.BG, radius=0)
        bar.pack(fill="x")
        ui.button(bar, "НАЧАТЬ ПРОВЕРКУ", self.start, primary=True, width=230, height=48).pack(side="left")
        ui.button(bar, "Папка с отчётами", self.open_folder, primary=False, width=180, height=48)\
            .pack(side="left", padx=10)
        ui.button(bar, "⚙ Куда слать отчёт", self.screen_settings, primary=False,
                  width=200, height=48).pack(side="left")

        chans = [n for n, k in (("Discord", "discord"), ("Telegram", "telegram"))
                 if self.cfg.get(k, {}).get("enabled")]
        ui.label(root,
                 f"База: {sig.total_signatures()} сигнатур · "
                 f"{len(sig.CLIENTS)} клиентов · {len(sig.HEUR_MODULES)} читерских модулей · "
                 f"отправка: {', '.join(chans) if chans else 'не настроена (config.json)'}",
                 size=11, color=ui.MUTED).pack(anchor="w", pady=(16, 0))

    # ==================================================================
    # ЭКРАН НАСТРОЕК — куда программа отправляет отчёт
    # ==================================================================
    def screen_settings(self):
        self.clear()
        root = ui.frame(self.container, color=ui.BG, radius=0)
        root.pack(fill="both", expand=True, padx=40, pady=28)

        ui.label(root, "Куда отправлять отчёт", size=26, weight="bold").pack(anchor="w")
        ui.label(root, "Настройки сохраняются в ~/MineChecker/config.json и подхватываются "
                       "при каждом запуске. Для версии, которую вы раздаёте игрокам, эти же "
                       "значения вшиваются в программу при сборке.",
                 size=12, color=ui.MUTED, wraplength=860).pack(anchor="w", pady=(4, 18))

        self.s_vars = {}

        def block(title, hint, fields, key):
            card = ui.frame(root, color=ui.CARD, border=1)
            card.pack(fill="x", pady=(0, 12))
            ci = ui.frame(card, color=ui.CARD, radius=0)
            ci.pack(fill="x", padx=18, pady=14)
            head = ui.frame(ci, color=ui.CARD, radius=0)
            head.pack(fill="x")
            var = tk.IntVar(value=1 if self.cfg.get(key, {}).get("enabled") else 0)
            self.s_vars[key + ".enabled"] = var
            ui.checkbox(head, title, var, bg=ui.CARD).pack(side="left")
            ui.label(head, hint, size=11, color=ui.MUTED, bg=ui.CARD).pack(side="left", padx=12)
            for label_text, subkey, placeholder in fields:
                ui.label(ci, label_text, size=11, weight="bold", color=ui.MUTED,
                         bg=ui.CARD).pack(anchor="w", pady=(10, 4))
                e = ui.entry(ci, placeholder, height=40)
                current = str(self.cfg.get(key, {}).get(subkey, "") or "")
                if current:
                    try:
                        e.delete(0, "end")
                    except Exception:
                        pass
                    e.insert(0, current)
                    if not ui.HAS_CTK:
                        e.configure(fg=ui.TEXT)
                e.pack(fill="x")
                self.s_vars[f"{key}.{subkey}"] = e

        block("Discord", "Настройки канала → Интеграции → Вебхуки → Копировать URL",
              [("WEBHOOK URL", "webhook_url", "https://discord.com/api/webhooks/…"),
               ("ID РОЛИ ДЛЯ ПИНГА (необязательно)", "mention_role_id", "например 123456789012345678")],
              "discord")
        block("Telegram", "Токен у @BotFather, chat_id у @userinfobot",
              [("ТОКЕН БОТА", "bot_token", "123456789:AA…"),
               ("CHAT ID", "chat_id", "-1001234567890")],
              "telegram")

        self.s_status = ui.label(root, "", size=12, color=ui.OK)
        self.s_status.pack(anchor="w", pady=(6, 10))

        bar = ui.frame(root, color=ui.BG, radius=0)
        bar.pack(fill="x")
        ui.button(bar, "Сохранить", self._save_settings, primary=True, width=170).pack(side="left")
        ui.button(bar, "Проверить отправку", self._test_send, primary=False, width=200)\
            .pack(side="left", padx=8)
        ui.button(bar, "Назад", self.screen_setup, primary=False, width=140).pack(side="right")

    def _collect_settings(self):
        for key in ("discord", "telegram"):
            self.cfg.setdefault(key, {})
            self.cfg[key]["enabled"] = bool(self.s_vars[key + ".enabled"].get())
        for name, widget in self.s_vars.items():
            if name.endswith(".enabled"):
                continue
            key, sub = name.split(".", 1)
            self.cfg[key][sub] = ui.entry_value(widget)

    def _save_settings(self):
        from .settings import save_user_config
        self._collect_settings()
        path = save_user_config(self.cfg)
        self.s_status.configure(text=f"✔ Сохранено: {path}")

    def _test_send(self):
        """Отправляет пустой тестовый отчёт, чтобы сразу увидеть, дошло или нет."""
        import time
        from .report import Report
        from .utils import Finding
        self._collect_settings()
        rep = Report("ТЕСТ", "ТЕСТ", pi.system_info(),
                     [Finding("Тестовое сообщение Mine Checker", "info", "Система",
                              "Проверка связи с ботом.", "", ["Если вы это видите — отправка работает."])],
                     {}, time.time() - 1, time.time())
        paths = report_mod.save_reports(rep, self.out_dir)
        results = senders.deliver(rep, self.cfg, paths)
        ok = all(r[1] for r in results)
        self.s_status.configure(
            text=("✔ " if ok else "✖ ") + " · ".join(f"{n}: {m}" for n, _o, m in results),
            text_color=ui.OK if ok else "#ff4d5e") if ui.HAS_CTK else \
            self.s_status.configure(
                text=("✔ " if ok else "✖ ") + " · ".join(f"{n}: {m}" for n, _o, m in results),
                fg=ui.OK if ok else "#ff4d5e")

    # ==================================================================
    def start(self):
        player = ui.entry_value(self.e_player)
        admin = ui.entry_value(self.e_admin)
        if not player:
            return self._err("Укажите никнейм игрока.")
        if not admin:
            return self._err("Укажите никнейм администратора.")
        if not self.var_consent.get():
            return self._err("Игрок должен подтвердить согласие на проверку.")
        self.screen_scan(player, admin)

    def _err(self, text):
        try:
            self.err.configure(text=text)
        except Exception:
            pass

    # ==================================================================
    # ЭКРАН 2 — процесс
    # ==================================================================
    def screen_scan(self, player, admin):
        self.clear()
        root = ui.frame(self.container, color=ui.BG, radius=0)
        root.pack(fill="both", expand=True, padx=40, pady=34)

        ui.label(root, "Идёт проверка", size=28, weight="bold").pack(anchor="w")
        ui.label(root, f"Игрок: {player}   ·   Администратор: {admin}",
                 size=13, color=ui.MUTED).pack(anchor="w", pady=(2, 26))

        self.lbl_pct = ui.label(root, "0%", size=52, weight="bold", color=ui.ACCENT)
        self.lbl_pct.pack(anchor="w")
        self.pbar = ui.progressbar(root)
        self.pbar.pack(fill="x", pady=(8, 10))
        self.lbl_step = ui.label(root, "Запуск…", size=13, color=ui.MUTED)
        self.lbl_step.pack(anchor="w", pady=(0, 18))

        ui.label(root, "ЖУРНАЛ ПРОВЕРКИ", size=11, weight="bold", color=ui.MUTED).pack(anchor="w", pady=(0, 6))
        self.log = ui.textbox(root, height=300)
        self.log.pack(fill="both", expand=True)

        threading.Thread(target=self._worker, args=(player, admin), daemon=True).start()
        self.win.after(80, self._pump)

    def _worker(self, player, admin):
        def cb(value, text):
            self.queue.put(("progress", value, text))
        try:
            rep = run_check(player, admin, self.cfg, progress_cb=cb)
            paths = report_mod.save_reports(rep, self.out_dir)
            self.queue.put(("progress", 0.98, "Отправляю отчёт…"))
            results = senders.deliver(rep, self.cfg, paths)
            self.queue.put(("done", rep, paths, results))
        except Exception as exc:                    # noqa: BLE001
            import traceback
            self.queue.put(("error", traceback.format_exc(), str(exc)))

    def _pump(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg[0] == "progress":
                    _, value, text = msg
                    try:
                        self.pbar.set(value)
                        self.lbl_pct.configure(text=f"{value * 100:.0f}%")
                        if text:
                            self.lbl_step.configure(text=text[:140])
                            # в журнал пишем не каждое обновление, иначе окно
                            # захлебнётся тысячами строк на большой папке
                            self._log_tick = getattr(self, "_log_tick", 0) + 1
                            if self._log_tick % 12 == 1 or value >= 0.95:
                                ui.textbox_append(self.log, f"[{value*100:5.1f}%] {text[:160]}")
                    except Exception:
                        pass
                elif msg[0] == "done":
                    _, rep, paths, results = msg
                    self.report, self.paths = rep, paths
                    self.screen_result(results)
                    return
                elif msg[0] == "error":
                    _, tb, short = msg
                    ui.textbox_append(self.log, tb)
                    self.lbl_step.configure(text=f"Ошибка: {short}")
                    return
        except queue.Empty:
            pass
        self.win.after(80, self._pump)

    # ==================================================================
    # ЭКРАН 3 — результат
    # ==================================================================
    def screen_result(self, results):
        self.clear()
        rep = self.report
        root = ui.frame(self.container, color=ui.BG, radius=0)
        root.pack(fill="both", expand=True, padx=32, pady=24)

        # верхняя плашка с вердиктом
        banner = ui.frame(root, color=ui.CARD, border=1, border_color=rep.verdict_color)
        banner.pack(fill="x")
        bi = ui.frame(banner, color=ui.CARD, radius=0)
        bi.pack(fill="x", padx=20, pady=16)
        ui.label(bi, rep.verdict_label, size=30, weight="bold",
                 color=rep.verdict_color, bg=ui.CARD).pack(anchor="w")
        ui.label(bi, rep.verdict_text, size=13, color=ui.MUTED, bg=ui.CARD).pack(anchor="w", pady=(2, 0))

        # мета-строка
        meta = ui.frame(root, color=ui.BG, radius=0)
        meta.pack(fill="x", pady=(12, 12))
        for k, v in (("ИГРОК", rep.player), ("АДМИНИСТРАТОР", rep.admin),
                     ("СИСТЕМА", rep.sysinfo.get("os_version", "—")), ("ВРЕМЯ", rep.duration)):
            cell = ui.frame(meta, color=ui.CARD, border=1)
            cell.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ci = ui.frame(cell, color=ui.CARD, radius=0)
            ci.pack(fill="x", padx=14, pady=10)
            ui.label(ci, k, size=10, weight="bold", color=ui.MUTED, bg=ui.CARD).pack(anchor="w")
            ui.label(ci, str(v)[:34], size=14, weight="bold", bg=ui.CARD).pack(anchor="w")

        # счётчики
        stats = ui.frame(root, color=ui.BG, radius=0)
        stats.pack(fill="x", pady=(0, 12))
        for sev in ("critical", "high", "medium", "low", "info"):
            cell = ui.frame(stats, color=ui.CARD, border=1)
            cell.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ci = ui.frame(cell, color=ui.CARD, radius=0)
            ci.pack(fill="x", padx=12, pady=10)
            ui.label(ci, str(rep.counts.get(sev, 0)), size=24, weight="bold",
                     color=sig.SEVERITY_COLOR[sev], bg=ui.CARD, anchor="center").pack(fill="x")
            ui.label(ci, sig.SEVERITY_RU[sev], size=10, color=ui.MUTED,
                     bg=ui.CARD, anchor="center").pack(fill="x")

        # статус отправки
        line = " · ".join(f"{'✔' if ok else '✖'} {name}: {msg}" for name, ok, msg in results)
        ui.label(root, line, size=11,
                 color=ui.OK if all(r[1] for r in results) else "#ff8b3d",
                 wraplength=920).pack(anchor="w", pady=(0, 10))

        ui.label(root, f"НАХОДКИ ({len(rep.findings)})", size=11, weight="bold",
                 color=ui.MUTED).pack(anchor="w", pady=(0, 6))
        outer, holder = ui.scrollable(root, height=250)
        outer.pack(fill="both", expand=True)

        if not rep.findings:
            ui.label(holder, "Ничего не найдено — система чистая.", size=14, color=ui.OK)\
                .pack(anchor="w", pady=10)
        for f in rep.findings[:400]:
            card = ui.frame(holder, color=ui.CARD, border=1)
            card.pack(fill="x", pady=3, padx=2)
            ci = ui.frame(card, color=ui.CARD, radius=0)
            ci.pack(fill="x", padx=12, pady=9)
            head = ui.frame(ci, color=ui.CARD, radius=0)
            head.pack(fill="x")
            ui.badge(head, sig.SEVERITY_RU[f.severity], sig.SEVERITY_COLOR[f.severity],
                     bg=ui.CARD).pack(side="left", padx=(0, 10))
            ui.label(head, f.title, size=13, weight="bold", bg=ui.CARD, wraplength=700)\
                .pack(side="left", anchor="w")
            sub = f"{f.category}" + (f"  ·  {f.path}" if f.path else "")
            ui.label(ci, sub[:170], size=11, color=ui.MUTED, bg=ui.CARD).pack(anchor="w", pady=(4, 0))
            if f.evidence:
                ui.label(ci, "   ".join(str(x)[:90] for x in f.evidence[:3]),
                         size=10, color="#6f7788", bg=ui.CARD, wraplength=880).pack(anchor="w")

        # кнопки
        bar = ui.frame(root, color=ui.BG, radius=0)
        bar.pack(fill="x", pady=(12, 0))
        ui.button(bar, "Открыть отчёт", self.open_html, primary=True, width=170).pack(side="left")
        ui.button(bar, "Папка с отчётами", self.open_folder, primary=False, width=170)\
            .pack(side="left", padx=8)
        ui.button(bar, "Отправить ещё раз", self.resend, primary=False, width=180).pack(side="left")
        ui.button(bar, "Новая проверка", self.screen_setup, primary=False, width=170)\
            .pack(side="right")

    # ==================================================================
    def open_html(self):
        p = self.paths.get("html")
        if p and os.path.exists(p):
            webbrowser.open("file://" + os.path.abspath(p))

    def open_folder(self):
        os.makedirs(self.out_dir, exist_ok=True)
        if pi.WINDOWS:
            os.startfile(self.out_dir)                       # noqa: S606
        elif pi.MACOS:
            subprocess.Popen(["open", self.out_dir])
        else:
            subprocess.Popen(["xdg-open", self.out_dir])

    def resend(self):
        if not self.report:
            return
        results = senders.deliver(self.report, self.cfg, self.paths)
        self.screen_result(results)


def launch(cfg, out_dir):
    MineCheckerApp(cfg, out_dir).run()

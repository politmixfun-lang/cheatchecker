# -*- coding: utf-8 -*-
"""
Тонкая прослойка над customtkinter / tkinter.

Если установлен customtkinter — интерфейс получает скруглённые карточки и
современные контролы. Если нет — всё работает на чистом tkinter в той же
тёмной палитре, без единой внешней зависимости.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

try:
    import customtkinter as ctk
    ctk.set_appearance_mode("dark")
    HAS_CTK = True
except Exception:                      # noqa: BLE001
    ctk = None
    HAS_CTK = False

# --- палитра ---------------------------------------------------------------
BG      = "#0e1117"
CARD    = "#161b26"
CARD_HI = "#1c2230"
BORDER  = "#232a3a"
TEXT    = "#e6e9f0"
MUTED   = "#8b93a7"
ACCENT  = "#5b8cff"
ACCENT_H= "#7ba3ff"
OK      = "#2ecc71"

if sys.platform == "darwin":
    FAMILY = "SF Pro Display"
    MONO = "Menlo"
elif sys.platform.startswith("win"):
    FAMILY = "Segoe UI"
    MONO = "Consolas"
else:
    FAMILY = "DejaVu Sans"
    MONO = "DejaVu Sans Mono"


def font(size=14, weight="normal", mono=False):
    fam = MONO if mono else FAMILY
    if HAS_CTK:
        return ctk.CTkFont(family=fam, size=size, weight=weight)
    return (fam, size, weight)


# --- фабрики виджетов ------------------------------------------------------
def root_window(title, w, h):
    if HAS_CTK:
        win = ctk.CTk()
        win.configure(fg_color=BG)
    else:
        win = tk.Tk()
        win.configure(bg=BG)
    win.title(title)
    win.geometry(f"{w}x{h}")
    win.minsize(880, 620)
    return win


def frame(parent, color=None, radius=14, border=0, border_color=BORDER, **kw):
    color = BG if color is None else color
    if HAS_CTK:
        return ctk.CTkFrame(parent, fg_color=color, corner_radius=radius,
                            border_width=border, border_color=border_color, **kw)
    f = tk.Frame(parent, bg=color, highlightthickness=border,
                 highlightbackground=border_color, highlightcolor=border_color, bd=0, **kw)
    return f


def label(parent, text="", size=14, weight="normal", color=TEXT, bg=None, anchor="w",
          wraplength=0, justify="left", mono=False):
    bg = BG if bg is None else bg
    if HAS_CTK:
        return ctk.CTkLabel(parent, text=text, font=font(size, weight, mono),
                            text_color=color, fg_color=bg, anchor=anchor,
                            wraplength=wraplength, justify=justify)
    return tk.Label(parent, text=text, font=font(size, weight, mono), fg=color, bg=bg,
                    anchor=anchor, wraplength=wraplength or 0, justify=justify)


def button(parent, text, command, primary=True, width=180, height=44, color=None):
    fill = color or (ACCENT if primary else CARD_HI)
    hover = ACCENT_H if primary else BORDER
    fg = "#0b0e14" if primary else TEXT
    if HAS_CTK:
        return ctk.CTkButton(parent, text=text, command=command, width=width, height=height,
                             corner_radius=12, fg_color=fill, hover_color=hover,
                             text_color=fg, font=font(14, "bold"))
    # На macOS нативная tk.Button игнорирует цвет фона, поэтому кнопка собирается
    # из Frame + Label — так она выглядит одинаково во всех системах.
    holder = tk.Frame(parent, bg=fill, bd=0, highlightthickness=0)
    lbl = tk.Label(holder, text=text, bg=fill, fg=fg, font=font(12, "bold"),
                   padx=16, pady=11, cursor="hand2")
    lbl.pack(fill="both", expand=True)

    def paint(c):
        holder.configure(bg=c)
        lbl.configure(bg=c)

    for w in (holder, lbl):
        w.bind("<Button-1>", lambda _e: command())
        w.bind("<Enter>", lambda _e: paint(hover))
        w.bind("<Leave>", lambda _e: paint(fill))
    return holder


def entry(parent, placeholder="", width=320, height=44):
    if HAS_CTK:
        return ctk.CTkEntry(parent, placeholder_text=placeholder, width=width, height=height,
                            corner_radius=10, fg_color=CARD_HI, border_color=BORDER,
                            border_width=1, text_color=TEXT, font=font(15))
    e = tk.Entry(parent, font=font(14), bg=CARD_HI, fg=TEXT, insertbackground=TEXT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT)
    _add_placeholder(e, placeholder)
    return e


def _add_placeholder(widget, text):
    if not text:
        return
    widget.insert(0, text)
    widget.config(fg=MUTED)

    def on_in(_):
        if widget.get() == text:
            widget.delete(0, "end")
            widget.config(fg=TEXT)

    def on_out(_):
        if not widget.get():
            widget.insert(0, text)
            widget.config(fg=MUTED)

    widget.bind("<FocusIn>", on_in)
    widget.bind("<FocusOut>", on_out)
    widget._placeholder = text


def entry_value(widget) -> str:
    v = widget.get().strip()
    if not HAS_CTK and getattr(widget, "_placeholder", None) == v:
        return ""
    return v


def checkbox(parent, text, variable, bg=None):
    bg = CARD if bg is None else bg
    if HAS_CTK:
        return ctk.CTkCheckBox(parent, text=text, variable=variable, font=font(13),
                               text_color=TEXT, fg_color=ACCENT, hover_color=ACCENT_H,
                               border_color=BORDER, corner_radius=6, checkbox_width=20,
                               checkbox_height=20)
    return tk.Checkbutton(parent, text=text, variable=variable, font=font(12),
                          bg=bg, fg=TEXT, selectcolor=CARD_HI, activebackground=bg,
                          activeforeground=TEXT, relief="flat", bd=0,
                          highlightthickness=0, anchor="w", justify="left", cursor="hand2")


def progressbar(parent, width=760):
    if HAS_CTK:
        p = ctk.CTkProgressBar(parent, width=width, height=10, corner_radius=6,
                               fg_color=CARD_HI, progress_color=ACCENT)
        p.set(0)
        return p
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("MC.Horizontal.TProgressbar", troughcolor=CARD_HI, background=ACCENT,
                    bordercolor=CARD_HI, lightcolor=ACCENT, darkcolor=ACCENT, thickness=10)
    p = ttk.Progressbar(parent, style="MC.Horizontal.TProgressbar", length=width,
                        mode="determinate", maximum=1000)
    p.set = lambda v: p.configure(value=int(v * 1000))  # type: ignore[attr-defined]
    return p


def textbox(parent, height=200, width=760):
    if HAS_CTK:
        t = ctk.CTkTextbox(parent, height=height, width=width, corner_radius=10,
                           fg_color=CARD, border_color=BORDER, border_width=1,
                           text_color=MUTED, font=font(12, mono=True))
        return t
    t = tk.Text(parent, height=max(6, height // 18), bg=CARD, fg=MUTED, relief="flat", bd=0,
                highlightthickness=1, highlightbackground=BORDER, wrap="word",
                font=font(11, mono=True), padx=10, pady=8)
    return t


def textbox_append(widget, line):
    try:
        if HAS_CTK:
            widget.configure(state="normal")
            widget.insert("end", line + "\n")
            widget.see("end")
        else:
            widget.configure(state="normal")
            widget.insert("end", line + "\n")
            widget.see("end")
            widget.configure(state="disabled")
    except Exception:
        pass


def scrollable(parent, height=340):
    """Возвращает (внешний_виджет, внутренний_контейнер_для_детей)."""
    if HAS_CTK:
        sf = ctk.CTkScrollableFrame(parent, fg_color=BG, corner_radius=0, height=height)
        return sf, sf
    outer = tk.Frame(parent, bg=BG)
    canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0, height=height)
    vs = tk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg=BG)
    inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=e.width))
    canvas.configure(yscrollcommand=vs.set)
    canvas.pack(side="left", fill="both", expand=True)
    vs.pack(side="right", fill="y")

    def wheel(event):
        delta = -1 * (event.delta // (120 if sys.platform.startswith("win") else 1))
        canvas.yview_scroll(int(delta), "units")
    canvas.bind_all("<MouseWheel>", wheel)
    return outer, inner


def badge(parent, text, color, bg=CARD):
    """Маленькая цветная плашка."""
    if HAS_CTK:
        return ctk.CTkLabel(parent, text=f" {text} ", font=font(10, "bold"),
                            text_color="#0b0e14", fg_color=color, corner_radius=10,
                            width=90, height=22)
    return tk.Label(parent, text=f" {text} ", font=font(9, "bold"),
                    fg="#0b0e14", bg=color, padx=6, pady=2)

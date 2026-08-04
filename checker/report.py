# -*- coding: utf-8 -*-
"""Сборка отчёта: вердикт, .txt для отправки, .html для просмотра, .json для архива."""

from __future__ import annotations

import html
import json
import os
import platform
import re
from datetime import datetime

from . import signatures as sig
from .utils import Finding

LOCATION_RU = {"disk": "На компьютере", "deleted": "Удалён",
               "renamed": "Переименован", "trace": "След"}
LOCATION_ICON = {"disk": "💾", "deleted": "🗑", "renamed": "🎭", "trace": "👣"}

VERDICTS = {
    "clean":     ("ЧИСТО",              "#2ecc71", "Читов не обнаружено."),
    "grey":      ("СЕРАЯ ЗОНА",         "#5ac8fa", "Найдены моды, запрещённые на части серверов."),
    "suspicious":("ПОДОЗРИТЕЛЬНО",      "#ffd23f", "Есть следы, требующие ручной проверки."),
    "traces":    ("СЛЕДЫ ЧИТОВ",        "#ff8b3d", "Найдены следы удалённых читов."),
    "cheats":    ("ЧИТЫ НАЙДЕНЫ",       "#ff4d5e", "Обнаружены читы. Проверка провалена."),
}


class Report:
    def __init__(self, player, admin, sysinfo, findings, stats, started, finished):
        self.player = player or "—"
        self.admin = admin or "—"
        self.sysinfo = sysinfo
        self.findings = sorted(findings, key=lambda f: (-f.weight, f.category, f.title))
        self.stats = stats
        self.started = started
        self.finished = finished
        self.counts = {k: 0 for k in sig.SEVERITY_ORDER}
        for f in self.findings:
            self.counts[f.severity] = self.counts.get(f.severity, 0) + 1
        self.verdict = self._verdict()

    # -----------------------------------------------------------------
    def _verdict(self):
        crit = self.counts.get("critical", 0)
        high = self.counts.get("high", 0)
        med = self.counts.get("medium", 0)
        real_cheat = any(f.severity == "critical" and f.category in
                         (sig.CAT_CLIENT, sig.CAT_GHOST, sig.CAT_MOD, sig.CAT_BEDROCK,
                          sig.CAT_INJECT, sig.CAT_MACRO)
                         for f in self.findings)
        traces = any(f.category in (sig.CAT_TRACE, sig.CAT_CLEANER) and f.weight >= 3
                     for f in self.findings)
        if real_cheat:
            return "cheats"
        if crit:
            return "cheats"
        if traces or high >= 2:
            return "traces"
        if high or med >= 3:
            return "suspicious"
        if med or any(f.category == sig.CAT_GREY for f in self.findings):
            return "grey"
        return "clean"

    @property
    def verdict_label(self):
        return VERDICTS[self.verdict][0]

    @property
    def verdict_color(self):
        return VERDICTS[self.verdict][1]

    @property
    def verdict_text(self):
        return VERDICTS[self.verdict][2]

    @property
    def duration(self):
        return f"{self.finished - self.started:.1f} с"

    def top(self, n=12):
        return [f for f in self.findings if f.severity in ("critical", "high")][:n]

    # -----------------------------------------------------------------
    def summary_dict(self):
        return {
            "player": self.player,
            "admin": self.admin,
            "verdict": self.verdict,
            "verdict_label": self.verdict_label,
            "counts": self.counts,
            "total": len(self.findings),
            "os": self.sysinfo.get("os_version", ""),
            "duration": self.duration,
            "date": datetime.fromtimestamp(self.finished).strftime("%d.%m.%Y %H:%M:%S"),
        }

    # -----------------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps({
            "summary": self.summary_dict(),
            "system": self.sysinfo,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }, ensure_ascii=False, indent=2)

    def to_text(self) -> str:
        L = []
        w = 78
        L.append("=" * w)
        L.append("MINE CHECKER — ОТЧЁТ О ПРОВЕРКЕ НА ЧИТЫ".center(w))
        L.append("=" * w)
        L.append(f"Игрок:          {self.player}")
        L.append(f"Администратор:  {self.admin}")
        L.append(f"Дата проверки:  {datetime.fromtimestamp(self.finished).strftime('%d.%m.%Y %H:%M:%S')}")
        L.append(f"Длительность:   {self.duration}")
        L.append("")
        L.append(f"ВЕРДИКТ: {self.verdict_label} — {self.verdict_text}")
        L.append("")
        L.append("-" * w)
        L.append("СИСТЕМА")
        L.append("-" * w)
        for k, v in self.sysinfo.items():
            L.append(f"  {k:<14} {v}")
        L.append("")
        L.append("-" * w)
        L.append("ИТОГИ")
        L.append("-" * w)
        for sev in ("critical", "high", "medium", "low", "info"):
            L.append(f"  {sig.SEVERITY_RU[sev]:<10} {self.counts.get(sev, 0)}")
        L.append(f"  {'ВСЕГО':<10} {len(self.findings)}")
        for k, v in self.stats.items():
            L.append(f"  {k:<10} {v}")
        L.append("")

        if not self.findings:
            L.append("Находок нет. Система чистая.")
        else:
            L.append("=" * w)
            L.append("НАХОДКИ")
            L.append("=" * w)
            current = None
            for i, f in enumerate(self.findings, 1):
                if f.severity != current:
                    current = f.severity
                    L.append("")
                    L.append(f"### {sig.SEVERITY_RU[f.severity]} " + "#" * (w - 5 - len(sig.SEVERITY_RU[f.severity])))
                L.append("")
                L.append(f"[{i}] {f.title}")
                L.append(f"    Категория: {f.category}   [{LOCATION_RU.get(f.location, f.location)}]")
                if f.detail:
                    L.append(f"    Почему важно: {f.detail}")
                if f.path:
                    L.append(f"    Путь: {f.path}")
                for e in f.evidence[:20]:
                    L.append(f"      • {e}")
        L.append("")
        L.append("=" * w)
        L.append("Отчёт сформирован Mine Checker. Проверка проведена с согласия игрока.")
        L.append("=" * w)
        return "\n".join(L)

    # -----------------------------------------------------------------
    def to_html(self) -> str:
        e = html.escape
        loc_counts = {k: 0 for k in LOCATION_RU}
        for f in self.findings:
            loc_counts[f.location] = loc_counts.get(f.location, 0) + 1

        rows = []
        for idx, f in enumerate(self.findings):
            color = sig.SEVERITY_COLOR.get(f.severity, "#888")
            ev = "".join(f"<li>{e(str(x))}</li>" for x in f.evidence[:40])
            info = self._file_block(f)
            haystack = e((f.title + " " + f.path + " " + f.category).lower())
            rows.append(f"""
            <details class="card" data-loc="{f.location}" data-sev="{f.severity}"
                     data-search="{haystack}" style="--sev:{color}">
              <summary>
                <span class="badge" style="background:{color}">{sig.SEVERITY_RU[f.severity]}</span>
                <span class="loc" title="{LOCATION_RU.get(f.location, '')}">{LOCATION_ICON.get(f.location, '')} {LOCATION_RU.get(f.location, '')}</span>
                <span class="ttl">{e(f.title)}</span>
                <span class="cat">{e(f.category)}</span>
              </summary>
              <div class="body">
                {'<p class="why">' + e(f.detail) + '</p>' if f.detail else ''}
                {info}
                <div class="evi"><b>Подробности проверки</b><ul>{ev}</ul></div>
              </div>
            </details>""")

        sysrows = "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>"
                          for k, v in self.sysinfo.items())
        counts = "".join(
            f'<div class="stat"><div class="num" style="color:{sig.SEVERITY_COLOR[sv]}">'
            f'{self.counts.get(sv, 0)}</div><div class="lbl">{sig.SEVERITY_RU[sv]}</div></div>'
            for sv in ("critical", "high", "medium", "low", "info"))

        filters = ['<button class="fbtn on" data-f="all">Все <b>%d</b></button>' % len(self.findings)]
        for key in ("disk", "deleted", "renamed", "trace"):
            if loc_counts.get(key):
                filters.append('<button class="fbtn" data-f="%s">%s %s <b>%d</b></button>'
                               % (key, LOCATION_ICON[key], LOCATION_RU[key], loc_counts[key]))
        sev_filters = ['<button class="sbtn on" data-s="all">Любая важность</button>']
        for sv in ("critical", "high", "medium", "low", "info"):
            if self.counts.get(sv):
                sev_filters.append('<button class="sbtn" data-s="%s" style="--c:%s">%s <b>%d</b></button>'
                                   % (sv, sig.SEVERITY_COLOR[sv], sig.SEVERITY_RU[sv], self.counts[sv]))

        return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mine Checker — {e(self.player)}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#0e1117;color:#e6e9f0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1060px;margin:0 auto;padding:28px 18px 60px}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:#8b93a7;font-size:13px;margin-bottom:22px}}
.verdict{{border-radius:16px;padding:22px;background:linear-gradient(135deg,{self.verdict_color}22,#161b26);
  border:1px solid {self.verdict_color}55;margin-bottom:20px}}
.verdict .big{{font-size:30px;font-weight:800;color:{self.verdict_color};letter-spacing:.5px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:18px 0}}
.meta div{{background:#161b26;border:1px solid #232a3a;border-radius:12px;padding:12px 14px}}
.meta .k{{color:#8b93a7;font-size:12px;text-transform:uppercase;letter-spacing:.6px}}
.meta .v{{font-size:16px;font-weight:600;margin-top:3px;word-break:break-word}}
.stats{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 26px}}
.stat{{flex:1;min-width:110px;background:#161b26;border:1px solid #232a3a;border-radius:12px;padding:14px;text-align:center}}
.stat .num{{font-size:26px;font-weight:800}}
.stat .lbl{{font-size:11px;color:#8b93a7;letter-spacing:.6px}}
h2{{font-size:15px;color:#8b93a7;text-transform:uppercase;letter-spacing:1px;margin:26px 0 10px}}
.bar{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}}
.fbtn,.sbtn{{background:#161b26;border:1px solid #232a3a;color:#c3c9d6;border-radius:20px;
  padding:7px 14px;font:inherit;font-size:13px;cursor:pointer;transition:.15s}}
.fbtn b,.sbtn b{{color:#fff;margin-left:3px}}
.fbtn:hover,.sbtn:hover{{border-color:#3a4761;color:#fff}}
.fbtn.on{{background:#5b8cff;border-color:#5b8cff;color:#0b0e14;font-weight:600}}
.fbtn.on b{{color:#0b0e14}}
.sbtn.on{{background:var(--c,#5b8cff);border-color:var(--c,#5b8cff);color:#0b0e14;font-weight:600}}
.sbtn.on b{{color:#0b0e14}}
#q{{flex:1;min-width:190px;background:#161b26;border:1px solid #232a3a;color:#e6e9f0;
  border-radius:20px;padding:8px 15px;font:inherit;font-size:13px;outline:none}}
#q:focus{{border-color:#5b8cff}}
#empty{{display:none;color:#8b93a7;padding:22px;text-align:center;background:#141924;
  border:1px dashed #232a3a;border-radius:12px}}
.card{{background:#141924;border:1px solid #232a3a;border-left:4px solid var(--sev);
  border-radius:10px;margin-bottom:8px;overflow:hidden}}
.card.hide{{display:none}}
summary{{cursor:pointer;padding:12px 14px;display:flex;gap:9px;align-items:center;flex-wrap:wrap;list-style:none}}
summary::-webkit-details-marker{{display:none}}
summary:hover{{background:#182031}}
.badge{{font-size:10px;font-weight:800;color:#0e1117;padding:3px 8px;border-radius:20px;letter-spacing:.5px;white-space:nowrap}}
.loc{{font-size:11px;color:#8b93a7;background:#1d2432;padding:3px 9px;border-radius:20px;white-space:nowrap}}
.ttl{{font-weight:600;flex:1;min-width:200px}}
.cat{{font-size:11px;color:#8b93a7;background:#1d2432;padding:3px 9px;border-radius:20px}}
.body{{padding:0 14px 14px;border-top:1px solid #232a3a}}
.why{{color:#c3c9d6;margin:12px 0 10px}}
.fileblock{{background:#0b0e14;border:1px solid #232a3a;border-radius:10px;padding:12px 14px;margin:10px 0}}
.fileblock .row{{display:flex;gap:10px;padding:4px 0;font-size:13px;flex-wrap:wrap}}
.fileblock .rk{{color:#8b93a7;min-width:130px}}
.fileblock .rv{{color:#e6e9f0;word-break:break-all;flex:1}}
.pathline{{display:flex;gap:8px;align-items:flex-start;margin-bottom:8px}}
.pathline code{{background:#161b26;padding:6px 10px;border-radius:6px;font-size:12px;
  word-break:break-all;flex:1;border:1px solid #232a3a}}
.copy{{background:#1d2432;border:1px solid #232a3a;color:#c3c9d6;border-radius:6px;
  padding:6px 11px;font-size:12px;cursor:pointer;white-space:nowrap}}
.copy:hover{{background:#5b8cff;color:#0b0e14;border-color:#5b8cff}}
.state{{display:inline-block;font-size:12px;padding:3px 10px;border-radius:20px;font-weight:600}}
.state.gone{{background:#ff8b3d22;color:#ff8b3d;border:1px solid #ff8b3d55}}
.state.here{{background:#2ecc7122;color:#2ecc71;border:1px solid #2ecc7155}}
.evi{{margin-top:10px}}
.evi b{{font-size:12px;color:#8b93a7;text-transform:uppercase;letter-spacing:.5px}}
ul{{margin:6px 0 0;padding-left:20px;color:#9aa3b5;font-size:13px}}
li{{margin:3px 0;word-break:break-word}}
table{{width:100%;border-collapse:collapse;background:#141924;border-radius:10px;overflow:hidden}}
td{{padding:8px 12px;border-bottom:1px solid #232a3a;font-size:13px}}
td:first-child{{color:#8b93a7;width:200px}}
.foot{{margin-top:34px;color:#5c6478;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<h1>Mine Checker — отчёт о проверке</h1>
<div class="sub">Сформирован {e(datetime.fromtimestamp(self.finished).strftime('%d.%m.%Y в %H:%M:%S'))} · {e(self.duration)}</div>
<div class="verdict"><div class="big">{e(self.verdict_label)}</div><div>{e(self.verdict_text)}</div></div>
<div class="meta">
  <div><div class="k">Игрок</div><div class="v">{e(self.player)}</div></div>
  <div><div class="k">Администратор</div><div class="v">{e(self.admin)}</div></div>
  <div><div class="k">Операционная система</div><div class="v">{e(self.sysinfo.get('os_version',''))}</div></div>
  <div><div class="k">Учётная запись</div><div class="v">{e(str(self.sysinfo.get('user','')))}</div></div>
</div>
<div class="stats">{counts}</div>

<h2>Находки ({len(self.findings)})</h2>
<div class="bar">{''.join(filters)}<input id="q" placeholder="Поиск по названию или пути…"></div>
<div class="bar">{''.join(sev_filters)}</div>
<div id="list">{''.join(rows) if rows else '<p style="color:#2ecc71">Ничего не найдено — система чистая.</p>'}</div>
<div id="empty">Под выбранные фильтры ничего не подходит.</div>

<h2>Система</h2><table>{sysrows}</table>
<div class="foot">Mine Checker · проверка проведена с согласия игрока</div>
</div>
<script>
(function(){{
  var loc="all", sev="all";
  var cards=[].slice.call(document.querySelectorAll(".card"));
  var q=document.getElementById("q"), empty=document.getElementById("empty");

  function apply(){{
    var text=(q.value||"").toLowerCase().trim(), shown=0;
    cards.forEach(function(c){{
      var ok=(loc==="all"||c.dataset.loc===loc)
          && (sev==="all"||c.dataset.sev===sev)
          && (!text||c.dataset.search.indexOf(text)>=0);
      c.classList.toggle("hide",!ok);
      if(ok) shown++;
    }});
    empty.style.display=shown?"none":"block";
  }}

  document.querySelectorAll(".fbtn").forEach(function(b){{
    b.onclick=function(){{
      document.querySelectorAll(".fbtn").forEach(function(x){{x.classList.remove("on");}});
      b.classList.add("on"); loc=b.dataset.f; apply();
    }};
  }});
  document.querySelectorAll(".sbtn").forEach(function(b){{
    b.onclick=function(){{
      document.querySelectorAll(".sbtn").forEach(function(x){{x.classList.remove("on");}});
      b.classList.add("on"); sev=b.dataset.s; apply();
    }};
  }});
  q.oninput=apply;

  document.addEventListener("click",function(ev){{
    var b=ev.target.closest(".copy");
    if(!b) return;
    ev.preventDefault();
    var t=b.getAttribute("data-path");
    (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){{
      var old=b.textContent; b.textContent="Скопировано"; setTimeout(function(){{b.textContent=old;}},1200);
    }}).catch(function(){{
      var ta=document.createElement("textarea"); ta.value=t; document.body.appendChild(ta);
      ta.select(); try{{document.execCommand("copy");}}catch(e){{}} document.body.removeChild(ta);
      var old=b.textContent; b.textContent="Скопировано"; setTimeout(function(){{b.textContent=old;}},1200);
    }});
  }});
}})();
</script>
</body></html>"""

    def _file_block(self, f) -> str:
        """Карточка файла: где лежит, существует ли, когда удалён, размер и хеш."""
        e = html.escape
        if not f.path and not f.meta.get("paths"):
            return ""

        def find_ev(prefix):
            for x in f.evidence:
                if isinstance(x, str) and x.startswith(prefix):
                    return x.split(":", 1)[1].strip()
            return ""

        exists = bool(f.path) and os.path.exists(f.path)
        deleted_at = f.meta.get("deleted_at") or find_ev("Удалён")

        if f.location == "deleted":
            state = ('<span class="state gone">Удалён'
                     + (f' · {e(deleted_at)}' if deleted_at else '') + '</span>')
        elif exists:
            state = '<span class="state here">Файл на месте</span>'
        elif f.location == "renamed":
            state = '<span class="state gone">Переименован / замаскирован</span>'
        else:
            state = '<span class="state gone">Файла нет по этому пути</span>'

        rows = []
        folder = os.path.dirname(f.path) if f.path else ""
        for label, value in (("Папка", folder),
                             ("Имя файла", os.path.basename(f.path) if f.path else ""),
                             ("Размер", find_ev("Размер")),
                             ("Создан", find_ev("Создан")),
                             ("Изменён", find_ev("Изменён")),
                             ("Последний доступ", find_ev("Последний доступ")),
                             ("Удалён", deleted_at),
                             ("Запускался", find_ev("Последний запуск")),
                             ("SHA-256", find_ev("SHA-256")),
                             ("Имя мода внутри", find_ev("Имя мода внутри"))):
            if value:
                rows.append(f'<div class="row"><div class="rk">{label}</div>'
                            f'<div class="rv">{e(str(value))}</div></div>')

        grouped = f.meta.get("paths")
        if grouped and len(grouped) > 1:
            items = "".join(f"<li>{e(p)}</li>" for p in grouped[:60])
            rows.append(f'<div class="row"><div class="rk">Все совпадения</div>'
                        f'<div class="rv"><ul>{items}</ul></div></div>')

        path_line = ""
        if f.path:
            path_line = (f'<div class="pathline"><code>{e(f.path)}</code>'
                         f'<button class="copy" data-path="{e(f.path)}">Скопировать путь</button></div>')

        return f'<div class="fileblock">{path_line}<div style="margin:6px 0 8px">{state}</div>{"".join(rows)}</div>'


def safe_name(text: str) -> str:
    return re.sub(r"[^\w\-]+", "_", (text or "player"), flags=re.U)[:40] or "player"


def save_reports(report: Report, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.fromtimestamp(report.finished).strftime("%Y-%m-%d_%H-%M-%S")
    base = f"check_{safe_name(report.player)}_{stamp}"
    paths = {}
    for ext, data in (("txt", report.to_text()), ("html", report.to_html()), ("json", report.to_json())):
        p = os.path.join(out_dir, f"{base}.{ext}")
        with open(p, "w", encoding="utf-8") as f:
            f.write(data)
        paths[ext] = p
    return paths

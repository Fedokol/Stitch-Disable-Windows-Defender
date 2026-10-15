#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smoke-тест GUI defender_toggle.py без реального окна.
Подменяем модуль tkinter на заглушку, которая ЗАПИСЫВАЕТ все вызовы и
синхронно выполняет root.after(...). Так мы реально прогоняем код
построения интерфейса и ветку обновления статуса / нажатия кнопок.

Запуск:  python3 test_gui_smoke.py
"""
import io
import json
import sys
import types
from contextlib import redirect_stdout

import defender_toggle as d

PASS = FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {extra}")


# --------------------------------------------------------------------------- #
#  Заглушка tkinter
# --------------------------------------------------------------------------- #
REGISTRY = []          # все созданные виджеты: (type, kwargs, widget)
CALLS = []             # все вызовы методов: (widget_id, method, args, kwargs)
AFTER_QUEUE = []


class FakeWidget:
    _counter = 0

    def __init__(self, kind, *args, **kwargs):
        FakeWidget._counter += 1
        self.id = FakeWidget._counter
        self.kind = kind
        self.args = args
        self.kwargs = dict(kwargs)
        self._cfg = dict(kwargs)
        REGISTRY.append(self)

    # любые методы виджета
    def __getattr__(self, name):
        def _method(*a, **kw):
            CALLS.append((self.id, name, a, kw))
            if name == "configure" or name == "config":
                self._cfg.update(kw)
            if name == "get" and "variable" in self.kwargs:
                return True
            if name == "insert":
                self.__dict__["_text"] = self.__dict__.get("_text", "") + str(a[-1] if a else "")
            return ""
        return _method

    # обращение к атрибутам-свойствам
    @property
    def text_content(self):
        return self.__dict__.get("_text", "")

    @property
    def current_text(self):
        """Текст виджета с учётом последующих configure(text=...)."""
        return str(self.__dict__.get("_cfg", {}).get("text", ""))


class FakeVar:
    def __init__(self, *a, **kw):
        self._v = kw.get("value", False)

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class FakeTk(FakeWidget):
    def __init__(self, *a, **kw):
        super().__init__("Tk", *a, **kw)
        self._depth = 0

    def after(self, delay, func=None, *args):
        """Выполняем колбэк синхронно, с защитой от бесконечной рекурсии."""
        AFTER_QUEUE.append(func)
        if func is None or self._depth > 6:
            return 1
        self._depth += 1
        try:
            func(*args)
        finally:
            self._depth -= 1
        return 1

    def mainloop(self, *a, **kw):
        CALLS.append((self.id, "mainloop", a, kw))


def install_fake_tkinter():
    tk = types.ModuleType("tkinter")
    tk.Tk = FakeTk
    tk.Frame = lambda *a, **kw: FakeWidget("Frame", *a, **kw)
    tk.Label = lambda *a, **kw: FakeWidget("Label", *a, **kw)
    tk.Button = lambda *a, **kw: FakeWidget("Button", *a, **kw)
    tk.Checkbutton = lambda *a, **kw: FakeWidget("Checkbutton", *a, **kw)
    tk.Text = lambda *a, **kw: FakeWidget("Text", *a, **kw)
    tk.LabelFrame = lambda *a, **kw: FakeWidget("LabelFrame", *a, **kw)
    tk.BooleanVar = FakeVar
    tk.StringVar = FakeVar
    tk.TclError = type("TclError", (Exception,), {})

    ttk = types.ModuleType("tkinter.ttk")
    ttk.Style = lambda *a, **kw: FakeWidget("Style", *a, **kw)
    ttk.Scrollbar = lambda *a, **kw: FakeWidget("Scrollbar", *a, **kw)
    ttk.Progressbar = lambda *a, **kw: FakeWidget("Progressbar", *a, **kw)
    tk.ttk = ttk

    fd = types.ModuleType("tkinter.filedialog")
    fd.askdirectory = lambda **kw: "C:\\Games"
    tk.filedialog = fd

    mb = types.ModuleType("tkinter.messagebox")
    mb.SHOWN = []
    mb.showinfo = lambda *a, **kw: mb.SHOWN.append(("info", a, kw))
    mb.showerror = lambda *a, **kw: mb.SHOWN.append(("error", a, kw))
    mb.askyesno = lambda *a, **kw: (mb.SHOWN.append(("askyesno", a, kw)), True)[1]
    tk.messagebox = mb

    sys.modules["tkinter"] = tk
    sys.modules["tkinter.ttk"] = ttk
    sys.modules["tkinter.filedialog"] = fd
    sys.modules["tkinter.messagebox"] = mb
    return tk, mb


fake_tk, fake_mb = install_fake_tkinter()

STATUS_ON = {
    "available": True, "rtp_off": False, "behavior_off": False, "ioav_off": False,
    "script_off": False, "archive_off": False, "cloud_off": False, "puas_off": False,
    "tamper_api": True, "tamper_reg": 4, "engine_ver": "1.1.2400.7",
    "product_ver": "4.18.24090.11", "service_ver": "1.1.24090.11",
    "definitions": "10/15/2026 8:12:33 AM", "off_reason": "Unknown",
    "av_enabled": True, "mode": "Active Mode", "last_quick": "10/14/2026",
}
STATUS_OFF = dict(STATUS_ON, rtp_off=True, behavior_off=True, tamper_api=False,
                  tamper_reg=0, off_reason="AdminAction")

d.IS_WINDOWS = True
d.is_admin = lambda: True

# --------------------------------------------------------------------------- #
print("\n=== A. Построение окна при включённой защите ===")
state = {"cur": STATUS_ON}
scripts = []


def ps_stub(script, timeout=90):
    scripts.append(script)
    if "ConvertTo-Json" in script:
        return 0, json.dumps(state["cur"]), ""
    if "ExclusionPath" in script:
        return 0, "OK", ""
    return 0, "OK", ""


d.run_ps = ps_stub
d.relaunch_as_admin = lambda: 0

rc = d.run_gui()
check("run_gui вернул 0", rc == 0)
check("mainloop был вызван", any(c[1] == "mainloop" for c in CALLS))

kinds = [w.kind for w in REGISTRY]
check("создано окно Tk", "Tk" in kinds)
check("созданы кнопки Button", kinds.count("Button") >= 4, str(kinds.count("Button")))
check("создан чекбокс 'доп. защита'", "Checkbutton" in kinds)
check("создан журнал Text", "Text" in kinds)
check("создан LabelFrame журнала", "LabelFrame" in kinds)
check("создан стиль ttk", "Style" in kinds)


def find_widgets(substr):
    return [w for w in REGISTRY
            if w.kind == "Button" and substr in str(w.kwargs.get("text", ""))]


btn_off = find_widgets("ОТКЛЮЧИТЬ")
btn_on = find_widgets("ВКЛЮЧИТЬ")
check("найдена кнопка ОТКЛЮЧИТЬ", len(btn_off) == 1)
check("найдена кнопка ВКЛЮЧИТЬ", len(btn_on) == 1)

labels = [w for w in REGISTRY if w.kind == "Label"]
title_txts = [w.current_text for w in labels]
check("в статусе показано 'ЗАЩИТА ВКЛЮЧЕНА'",
      any("ЗАЩИТА ВКЛЮЧЕНА" in t for t in title_txts), str(title_txts[:6]))
check("показана версия продукта", any("4.18.24090.11" in t for t in title_txts))
check("показан Tamper Protection", any("Tamper Protection" in t for t in title_txts))
check("показано предупреждение о безопасности",
      any("снижает защиту" in t for t in title_txts))

texts = [w for w in REGISTRY if w.kind == "Text"]
check("в журнал что-то записано", bool(texts) and bool(texts[0].text_content))
check("журнал содержит 'Статус обновлён'",
      bool(texts) and "Статус обновлён" in texts[0].text_content)

# --------------------------------------------------------------------------- #
print("\n=== B. Нажатие кнопки ОТКЛЮЧИТЬ ===")
REGISTRY.clear()
CALLS.clear()
scripts.clear()
fake_mb.SHOWN.clear()
state["cur"] = STATUS_OFF          # после применения защита станет выключена
rc = d.run_gui()
btn_off = find_widgets("ОТКЛЮЧИТЬ")
check("кнопка найдена", len(btn_off) == 1)

cmd = btn_off[0].kwargs.get("command")
check("у кнопки есть обработчик", callable(cmd))
cmd()  # имитируем клик

check("показано окно подтверждения", any(s[0] == "askyesno" for s in fake_mb.SHOWN))
check("вызван Set-MpPreference -DisableRealtimeMonitoring $true",
      any("DisableRealtimeMonitoring $true" in s for s in scripts),
      str([s[:60] for s in scripts])[:200])
check("вызваны доп. компоненты (чекбокс по умолчанию включён)",
      any("DisableBehaviorMonitoring" in s for s in scripts))

labels = [w.current_text for w in REGISTRY if w.kind == "Label"]
check("статус обновился на 'ЗАЩИТА ОТКЛЮЧЕНА'",
      any("ЗАЩИТА ОТКЛЮЧЕНА" in t for t in labels))

texts = [w for w in REGISTRY if w.kind == "Text"]
log = texts[0].text_content if texts else ""
check("в журнале запись об отключении", "ВЫКЛ" in log, log[:200])

# --------------------------------------------------------------------------- #
print("\n=== C. Нажатие кнопки ВКЛЮЧИТЬ ===")
REGISTRY.clear()
CALLS.clear()
scripts.clear()
state["cur"] = STATUS_ON
rc = d.run_gui()
btn_on = find_widgets("ВКЛЮЧИТЬ")
btn_on[0].kwargs["command"]()
check("вызван DisableRealtimeMonitoring $false",
      any("DisableRealtimeMonitoring $false" in s for s in scripts))
labels = [w.current_text for w in REGISTRY if w.kind == "Label"]
check("статус обновился на 'ЗАЩИТА ВКЛЮЧЕНА'",
      any("ЗАЩИТА ВКЛЮЧЕНА" in t for t in labels))

# --------------------------------------------------------------------------- #
print("\n=== D. Добавление исключения ===")
REGISTRY.clear()
scripts.clear()
fake_mb.SHOWN.clear()
state["cur"] = STATUS_ON
rc = d.run_gui()
excl = [w for w in REGISTRY if w.kind == "Button"
        and "исключения" in str(w.kwargs.get("text", ""))]
check("кнопка исключений найдена", len(excl) == 1)
excl[0].kwargs["command"]()
check("вызван Add-MpPreference -ExclusionPath",
      any("ExclusionPath" in s and "C:\\Games" in s for s in scripts))
check("показано информационное окно", any(s[0] == "info" for s in fake_mb.SHOWN))

# --------------------------------------------------------------------------- #
print("\n=== E. Ошибка Tamper Protection в GUI ===")
REGISTRY.clear()
scripts.clear()
state["cur"] = STATUS_ON


def ps_tamper(script, timeout=90):
    scripts.append(script)
    if "ConvertTo-Json" in script:
        return 0, json.dumps(state["cur"]), ""
    return 1, "", ("Set-MpPreference : Operation failed with the following error: "
                   "0x80070005 Unauthorized access to preference")


d.run_ps = ps_tamper
rc = d.run_gui()
btn_off = find_widgets("ОТКЛЮЧИТЬ")
btn_off[0].kwargs["command"]()
texts = [w for w in REGISTRY if w.kind == "Text"]
log = texts[0].text_content if texts else ""
check("в журнале объяснение про Tamper Protection", "Tamper Protection" in log, log[:300])
check("в журнале есть путь отключения Tamper", "Безопасность Windows" in log)

# --------------------------------------------------------------------------- #
print("\n=== F. Defender недоступен в GUI ===")
REGISTRY.clear()
state["cur"] = dict(STATUS_ON, available=False)
d.run_ps = ps_stub
rc = d.run_gui()
labels = [w.current_text for w in REGISTRY if w.kind == "Label"]
check("показано 'Defender недоступен'",
      any("Defender недоступен" in t for t in labels))

# --------------------------------------------------------------------------- #
print("\n=== G. Кнопка повышения прав (не админ) ===")
REGISTRY.clear()
CALLS.clear()
d.is_admin = lambda: False
elev = []
d.relaunch_as_admin = lambda: (elev.append(1), 0)[1]
rc = d.run_gui()
adm = [w for w in REGISTRY if w.kind == "Button"
       and "администратора" in str(w.kwargs.get("text", ""))]
check("кнопка 'Запустить от администратора' присутствует", len(adm) == 1)
d.is_admin = lambda: True

print(f"\n{'=' * 56}")
print(f"  РЕЗУЛЬТАТ GUI-смоука: {PASS} прошло, {FAIL} провалено")
print(f"{'=' * 56}\n")
sys.exit(1 if FAIL else 0)

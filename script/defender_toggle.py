#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Defender Toggle
=======================
Небольшое приложение для включения / отключения защиты Microsoft Defender
(защита в реальном времени) в Windows 10 / 11.

Режимы работы:
  * GUI  (по умолчанию)      — окно на tkinter с кнопками и статусом
  * CLI                      — defender_toggle.py on | off | status | toggle

Как это работает:
  Используется официальный PowerShell-модуль Defender (Set-MpPreference).
  Это единственный надёжный способ на Windows 11/10 22H2+ — правка реестра
  (DisableAntiSpyware) заблокирована функцией "Защита от несанкционированного
  вмешательства" (Tamper Protection).

Требования:
  * Windows 10 / 11
  * Права администратора (приложение само попросит повышение через UAC)
  * Отключённая "Защита от несанкционированного вмешательства", если
    нужно надолго выключить Defender (иначе Windows вернёт защиту сама)

Запуск:  python defender_toggle.py
         или двойной клик по "Запустить от администратора.bat"

Автор: создано ассистентом Arena.ai
Лицензия: MIT — используйте на свой страх и риск.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import textwrap

APP_NAME = "Windows Defender Toggle"
APP_VERSION = "1.0"

# --------------------------------------------------------------------------- #
#  Определение ОС и прав администратора
# --------------------------------------------------------------------------- #

IS_WINDOWS = os.name == "nt" or sys.platform.startswith("win")


def is_admin() -> bool:
    """True, если процесс запущен с правами администратора."""
    if not IS_WINDOWS:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _python_exe() -> str:
    """Путь к python.exe (или к самому .exe, если собрано PyInstaller'ом)."""
    if getattr(sys, "frozen", False):
        return sys.executable
    return sys.executable


def relaunch_as_admin() -> int:
    """Перезапускает приложение с правами администратора через UAC."""
    if not IS_WINDOWS:
        print("Повышение прав доступно только в Windows.")
        return 1

    try:
        if getattr(sys, "frozen", False):
            target, params = sys.executable, ""
        else:
            target = _python_exe()
            params = '"{}" {}'.format(
                os.path.abspath(sys.argv[0]),
                " ".join('"{}"'.format(a) for a in sys.argv[1:]),
            )
        # runas -> показ окна UAC; SW_SHOWNORMAL = 1
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", target, params, None, 1
        )
        if rc <= 32:
            print(f"Не удалось повысить права (код ошибки ShellExecute: {rc}).")
            return 1
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Ошибка при запросе прав администратора: {exc}")
        return 1


# --------------------------------------------------------------------------- #
#  Взаимодействие с PowerShell
# --------------------------------------------------------------------------- #

def _powershell_path() -> str | None:
    for cand in (
        shutil.which("powershell"),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ):
        if cand and os.path.exists(cand):
            return cand
    return None


def run_ps(script: str, timeout: int = 90) -> tuple[int, str, str]:
    """Выполняет PowerShell-скрипт. Возвращает (returncode, stdout, stderr)."""
    if not IS_WINDOWS:
        return 127, "", "Эта функция работает только в Windows."

    exe = _powershell_path()
    if not exe:
        return 127, "", "PowerShell не найден в системе."

    cmd = [
        exe,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]

    creationflags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creationflags = subprocess.CREATE_NO_WINDOW  # не мелькать консолью

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        return 124, "", "PowerShell не ответил за отведённое время (тайм-аут)."
    except Exception as exc:  # noqa: BLE001
        return 1, "", f"Не удалось запустить PowerShell: {exc}"

    return proc.returncode, _decode(proc.stdout), _decode(proc.stderr)


def _decode(data: bytes) -> str:
    """Аккуратно декодируем вывод PowerShell (консоль часто в CP866/CP1251)."""
    if not data:
        return ""
    for enc in ("utf-8", "cp866", "cp1251", "mbcs"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _ps_quote(text: str) -> str:
    """Экранирование строки для PowerShell."""
    return "'" + text.replace("'", "''") + "'"


# --------------------------------------------------------------------------- #
#  Основная логика Defender
# --------------------------------------------------------------------------- #

STATUS_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
Import-Module Defender -ErrorAction SilentlyContinue
$p = Get-MpPreference
$c = Get-MpComputerStatus
$out = [ordered]@{}
$out.available = ($null -ne $c)
if ($null -eq $p) {
    # Модуль Defender есть, но управление заблокировано (сторонний AV / Server)
    $out.available = $false
}
$out.rtp_off        = [bool]$p.DisableRealtimeMonitoring
$out.behavior_off   = [bool]$p.DisableBehaviorMonitoring
$out.ioav_off       = [bool]$p.DisableIOAVProtection
$out.script_off     = [bool]$p.DisableScriptScanning
$out.archive_off    = [bool]$p.DisableArchiveScanning
$out.cloud_off      = [bool]($p.MAPSSampling -eq 0)
$out.puas_off       = [bool]($p.PUAProtection -eq 'Disabled')
$out.tamper_api     = [bool]$c.IsTamperProtected
$out.tamper_reg     = [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection).TamperProtection
$out.engine_ver     = [string]$c.AMEngineVersion
$out.product_ver    = [string]$c.AMProductVersion
$out.service_ver    = [string]$c.AMServiceVersion
$out.definitions    = [string]$c.AntivirusSignatureLastUpdated
$out.off_reason     = [string]$c.RealTimeProtectionDisabledBy
$out.av_enabled     = [bool]$c.AntivirusEnabled
$out.mode           = [string]$c.AMRunningMode
$out.last_quick     = [string]$c.QuickScanEndTime
Write-Output ($out | ConvertTo-Json -Compress)
"""


def get_status() -> dict:
    """Снимок состояния Microsoft Defender.

    Возвращает словарь, где ``rtp`` = True, если защита в реальном времени
    включена; ``*_off`` = True, если соответствующий компонент отключён.
    """
    rc, out, err = run_ps(STATUS_PS)
    result = {
        "ok": False,
        "available": False,
        "raw_stdout": out.strip(),
        "raw_stderr": err.strip(),
        "returncode": rc,
        "rtp": None,
        "tamper": None,
        "engine_ver": "",
        "product_ver": "",
        "service_ver": "",
        "definitions": "",
        "off_reason": "",
        "mode": "",
        "last_quick": "",
        "admin": is_admin(),
    }

    text = out.strip()
    start = text.find("{")
    if start < 0:
        return result

    try:
        data = json.loads(text[start:text.rfind("}") + 1])
    except json.JSONDecodeError:
        return result

    result["ok"] = True
    result["available"] = bool(data.get("available", True))
    result["rtp"] = not bool(data.get("rtp_off"))
    result["behavior"] = not bool(data.get("behavior_off"))
    result["onaccess"] = not bool(data.get("ioav_off"))
    result["script_scan"] = not bool(data.get("script_off"))
    result["archive_scan"] = not bool(data.get("archive_off"))
    result["tamper"] = bool(data.get("tamper_api") or data.get("tamper_reg"))
    result["engine_ver"] = str(data.get("engine_ver", ""))
    result["product_ver"] = str(data.get("product_ver", ""))
    result["service_ver"] = str(data.get("service_ver", ""))
    result["definitions"] = str(data.get("definitions", ""))
    result["off_reason"] = str(data.get("off_reason", ""))
    result["mode"] = str(data.get("mode", ""))
    result["last_quick"] = str(data.get("last_quick", ""))
    return result


def set_realtime(enabled: bool) -> dict:
    """Включает (enabled=True) или отключает защиту в реальном времени."""
    value = "$false" if enabled else "$true"
    script = (
        "$ErrorActionPreference='Stop';"
        "Import-Module Defender -ErrorAction Stop;"
        f"Set-MpPreference -DisableRealtimeMonitoring {value};"
        "Write-Output 'OK'"
    )
    rc, out, err = run_ps(script)
    text = (out + "\n" + err).strip()
    return {
        "ok": rc == 0 and "OK" in out,
        "message": _friendly_error(text, enabled),
        "returncode": rc,
        "detail": text,
    }


def set_extra_protection(enabled: bool) -> dict:
    """
    Дополнительный набор: поведенческий мониторинг, проверка архивов,
    проверка скачанных файлов (IOAV), проверка скриптов.
    Полезно, если одного DisableRealtimeMonitoring недостаточно.
    """
    v = "$false" if enabled else "$true"
    script = (
        "$ErrorActionPreference='Continue';"
        "Import-Module Defender -ErrorAction SilentlyContinue;"
        f"Set-MpPreference -DisableBehaviorMonitoring {v}"
        f" -DisableIOAVProtection {v} -DisableScriptScanning {v}"
        f" -DisableArchiveScanning {v};"
        "Write-Output 'DONE'"
    )
    rc, out, err = run_ps(script)
    return {
        "ok": "DONE" in out,
        "message": _friendly_error((out + "\n" + err).strip(), enabled),
        "returncode": rc,
        "detail": (out + "\n" + err).strip(),
    }


def add_exclusion(path: str) -> dict:
    """Добавляет папку/файл в исключения (часто нужнее, чем полное отключение)."""
    script = (
        "$ErrorActionPreference='Stop';"
        f"Add-MpPreference -ExclusionPath {_ps_quote(path)};"
        "Write-Output 'OK'"
    )
    rc, out, err = run_ps(script)
    return {
        "ok": rc == 0 and "OK" in out,
        "message": (out + "\n" + err).strip() or "Готово",
        "returncode": rc,
    }


def _diag_text(st: dict) -> str:
    """Склеивает stdout+stderr из снимка статуса для диагностики."""
    parts = [p for p in (st.get("raw_stdout"), st.get("raw_stderr")) if p]
    return "\n".join(parts) or "нет данных"


def _friendly_error(text: str, enabled: bool) -> str:
    """Переводит типовые ошибки PowerShell в понятный русский текст."""
    low = text.lower()
    action = "включить" if enabled else "отключить"

    if "access is denied" in low or "access denied" in low or "отказано в доступе" in low:
        return (
            f"Отказано в доступе. Чтобы {action} защиту, запустите приложение "
            "от имени администратора."
        )
    if "unauthorized access" in low or "tamper" in low or "protected from tampering" in low:
        return (
            "Windows заблокировала изменение: включена «Защита от "
            "несанкционированного вмешательства» (Tamper Protection).\n"
            "Отключите её вручную: Безопасность Windows → Защита от вирусов и угроз → "
            "Параметры защиты от вирусов и угроз → Управление настройками → "
            "Защита от несанкционированного вмешательства — Выкл. "
            "Затем повторите попытку."
        )
    if ("not recognized as the name of a cmdlet" in low
            or "module 'defender'" in low
            or "modulenotfound" in low.replace(" ", "")
            or ("could not find" in low and "defender" in low)):
        return (
            "Модуль управления Defender недоступен в этой системе (возможно, "
            "установлен сторонний антивирус или это редакция Windows без "
            "компонента Defender)."
        )
    if "another antivirus" in low or "third" in low or "passive" in low:
        return (
            "Defender работает в пассивном режиме — активен сторонний антивирус. "
            "Управлять им нужно из его собственного интерфейса."
        )
    if "operation failed" in low or "0x8" in low:
        return (
            "Операция отклонена системой. Чаще всего причина — Tamper Protection "
            "или групповые политики. Подробности в логе ниже."
        )
    if not text:
        return "Готово." if enabled else "Готово."
    return text


# --------------------------------------------------------------------------- #
#  Графический интерфейс (tkinter)
# --------------------------------------------------------------------------- #

def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("tkinter не установлен — доступен только режим командной строки.")
        print("Используйте: python defender_toggle.py --help")
        return 1

    if not IS_WINDOWS:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            APP_NAME,
            "Эта программа работает только в Windows.\n"
            "Сейчас запущена не-Windows система, поэтому управление "
            "Microsoft Defender недоступно.",
        )
        root.destroy()
        return 1

    ACCENT_OFF = "#c0392b"
    ACCENT_ON = "#1e8449"
    BG = "#1e1f26"
    FG = "#e8e9ed"
    CARD = "#282a34"
    MUTED = "#9aa0ae"

    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.geometry("660x560")
    root.minsize(620, 520)
    root.configure(bg=BG)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TProgressbar", troughcolor=CARD, background="#4a90d9",
                    bordercolor=CARD, lightcolor="#4a90d9", darkcolor="#4a90d9")

    # --- шапка ----------------------------------------------------------- #
    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", padx=22, pady=(20, 6))

    tk.Label(header, text="🛡  Microsoft Defender", bg=BG, fg=FG,
             font=("Segoe UI", 17, "bold")).pack(anchor="w")
    tk.Label(header, text="Включение и отключение защиты в реальном времени",
             bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w")

    # --- статус ---------------------------------------------------------- #
    status_card = tk.Frame(root, bg=CARD)
    status_card.pack(fill="x", padx=22, pady=12)

    status_title = tk.Label(status_card, text="Статус: получение…", bg=CARD,
                            fg=FG, font=("Segoe UI", 13, "bold"))
    status_title.pack(anchor="w", padx=16, pady=(14, 2))

    status_sub = tk.Label(status_card, text="", bg=CARD, fg=MUTED,
                          font=("Segoe UI", 9), justify="left")
    status_sub.pack(anchor="w", padx=16, pady=(0, 14))

    # --- большое состояние ---------------------------------------------- #
    big = tk.Label(root, text="…", bg=BG, fg=MUTED, font=("Segoe UI", 11))
    big.pack(anchor="w", padx=26)

    # --- кнопки ---------------------------------------------------------- #
    btn_frame = tk.Frame(root, bg=BG)
    btn_frame.pack(fill="x", padx=22, pady=10)

    def make_btn(parent, text, command, color):
        b = tk.Button(parent, text=text, command=command, bg=color, fg="white",
                      activebackground=color, activeforeground="white",
                      font=("Segoe UI", 11, "bold"), relief="flat",
                      cursor="hand2", padx=14, pady=12, bd=0,
                      highlightthickness=0)
        return b

    btn_off = make_btn(btn_frame, "⛔  ОТКЛЮЧИТЬ защиту", lambda: apply(False), ACCENT_OFF)
    btn_off.pack(side="left", expand=True, fill="both", padx=(0, 5))

    btn_on = make_btn(btn_frame, "✅  ВКЛЮЧИТЬ защиту", lambda: apply(True), ACCENT_ON)
    btn_on.pack(side="left", expand=True, fill="both", padx=(5, 0))

    extra_frame = tk.Frame(root, bg=BG)
    extra_frame.pack(fill="x", padx=22, pady=(0, 8))

    var_extra = tk.BooleanVar(value=True)
    tk.Checkbutton(
        extra_frame,
        text="Также отключить поведенческий мониторинг, проверку скриптов, "
             "архивов и скачанных файлов",
        variable=var_extra, bg=BG, fg=MUTED, activebackground=BG,
        activeforeground=FG, selectcolor=CARD, font=("Segoe UI", 9),
        anchor="w", justify="left", wraplength=580,
    ).pack(fill="x")

    tools_frame = tk.Frame(root, bg=BG)
    tools_frame.pack(fill="x", padx=22, pady=(0, 8))

    def add_exclusion_dialog():
        path = filedialog.askdirectory(title="Выберите папку для исключения")
        if path:
            res = add_exclusion(path)
            messagebox.showinfo(APP_NAME, res["message"])
            refresh()

    tk.Button(tools_frame, text="＋ Добавить папку в исключения",
              command=add_exclusion_dialog, bg=CARD, fg=FG, relief="flat",
              font=("Segoe UI", 9), cursor="hand2", padx=10, pady=7,
              activebackground="#33364a", activeforeground=FG,
              bd=0).pack(side="left")

    tk.Button(tools_frame, text="⟳ Обновить статус", command=lambda: refresh(),
              bg=CARD, fg=FG, relief="flat", font=("Segoe UI", 9),
              cursor="hand2", padx=10, pady=7, activebackground="#33364a",
              activeforeground=FG, bd=0).pack(side="left", padx=8)

    if not is_admin():
        tk.Button(tools_frame, text="🔑 Запустить от администратора",
                  command=lambda: (relaunch_as_admin(), root.destroy()),
                  bg="#b8860b", fg="white", relief="flat", font=("Segoe UI", 9, "bold"),
                  cursor="hand2", padx=10, pady=7, bd=0).pack(side="right")

    # --- лог ------------------------------------------------------------- #
    log_frame = tk.LabelFrame(root, text=" Журнал ", bg=BG, fg=MUTED,
                              font=("Segoe UI", 9))
    log_frame.pack(fill="both", expand=True, padx=22, pady=(4, 12))

    log = tk.Text(log_frame, bg="#15161c", fg="#c9d1d9", relief="flat",
                  font=("Consolas", 9), height=7, wrap="word", bd=0,
                  padx=8, pady=6)
    log.pack(side="left", fill="both", expand=True)
    sb = ttk.Scrollbar(log_frame, command=log.yview)
    sb.pack(side="right", fill="y")
    log.configure(yscrollcommand=sb.set)
    log.configure(state="disabled")

    def write_log(msg: str) -> None:
        import datetime
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        log.configure(state="normal")
        log.insert("end", f"[{stamp}] {msg}\n")
        log.see("end")
        log.configure(state="disabled")

    # --- предупреждение -------------------------------------------------- #
    warn = (
        "⚠ Отключение антивируса снижает защиту компьютера. "
        "Windows может автоматически включить Defender обратно через несколько "
        "минут, если активна «Защита от несанкционированного вмешательства»."
    )
    tk.Label(root, text=textwrap.fill(warn, 92), bg=BG, fg="#d9a441",
             font=("Segoe UI", 8), justify="left").pack(fill="x", padx=24, pady=(0, 12))

    busy = {"flag": False}

    def apply(enabled: bool) -> None:
        if busy["flag"]:
            return
        action = "включить" if enabled else "отключить"
        if not enabled:
            if not messagebox.askyesno(
                APP_NAME,
                "Отключить защиту Microsoft Defender в реальном времени?\n\n"
                "Компьютер останется без активной антивирусной защиты.\n"
                "Продолжить?",
                icon="warning",
            ):
                write_log("Отмена: пользователь отказался отключать защиту.")
                return
        if not is_admin():
            write_log("Нет прав администратора — запрашиваю повышение (UAC)…")
            relaunch_as_admin()
            root.destroy()
            return

        busy["flag"] = True
        big.configure(text=f"Выполняю: {action} защиту…", fg=MUTED)
        write_log(f"{action.capitalize()} защиту в реальном времени…")
        root.after(30, lambda: _do_apply(enabled, action))

    def _do_apply(enabled: bool, action: str) -> None:
        try:
            res = set_realtime(enabled)
            write_log(res["message"] if not res["ok"] else
                      f"Защита в реальном времени: {'ВКЛ' if enabled else 'ВЫКЛ'} — выполнено.")
            if not res["ok"] and res.get("detail"):
                write_log("Технические подробности:\n" + res["detail"][:1200])

            if var_extra.get():
                extra = set_extra_protection(enabled)
                write_log(("Дополнительные компоненты защиты обновлены."
                           if extra["ok"] else
                           f"Доп. компоненты: {extra['message'][:400]}"))
        finally:
            busy["flag"] = False
            refresh()

    def refresh() -> None:
        busy["flag"] = True
        status_title.configure(text="Статус: проверка…", fg=MUTED)
        root.after(30, _do_refresh)

    def _do_refresh() -> None:
        st = get_status()
        busy["flag"] = False
        if not st["ok"]:
            status_title.configure(text="Статус: неизвестен", fg="#d9a441")
            detail = _diag_text(st)
            status_sub.configure(text=_friendly_error(detail, True)[:400])
            big.configure(text="Не удалось прочитать состояние Defender.", fg="#d9a441")
            btn_on.configure(state="normal", bg=ACCENT_ON)
            btn_off.configure(state="normal", bg=ACCENT_OFF)
            write_log("Не удалось получить статус. " + _friendly_error(detail, True)[:300])
            return

        if not st["available"]:
            status_title.configure(text="Статус: Defender недоступен", fg="#d9a441")
            status_sub.configure(
                text="Модуль управления Defender не отвечает. Возможные причины:\n"
                     "установлен сторонний антивирус, Defender в пассивном режиме,\n"
                     "редакция Windows без компонента Defender.")
            big.configure(text="Управление защитой в этой системе недоступно.", fg="#d9a441")
            write_log("Get-MpPreference вернул пустой результат — Defender недоступен.")
            return

        on = st["rtp"]
        tamper = st.get("tamper")
        if on:
            status_title.configure(text="Статус: ЗАЩИТА ВКЛЮЧЕНА", fg="#4ec98a")
            big.configure(text="Real-time защита активна — файлы проверяются при обращении.",
                          fg="#4ec98a")
            btn_off.configure(state="normal")
            btn_on.configure(state="disabled", bg="#3d5c48")
        else:
            status_title.configure(text="Статус: ЗАЩИТА ОТКЛЮЧЕНА", fg="#e8735f")
            big.configure(text="Real-time защита выключена — система не сканирует файлы.",
                          fg="#e8735f")
            btn_on.configure(state="normal", bg=ACCENT_ON)
            btn_off.configure(state="disabled", bg="#5c3a35")

        lines = []
        if tamper:
            lines.append("Tamper Protection: ВКЛ (изменения могут блокироваться/откатываться)")
        else:
            lines.append("Tamper Protection: выкл")
        if st.get("product_ver"):
            lines.append(f"Версия продукта: {st['product_ver']}   Движок: {st.get('engine_ver','')}")
        if st.get("definitions"):
            lines.append(f"Базы обновлены: {st['definitions']}")
        if st.get("off_reason") and st["off_reason"].lower() not in ("", "none", "0"):
            lines.append(f"Защиту отключил: {st['off_reason']}")
        lines.append("Права администратора: " + ("есть" if st["admin"] else "НЕТ"))
        status_sub.configure(text="\n".join(lines))
        write_log(f"Статус обновлён: real-time = {'ВКЛ' if on else 'ВЫКЛ'}, "
                  f"tamper = {'вкл' if tamper else 'выкл'}.")

    root.after(150, refresh)
    root.mainloop()
    return 0


# --------------------------------------------------------------------------- #
#  Режим командной строки
# --------------------------------------------------------------------------- #

CLI_HELP = f"""{APP_NAME} {APP_VERSION}

Использование:
  python defender_toggle.py                запустить графический интерфейс
  python defender_toggle.py status         показать текущее состояние Defender
  python defender_toggle.py off            отключить защиту в реальном времени
  python defender_toggle.py on             включить защиту в реальном времени
  python defender_toggle.py toggle         переключить (вкл <-> выкл)
  python defender_toggle.py exclude PATH   добавить папку/файл в исключения

Дополнительные ключи:
  --extra        вместе с real-time отключить/включить поведенческий
                 мониторинг, проверку скриптов, архивов и скачанных файлов
  --json         вывести результат в формате JSON (для скриптов)
  --force        не спрашивать подтверждение
  --no-admin     не запрашивать повышение прав автоматически
  -h, --help     эта справка

Примечания:
  * Нужны права администратора.
  * Если включена «Защита от несанкционированного вмешательства»
    (Tamper Protection), Windows отклонит изменения — сначала отключите её
    в приложении «Безопасность Windows».
  * Отключение защиты снижает безопасность системы.
"""


def _print_status_json(st: dict) -> None:
    print(json.dumps(st, ensure_ascii=False, indent=2))


def _print_status_human(st: dict) -> None:
    if not st["ok"]:
        print("Не удалось получить состояние Defender.")
        detail = _diag_text(st)
        if detail and detail != "нет данных":
            print(_friendly_error(detail, True))
        return
    if not st["available"]:
        print("Microsoft Defender недоступен в этой системе.")
        print("Возможные причины: сторонний антивирус, пассивный режим Defender,")
        print("либо редакция Windows без компонента Defender.")
        return
    print("=" * 56)
    print("  Microsoft Defender — текущее состояние")
    print("=" * 56)
    print(f"  Защита в реальном времени : {'ВКЛЮЧЕНА' if st['rtp'] else 'ОТКЛЮЧЕНА'}")
    print(f"  Tamper Protection         : {'включена' if st.get('tamper') else 'выключена'}")
    print(f"  Поведенческий мониторинг  : {'вкл' if st.get('behavior') else 'выкл'}")
    print(f"  Проверка скриптов         : {'вкл' if st.get('script_scan') else 'выкл'}")
    print(f"  Проверка архивов          : {'вкл' if st.get('archive_scan') else 'выкл'}")
    print(f"  Скачанные файлы (IOAV)    : {'вкл' if st.get('onaccess') else 'выкл'}")
    print(f"  Режим работы              : {st.get('mode') or '—'}")
    print(f"  Версия продукта           : {st.get('product_ver') or '—'}")
    print(f"  Версия движка             : {st.get('engine_ver') or '—'}")
    print(f"  Базы обновлены            : {st.get('definitions') or '—'}")
    print(f"  Последняя быстрая проверка: {st.get('last_quick') or '—'}")
    if st.get("off_reason") and st["off_reason"].lower() not in ("", "unknown"):
        print(f"  Защиту отключил           : {st['off_reason']}")
    print(f"  Права администратора      : {'да' if st['admin'] else 'НЕТ'}")
    print("=" * 56)


def run_cli(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    as_json = "--json" in flags
    extra = "--extra" in flags
    force = "--force" in flags
    no_admin = "--no-admin" in flags

    if not args or args[0] in ("-h", "--help", "help"):
        print(CLI_HELP)
        return 0

    command = args[0].lower()

    if not IS_WINDOWS:
        print("Ошибка: приложение работает только в Windows.")
        return 2

    if command == "status":
        st = get_status()
        _print_status_json(st) if as_json else _print_status_human(st)
        return 0 if st["ok"] else 1

    if command == "exclude":
        if len(args) < 2:
            print("Укажите путь: python defender_toggle.py exclude \"C:\\Games\"")
            return 2
        if not is_admin() and not no_admin:
            relaunch_as_admin()
            return 0
        res = add_exclusion(args[1])
        print("Готово." if res["ok"] else res["message"])
        return 0 if res["ok"] else 1

    if command not in ("on", "off", "toggle"):
        print(f"Неизвестная команда: {command}\n")
        print(CLI_HELP)
        return 2

    if command == "toggle":
        st = get_status()
        if not st["ok"]:
            print("Не удалось определить текущее состояние — переключение отменено.")
            return 1
        command = "on" if not st["rtp"] else "off"

    enable = command == "on"

    if not enable and not force:
        answer = input(
            "Отключить защиту Defender? Компьютер останется без антивируса. [д/Н] "
        ).strip().lower()
        if answer not in ("д", "y", "yes", "да"):
            print("Отменено.")
            return 0

    if not is_admin():
        if no_admin:
            print("Нет прав администратора. Запустите терминал от имени администратора.")
            return 3
        print("Запрашиваю права администратора (окно UAC)…")
        rc = relaunch_as_admin()
        return rc

    res = set_realtime(enable)
    if res["ok"]:
        print(f"Готово: защита в реальном времени {'ВКЛЮЧЕНА' if enable else 'ОТКЛЮЧЕНА'}.")
    else:
        print(f"Ошибка: {res['message']}")
        if res.get("detail"):
            print("\n--- вывод PowerShell ---")
            print(res["detail"])

    if extra:
        eres = set_extra_protection(enable)
        if eres["ok"]:
            print("Дополнительные компоненты защиты также обновлены.")
        else:
            print(f"Доп. компоненты: {eres['message'][:400]}")

    if as_json:
        print(json.dumps(res, ensure_ascii=False, indent=2))

    return 0 if res["ok"] else 1


# --------------------------------------------------------------------------- #

def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] not in ("-h", "--help", "help"):
        return run_cli(argv)
    if not argv:
        return run_gui()
    return run_cli(argv)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
        sys.exit(130)

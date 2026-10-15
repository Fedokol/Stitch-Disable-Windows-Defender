#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тесты логики defender_toggle.py без реальной Windows.
Подменяем run_ps() и IS_WINDOWS, проверяем парсинг статуса, ветки ошибок
и поведение CLI.  Запуск:  python3 test_defender_toggle.py
"""
import io
import json
import sys
from contextlib import redirect_stdout

import defender_toggle as d

PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def fake_ps(payload=None, rc=0, err="", raw=None):
    """Создаёт подмену run_ps, возвращающую заданный JSON."""
    body = raw if raw is not None else json.dumps(payload)

    def _stub(script, timeout=90):
        _stub.last_script = script
        return rc, body, err
    return _stub


STATUS_ON = {
    "available": True, "rtp_off": False, "behavior_off": False,
    "ioav_off": False, "script_off": False, "archive_off": False,
    "cloud_off": False, "puas_off": False,
    "tamper_api": True, "tamper_reg": 4,
    "engine_ver": "1.1.2400.7", "product_ver": "4.18.24090.11",
    "service_ver": "1.1.24090.11",
    "definitions": "10/15/2026 8:12:33 AM", "off_reason": "Unknown",
    "av_enabled": True, "mode": "Active Mode", "last_quick": "10/14/2026 3:00:00 AM",
}
STATUS_OFF = dict(STATUS_ON, rtp_off=True, behavior_off=True, tamper_api=False,
                  tamper_reg=0, off_reason="AdminAction")

print("\n=== 1. get_status(): защита включена ===")
d.IS_WINDOWS = True
d.run_ps = fake_ps(STATUS_ON)
st = d.get_status()
check("ok=True", st["ok"] is True)
check("available=True", st["available"] is True)
check("rtp=True (защита вкл)", st["rtp"] is True)
check("tamper=True", st["tamper"] is True)
check("behavior=True", st["behavior"] is True)
check("версия движка распознана", st["engine_ver"] == "1.1.2400.7")
check("базы распознаны", st["definitions"].startswith("10/15/2026"))
check("mode=Active Mode", st["mode"] == "Active Mode")

print("\n=== 2. get_status(): защита отключена ===")
d.run_ps = fake_ps(STATUS_OFF)
st = d.get_status()
check("rtp=False (защита выкл)", st["rtp"] is False)
check("tamper=False", st["tamper"] is False)
check("off_reason=AdminAction", st["off_reason"] == "AdminAction")

print("\n=== 3. get_status(): Defender недоступен ===")
d.run_ps = fake_ps(dict(STATUS_ON, available=False))
st = d.get_status()
check("ok=True, available=False", st["ok"] is True and st["available"] is False)

print("\n=== 4. get_status(): мусор / ошибка PowerShell ===")
d.run_ps = fake_ps(raw="Get-MpPreference : The term 'Get-MpPreference' is not recognized",
                   rc=1, err="ModuleNotFound")
st = d.get_status()
check("ok=False при не-JSON выводе", st["ok"] is False)
check("stderr сохранён", "ModuleNotFound" in st["raw_stderr"])
check("_friendly_error даёт понятный текст (по stdout+stderr)",
      "недоступен" in d._friendly_error(d._diag_text(st), True).lower())
check("_diag_text склеивает оба потока",
      "not recognized" in d._diag_text(st) and "ModuleNotFound" in d._diag_text(st))

print("\n=== 5. set_realtime(): формирует правильную команду ===")
d.run_ps = fake_ps(raw="OK")
res = d.set_realtime(False)
script = d.run_ps.last_script
check("отключение -> DisableRealtimeMonitoring $true",
      "DisableRealtimeMonitoring $true" in script)
check("res ok", res["ok"] is True)
res = d.set_realtime(True)
script = d.run_ps.last_script
check("включение -> DisableRealtimeMonitoring $false",
      "DisableRealtimeMonitoring $false" in script)
check("res ok", res["ok"] is True)

print("\n=== 6. set_extra_protection(): 4 компонента ===")
d.run_ps = fake_ps(raw="DONE")
res = d.set_extra_protection(False)
script = d.run_ps.last_script
for key in ("DisableBehaviorMonitoring", "DisableIOAVProtection",
            "DisableScriptScanning", "DisableArchiveScanning"):
    check(f"в команде есть {key}", f"{key} $true" in script)
check("res ok", res["ok"] is True)

print("\n=== 7. add_exclusion(): экранирование кавычек ===")
d.run_ps = fake_ps(raw="OK")
res = d.add_exclusion("C:\\It's a folder\\test")
script = d.run_ps.last_script
check("одинарная кавычка удвоена", "''" in script)
check("путь передан", "C:\\It" in script)
check("res ok", res["ok"] is True)

print("\n=== 8. _friendly_error(): ветки диагностики ===")
cases = [
    ("Access is denied", "администратор"),
    ("Unauthorized access to preference. ... protected from tampering", "Tamper"),
    ("The term 'Get-MpPreference' is not recognized as the name of a cmdlet", "недоступен"),
    ("Antivirus is in passive mode because another antivirus product", "пассивном"),
    ("Operation failed with the following error: 0x80070005", "отклонена"),
]
for text, expect in cases:
    msg = d._friendly_error(text, False)
    check(f"'{text[:35]}…' -> содержит '{expect}'", expect.lower() in msg.lower(), msg[:90])

print("\n=== 9. CLI status (человеческий вывод) ===")
d.run_ps = fake_ps(STATUS_ON)
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["status"])
out = buf.getvalue()
check("rc=0", rc == 0)
check("выводит ВКЛЮЧЕНА", "ВКЛЮЧЕНА" in out)
check("выводит Tamper Protection", "Tamper Protection" in out)
check("выводит Active Mode", "Active Mode" in out)

print("\n=== 10. CLI status --json ===")
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["status", "--json"])
data = json.loads(buf.getvalue())
check("валидный JSON", isinstance(data, dict))
check("rtp в JSON", data["rtp"] is True)

print("\n=== 11. CLI toggle: из состояния ВКЛ -> отключает ===")
calls = []


def seq_ps(script, timeout=90):
    calls.append(script)
    if "ConvertTo-Json" in script:
        return 0, json.dumps(STATUS_ON), ""
    return 0, "OK", ""


d.run_ps = seq_ps
d.is_admin = lambda: True
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["toggle", "--force"])
check("rc=0", rc == 0)
check("был вызов на отключение",
      any("DisableRealtimeMonitoring $true" in c for c in calls))
check("сообщение об отключении", "ОТКЛЮЧЕНА" in buf.getvalue())

print("\n=== 12. CLI toggle: из состояния ВЫКЛ -> включает ===")
calls = []


def seq_ps2(script, timeout=90):
    calls.append(script)
    if "ConvertTo-Json" in script:
        return 0, json.dumps(STATUS_OFF), ""
    return 0, "OK", ""


d.run_ps = seq_ps2
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["toggle", "--force"])
check("rc=0", rc == 0)
check("был вызов на включение",
      any("DisableRealtimeMonitoring $false" in c for c in calls))

print("\n=== 13. CLI off без прав администратора ===")
d.is_admin = lambda: False
d.relaunch_as_admin = lambda: 0
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["off", "--force", "--no-admin"])
check("rc=3 (нет прав)", rc == 3)
check("понятное сообщение", "администратор" in buf.getvalue().lower())

print("\n=== 14. CLI off: запрос подтверждения 'нет' ===")
d.is_admin = lambda: True
import builtins
_orig_input = builtins.input
builtins.input = lambda *a, **k: "н"
buf = io.StringIO()
try:
    with redirect_stdout(buf):
        rc = d.run_cli(["off"])
    check("отмена -> rc=0", rc == 0)
    check("сообщение 'Отменено'", "Отменено" in buf.getvalue())
except Exception as exc:  # noqa: BLE001
    check("отмена без исключения", False, str(exc))
finally:
    builtins.input = _orig_input

print("\n=== 15. CLI: неизвестная команда ===")
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["foobar"])
check("rc=2", rc == 2)
check("показана справка", "Использование" in buf.getvalue())

print("\n=== 16. Защита от запуска вне Windows ===")
d.IS_WINDOWS = False
buf = io.StringIO()
with redirect_stdout(buf):
    rc = d.run_cli(["status"])
check("rc=2 вне Windows", rc == 2)
check("сообщение про Windows", "Windows" in buf.getvalue())

print(f"\n{'=' * 56}")
print(f"  РЕЗУЛЬТАТ: {PASS} прошло, {FAIL} провалено")
print(f"{'=' * 56}\n")
sys.exit(1 if FAIL else 0)

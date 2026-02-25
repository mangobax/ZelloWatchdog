"""
Zello Watchdog Service
======================
Monitors that Zello is running and healthy on a Windows machine.
Takes escalating recovery actions (relaunch → reboot) when it isn't.

Configuration is loaded from config.ini (next to this script by default).
Telegram credentials can be set via config.ini or environment variables
(TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID).

Features:
  - Exponential backoff between relaunch attempts
  - Windows Event Log integration (optional, requires pywin32)
  - System health telemetry (CPU, RAM, disk reported with heartbeat)
  - Persistent state across service restarts (JSON state file)
  - Reboot loop protection (max N reboots per window)
  - Telegram command interface (/status, /restart, /pause, /resume, /report)
  - Daily summary report via Telegram
  - HTTP health endpoint for external monitoring

Usage:
    python zello_watchdog.py                   # uses config.ini next to script
    python zello_watchdog.py -c path/to.ini    # custom config path
"""

import os
import sys
import json
import time
import math
import signal
import logging
import argparse
import datetime
import threading
import subprocess
import configparser
import winreg
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import psutil
from logging.handlers import RotatingFileHandler

# Optional: Windows Event Log support (requires pywin32)
try:
    import win32evtlogutil  # type: ignore[import-untyped]
    import win32evtlog      # type: ignore[import-untyped]
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False



# =============================================================================
# AUTO-DETECT ZELLO INSTALL PATH
# =============================================================================

def _detect_zello_exe() -> str | None:
    """Try to find Zello.exe automatically via registry and common paths.

    Search order:
      1. Registry uninstall keys (HKLM 64-bit, HKLM 32-bit, HKCU)
      2. Common installation directories
      3. shutil.which() on PATH
    Returns the first valid path found, or None.
    """
    import shutil

    # --- Registry search ---
    uninstall_keys = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, base_key in uninstall_keys:
        try:
            with winreg.OpenKey(hive, base_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                if "zello" in display_name.lower():
                                    install_loc, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                                    candidate = Path(install_loc) / "Zello.exe"
                                    if candidate.exists():
                                        return str(candidate)
                            except OSError:
                                continue
                    except OSError:
                        break
        except OSError:
            continue

    # --- Common paths fallback ---
    common_paths = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Zello" / "Zello.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Zello" / "Zello.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Zello" / "Zello.exe",
    ]
    for p in common_paths:
        if p.exists():
            return str(p)

    # --- PATH search ---
    found = shutil.which("Zello.exe") or shutil.which("Zello")
    if found:
        return found

    return None


# =============================================================================
# CONFIGURATION LOADER
# =============================================================================

def _default_config_path() -> Path:
    """Return path to config.ini next to this script."""
    return Path(__file__).with_name("config.ini")


def load_config(config_path: Path | None = None) -> dict:
    """Load and validate configuration from an .ini file with env-var fallbacks.

    Returns a flat dict with typed values ready to use.
    """
    path = config_path or _default_config_path()
    if not path.exists():
        print(f"Config file not found: {path}", file=sys.stderr)
        sys.exit(1)

    cp = configparser.ConfigParser()
    cp.read(path, encoding="utf-8")

    appdata = os.getenv("APPDATA", "")

    cfg = {
        # [watchdog]
        "check_interval":         cp.getint("watchdog", "check_interval", fallback=5),
        "timeout_seconds":        cp.getint("watchdog", "timeout_seconds", fallback=60),
        "relaunch_after":         cp.getint("watchdog", "relaunch_after", fallback=15),
        "max_relaunch_attempts":  cp.getint("watchdog", "max_relaunch_attempts", fallback=3),
        "relaunch_verify_delay":  cp.getint("watchdog", "relaunch_verify_delay", fallback=5),
        "relaunch_backoff_base":  cp.getfloat("watchdog", "relaunch_backoff_base", fallback=2.0),
        "heartbeat_interval":     cp.getint("watchdog", "heartbeat_interval", fallback=7200),
        "self_watchdog_interval": cp.getint("watchdog", "self_watchdog_interval", fallback=60),
        "self_watchdog_timeout":  cp.getint("watchdog", "self_watchdog_timeout", fallback=180),

        # [zello]
        "wal_glob":      cp.get("zello", "wal_glob", fallback="*-wal"),
        "zello_dir":     Path(appdata) / "ZelloDesktop",
        "process_names": {
            n.strip().lower()
            for n in cp.get("zello", "process_names", fallback="zello.exe").split(",")
        },
        "task_name":     cp.get("zello", "task_name",
                                fallback="[Radio] Application \u2013 LaunchZelloGUI"),
        "exe_path":      (
            cp.get("zello", "exe_path", fallback="").strip()
            or _detect_zello_exe()
            or r"C:\Program Files (x86)\Zello\Zello.exe"  # ultimate fallback
        ),

        # [telegram]
        "telegram_min_interval": cp.getint("telegram", "min_interval", fallback=30),
        "telegram_bot_token": (
            cp.get("telegram", "bot_token", fallback="").strip()
            or os.getenv("TELEGRAM_BOT_TOKEN", "")
        ),
        "telegram_chat_id": (
            cp.get("telegram", "chat_id", fallback="").strip()
            or os.getenv("TELEGRAM_CHAT_ID", "")
        ),
        "telegram_polling_interval": cp.getint("telegram", "polling_interval", fallback=10),

        # [reboot_protection]
        "max_reboots_per_window": cp.getint("reboot_protection", "max_reboots_per_window",
                                            fallback=3),
        "reboot_window_seconds":  cp.getint("reboot_protection", "reboot_window_seconds",
                                            fallback=3600),

        # [daily_report]
        "daily_report_enabled": cp.getboolean("daily_report", "enabled", fallback=True),
        "daily_report_hour":    cp.getint("daily_report", "hour", fallback=8),
        "daily_report_minute":  cp.getint("daily_report", "minute", fallback=0),

        # [http]
        "http_enabled": cp.getboolean("http", "enabled", fallback=True),
        "http_port":    cp.getint("http", "port", fallback=8095),
        "http_host":    cp.get("http", "host", fallback="127.0.0.1"),

        # [event_log]
        "event_log_enabled": cp.getboolean("event_log", "enabled", fallback=True),

        # derived
        "site":       os.environ.get("COMPUTERNAME", "UNKNOWN"),
        "state_file": Path(__file__).with_name("watchdog_state.json"),
    }
    return cfg


# =============================================================================
# PERSISTENT STATE
# =============================================================================

class PersistentState:
    """Read/write a JSON file that survives service restarts and reboots."""

    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        try:
            self._path.write_text(
                json.dumps(self._data, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass

    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value
            self._save()

    def update(self, mapping: dict) -> None:
        with self._lock:
            self._data.update(mapping)
            self._save()

    @property
    def data(self) -> dict:
        with self._lock:
            return dict(self._data)


# =============================================================================
# STATISTICS TRACKER (for daily report)
# =============================================================================

class StatsTracker:
    """Accumulates counters for one reporting window."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.start_time = time.time()
            self.healthy_checks = 0
            self.unhealthy_checks = 0
            self.relaunches = 0
            self.successful_relaunches = 0
            self.reboots_requested = 0

    def record_check(self, healthy: bool) -> None:
        with self._lock:
            if healthy:
                self.healthy_checks += 1
            else:
                self.unhealthy_checks += 1

    def record_relaunch(self, success: bool) -> None:
        with self._lock:
            self.relaunches += 1
            if success:
                self.successful_relaunches += 1

    def record_reboot(self) -> None:
        with self._lock:
            self.reboots_requested += 1

    def snapshot(self) -> dict:
        with self._lock:
            total = self.healthy_checks + self.unhealthy_checks
            uptime_pct = (
                round(self.healthy_checks / total * 100, 1) if total > 0 else 0.0
            )
            return {
                "period_start": datetime.datetime.fromtimestamp(self.start_time)
                    .strftime("%Y-%m-%d %H:%M"),
                "total_checks": total,
                "healthy_checks": self.healthy_checks,
                "unhealthy_checks": self.unhealthy_checks,
                "uptime_pct": uptime_pct,
                "relaunches": self.relaunches,
                "successful_relaunches": self.successful_relaunches,
                "reboots_requested": self.reboots_requested,
            }


# =============================================================================
# HTTP HEALTH ENDPOINT
# =============================================================================

def _make_health_handler(watchdog: "ZelloWatchdog"):
    """Factory that creates an HTTP handler class with a reference to the watchdog."""

    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                body = json.dumps(watchdog.get_health_snapshot(), indent=2)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            # Suppress default console logging from HTTPServer
            pass

    return HealthHandler


# =============================================================================
# ZELLO WATCHDOG CLASS
# =============================================================================

class ZelloWatchdog:
    """Encapsulates all watchdog state, health-checking, and recovery logic."""

    def __init__(self, config: dict):
        self.cfg = config
        self.log = logging.getLogger("zello_watchdog")

        # Persistent state (survives restarts)
        self._state = PersistentState(config["state_file"])

        # Statistics for daily report
        self._stats = StatsTracker()

        # Mutable runtime state
        self._first_error_time: float | None = None
        self._relaunch_attempts: int = 0
        self._last_relaunch_time: float | None = None
        self._last_heartbeat_time: float = 0
        self._paused: bool = False
        self._last_daily_report_date: str | None = None
        self._start_time: float = time.time()

        # Last known health (for HTTP endpoint / commands)
        self._last_healthy: bool | None = None
        self._last_file_ok: bool | None = None
        self._last_process_ok: bool | None = None

        # Thread-safe heartbeat tracking for self-watchdog
        self._last_loop_heartbeat: float = time.time()
        self._heartbeat_lock = threading.Lock()

        # Telegram rate-limiting
        self._last_telegram_time: float = 0
        self._telegram_lock = threading.Lock()

        # Telegram command polling
        self._telegram_offset: int = 0

        # Shutdown flag
        self._shutdown_event = threading.Event()

    # ------------------------------------------------------------------
    # LOGGING SETUP
    # ------------------------------------------------------------------

    def setup_logging(self) -> None:
        """Configure root logger with rotating file handler + console + event log."""
        log_file = Path(__file__).with_suffix(".log")
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        # Rotating file handler
        fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setFormatter(fmt)

        # Console handler — force UTF-8 so emoji don't crash on cp1252 Windows consoles
        import io
        utf8_stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
        )
        ch = logging.StreamHandler(utf8_stdout)
        ch.setFormatter(fmt)

        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.addHandler(fh)
        root.addHandler(ch)

        # Windows Event Log handler (optional)
        if self.cfg["event_log_enabled"] and _HAS_WIN32:
            try:
                from logging.handlers import NTEventLogHandler
                eh = NTEventLogHandler("ZelloWatchdog")
                eh.setLevel(logging.WARNING)  # Only warnings+ go to Event Log
                eh.setFormatter(fmt)
                root.addHandler(eh)
                self.log.info("Windows Event Log handler registered.")
            except Exception as e:
                self.log.warning("Could not register Event Log handler: %s", e)

    # ------------------------------------------------------------------
    # WINDOWS EVENT LOG (direct writes for critical events)
    # ------------------------------------------------------------------

    def _write_event_log(self, msg: str, event_type: int = 1) -> None:
        """Write directly to Windows Event Log. event_type: 0=ERROR,1=WARNING,2=INFO."""
        if not self.cfg["event_log_enabled"] or not _HAS_WIN32:
            return
        try:
            evt_types = {
                0: win32evtlog.EVENTLOG_ERROR_TYPE,
                1: win32evtlog.EVENTLOG_WARNING_TYPE,
                2: win32evtlog.EVENTLOG_INFORMATION_TYPE,
            }
            win32evtlogutil.ReportEvent(
                "ZelloWatchdog",
                0,
                eventType=evt_types.get(event_type, win32evtlog.EVENTLOG_INFORMATION_TYPE),
                strings=[msg],
            )
        except Exception:
            pass  # Best-effort

    # ------------------------------------------------------------------
    # SYSTEM HEALTH TELEMETRY
    # ------------------------------------------------------------------

    def _get_system_telemetry(self) -> dict:
        """Collect CPU, RAM, and disk usage."""
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("C:\\")
            return {
                "cpu_pct": cpu,
                "ram_pct": round(mem.percent, 1),
                "ram_used_gb": round(mem.used / (1024**3), 1),
                "ram_total_gb": round(mem.total / (1024**3), 1),
                "disk_pct": round(disk.percent, 1),
                "disk_free_gb": round(disk.free / (1024**3), 1),
            }
        except Exception as e:
            self.log.error("Telemetry collection failed: %s", e)
            return {}

    def _format_telemetry(self, t: dict) -> str:
        if not t:
            return "telemetry unavailable"
        return (
            f"CPU {t['cpu_pct']}% | "
            f"RAM {t['ram_used_gb']}/{t['ram_total_gb']} GB ({t['ram_pct']}%) | "
            f"Disk C: {t['disk_free_gb']} GB free ({t['disk_pct']}% used)"
        )

    # ------------------------------------------------------------------
    # TELEGRAM
    # ------------------------------------------------------------------

    def send_telegram(self, msg: str, *, force: bool = False) -> None:
        """Send a Telegram message. Rate-limited unless *force* is True."""
        token = self.cfg["telegram_bot_token"]
        chat_id = self.cfg["telegram_chat_id"]
        if not token or not chat_id:
            return

        with self._telegram_lock:
            now = time.time()
            if not force and (now - self._last_telegram_time) < self.cfg["telegram_min_interval"]:
                self.log.debug("Telegram rate-limited, skipping: %s", msg[:80])
                return
            self._last_telegram_time = now

        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            requests.post(url, json={"chat_id": chat_id, "text": msg}, timeout=5)
        except Exception as e:
            self.log.error("[%s] Telegram alert failed: %s", self.cfg["site"], e)

    # ------------------------------------------------------------------
    # TELEGRAM COMMAND INTERFACE (polling)
    # ------------------------------------------------------------------

    def _poll_telegram_commands(self) -> None:
        """Background thread: poll Telegram for bot commands."""
        token = self.cfg["telegram_bot_token"]
        chat_id = self.cfg["telegram_chat_id"]
        interval = self.cfg["telegram_polling_interval"]

        if not token or not chat_id:
            return

        while not self._shutdown_event.is_set():
            try:
                url = f"https://api.telegram.org/bot{token}/getUpdates"
                resp = requests.get(
                    url,
                    params={"offset": self._telegram_offset, "timeout": interval},
                    timeout=interval + 5,
                )
                data = resp.json()
                for update in data.get("result", []):
                    self._telegram_offset = update["update_id"] + 1
                    msg = update.get("message", {})
                    text = msg.get("text", "").strip().lower()
                    msg_chat_id = str(msg.get("chat", {}).get("id", ""))

                    # Only respond to our configured chat
                    if msg_chat_id != str(chat_id):
                        continue

                    self._handle_telegram_command(text)

            except Exception as e:
                self.log.debug("Telegram polling error: %s", e)

            self._shutdown_event.wait(1)  # Small gap between polls

    def _handle_telegram_command(self, text: str) -> None:
        site = self.cfg["site"]

        if text == "/status":
            t = self._get_system_telemetry()
            running = self._last_process_ok if self._last_process_ok is not None else "?"
            wal = self._last_file_ok if self._last_file_ok is not None else "?"
            paused = "YES \u23f8\ufe0f" if self._paused else "no"
            uptime = int(time.time() - self._start_time)
            h, remainder = divmod(uptime, 3600)
            m, s = divmod(remainder, 60)
            self.send_telegram(
                f"\U0001f4cb [{site}] Status\n"
                f"  Process running: {running}\n"
                f"  WAL file present: {wal}\n"
                f"  Paused: {paused}\n"
                f"  Relaunch attempts: {self._relaunch_attempts}\n"
                f"  Watchdog uptime: {h}h {m}m {s}s\n"
                f"  {self._format_telemetry(t)}",
                force=True,
            )

        elif text == "/restart":
            self.send_telegram(f"\U0001f501 [{site}] Forcing Zello relaunch via command…", force=True)
            self._relaunch_attempts = 0
            self._try_relaunch()

        elif text == "/pause":
            self._paused = True
            self.send_telegram(f"\u23f8\ufe0f [{site}] Watchdog PAUSED — no recovery actions", force=True)

        elif text == "/resume":
            self._paused = False
            self._first_error_time = None
            self._relaunch_attempts = 0
            self.send_telegram(f"\u25b6\ufe0f [{site}] Watchdog RESUMED", force=True)

        elif text == "/report":
            self._send_daily_report(force=True)

        elif text == "/help":
            self.send_telegram(
                f"\U0001f4d6 [{site}] Commands:\n"
                "  /status  — current health + telemetry\n"
                "  /restart — force Zello relaunch now\n"
                "  /pause   — pause recovery actions\n"
                "  /resume  — resume recovery actions\n"
                "  /report  — send daily summary now\n"
                "  /help    — this message",
                force=True,
            )

    # ------------------------------------------------------------------
    # DAILY REPORT
    # ------------------------------------------------------------------

    def _check_daily_report(self) -> None:
        """Send daily report if it's past the configured time and hasn't been sent today."""
        if not self.cfg["daily_report_enabled"]:
            return

        now = datetime.datetime.now()
        today_str = now.strftime("%Y-%m-%d")

        if self._last_daily_report_date == today_str:
            return  # Already sent today

        target_hour = self.cfg["daily_report_hour"]
        target_minute = self.cfg["daily_report_minute"]

        if now.hour > target_hour or (now.hour == target_hour and now.minute >= target_minute):
            self._send_daily_report()
            self._last_daily_report_date = today_str

    def _send_daily_report(self, *, force: bool = False) -> None:
        site = self.cfg["site"]
        snap = self._stats.snapshot()
        t = self._get_system_telemetry()

        report = (
            f"\U0001f4ca [{site}] Daily Report\n"
            f"  Period: {snap['period_start']} → now\n"
            f"  Total checks: {snap['total_checks']}\n"
            f"  Healthy: {snap['healthy_checks']} | Unhealthy: {snap['unhealthy_checks']}\n"
            f"  Uptime: {snap['uptime_pct']}%\n"
            f"  Relaunches: {snap['relaunches']} "
            f"(successful: {snap['successful_relaunches']})\n"
            f"  Reboots requested: {snap['reboots_requested']}\n"
            f"  {self._format_telemetry(t)}"
        )
        self.send_telegram(report, force=True)
        self.log.info("Daily report sent.")

        # Reset stats for the next period
        self._stats.reset()

    # ------------------------------------------------------------------
    # SYSTEM
    # ------------------------------------------------------------------

    def _restart_windows(self) -> None:
        site = self.cfg["site"]
        self._stats.record_reboot()

        # Persist reboot timestamp for reboot-loop protection
        reboots = self._state.get("reboot_timestamps", [])
        reboots.append(time.time())
        self._state.set("reboot_timestamps", reboots)

        self._write_event_log(f"ZelloWatchdog [{site}] initiating system reboot", event_type=0)
        self.log.error("\U0001f504 [%s] Rebooting Windows", site)
        subprocess.run(["shutdown", "/r", "/t", "5"], shell=False)
        sys.exit(0)

    # ------------------------------------------------------------------
    # REBOOT LOOP PROTECTION
    # ------------------------------------------------------------------

    def _is_reboot_allowed(self) -> bool:
        """Return False if too many reboots have occurred within the configured window."""
        window = self.cfg["reboot_window_seconds"]
        max_reboots = self.cfg["max_reboots_per_window"]
        now = time.time()

        reboots: list[float] = self._state.get("reboot_timestamps", [])
        # Keep only recent timestamps
        recent = [t for t in reboots if now - t < window]
        # Persist the pruned list
        self._state.set("reboot_timestamps", recent)

        if len(recent) >= max_reboots:
            return False
        return True

    # ------------------------------------------------------------------
    # HEALTH CHECKS
    # ------------------------------------------------------------------

    def _is_process_running(self) -> bool:
        names = self.cfg["process_names"]
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"]
                if pname and pname.lower() in names:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def _kill_processes(self) -> bool:
        names = self.cfg["process_names"]
        killed = False
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"]
                if pname and pname.lower() in names:
                    proc.kill()
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return killed

    def _is_wal_present(self) -> bool:
        """Check for any WAL file matching the glob pattern in the Zello data dir."""
        try:
            return any(self.cfg["zello_dir"].glob(self.cfg["wal_glob"]))
        except OSError as e:
            self.log.error("Error checking WAL files: %s", e)
            return False

    def _check_health(self) -> tuple[bool, bool, bool]:
        file_ok = self._is_wal_present()
        process_ok = self._is_process_running()
        healthy = file_ok and process_ok
        # Cache for /status and HTTP endpoint
        self._last_healthy = healthy
        self._last_file_ok = file_ok
        self._last_process_ok = process_ok
        self._stats.record_check(healthy)
        return healthy, file_ok, process_ok

    # ------------------------------------------------------------------
    # HTTP HEALTH SNAPSHOT
    # ------------------------------------------------------------------

    def get_health_snapshot(self) -> dict:
        """Return a dict suitable for JSON serialisation via the HTTP endpoint."""
        uptime = int(time.time() - self._start_time)
        return {
            "site": self.cfg["site"],
            "healthy": self._last_healthy,
            "file_ok": self._last_file_ok,
            "process_ok": self._last_process_ok,
            "paused": self._paused,
            "relaunch_attempts": self._relaunch_attempts,
            "uptime_seconds": uptime,
            "telemetry": self._get_system_telemetry(),
            "stats": self._stats.snapshot(),
        }

    # ------------------------------------------------------------------
    # RELAUNCH (with exponential backoff)
    # ------------------------------------------------------------------

    def _launch_via_schtasks(self) -> bool:
        """Trigger Zello GUI launch via Task Scheduler. Returns True only on success."""
        task = self.cfg["task_name"]
        try:
            result = subprocess.run(
                ["schtasks", "/run", "/tn", task],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                self.log.error(
                    "schtasks /run failed (rc=%d): stdout=%r stderr=%r",
                    result.returncode, result.stdout.strip(), result.stderr.strip(),
                )
                return False
            self.log.warning("Triggered GUI launch via Task Scheduler: %r", result.stdout.strip())
            return True
        except subprocess.TimeoutExpired:
            self.log.error("schtasks /run timed out after 10 s")
            return False
        except Exception as e:
            self.log.error("Failed to trigger task: %s", e)
            return False

    def _backoff_delay(self) -> float:
        """Calculate exponential backoff delay based on attempt number.

        delay = relaunch_after * backoff_base ^ (attempt - 1)
        e.g. base=2: 15, 30, 60 s for attempts 1, 2, 3.
        """
        base_delay = self.cfg["relaunch_after"]
        backoff_base = self.cfg["relaunch_backoff_base"]
        exponent = max(0, self._relaunch_attempts - 1)
        return base_delay * math.pow(backoff_base, exponent)

    def _try_relaunch(self) -> bool:
        site = self.cfg["site"]
        max_att = self.cfg["max_relaunch_attempts"]
        verify_delay = self.cfg["relaunch_verify_delay"]

        if self._relaunch_attempts >= max_att:
            return False

        self._relaunch_attempts += 1
        self._last_relaunch_time = time.time()

        backoff = self._backoff_delay()
        self.send_telegram(
            f"\U0001f501 [{site}] Attempting to relaunch Zello "
            f"({self._relaunch_attempts}/{max_att}, next backoff {backoff:.0f} s)"
        )
        self.log.warning("[%s] Relaunch attempt %d (backoff=%.0f s)",
                         site, self._relaunch_attempts, backoff)

        self._write_event_log(
            f"ZelloWatchdog [{site}]: relaunch attempt {self._relaunch_attempts}/{max_att}",
            event_type=1,
        )

        self._kill_processes()
        time.sleep(1)  # Brief pause after kill before relaunch

        try:
            launched = self._launch_via_schtasks()
            if not launched:
                self.log.error("[%s] _launch_via_schtasks() returned failure", site)
                self._stats.record_relaunch(False)
                return False

            self.log.info("[%s] Waiting %d s to verify Zello started…", site, verify_delay)
            time.sleep(verify_delay)

            if self._is_process_running():
                self.log.info("[%s] Zello process confirmed running after relaunch", site)
                self.send_telegram(
                    f"\u2705 [{site}] Zello relaunched successfully "
                    f"(attempt {self._relaunch_attempts}/{max_att})"
                )
                self._stats.record_relaunch(True)
                return True
            else:
                self.log.warning(
                    "[%s] Zello process NOT detected after relaunch (attempt %d)",
                    site, self._relaunch_attempts,
                )
                self.send_telegram(
                    f"\u26a0\ufe0f [{site}] Relaunch attempt {self._relaunch_attempts} "
                    f"\u2014 process not detected after {verify_delay} s"
                )
                self._stats.record_relaunch(False)
                return False
        except Exception as e:
            self.log.error("[%s] Failed to launch Zello: %s", site, e)
            self._stats.record_relaunch(False)
            return False

    # ------------------------------------------------------------------
    # HEARTBEAT (with telemetry)
    # ------------------------------------------------------------------

    def _send_heartbeat(self) -> None:
        t = self._get_system_telemetry()
        self.send_telegram(
            f"\U0001fac0 [{self.cfg['site']}] ZelloWatchdog active\n"
            f"  {self._format_telemetry(t)}"
        )
        self.log.info("[%s] Heartbeat sent", self.cfg["site"])

    # ------------------------------------------------------------------
    # SELF-WATCHDOG (background thread)
    # ------------------------------------------------------------------

    def _self_watchdog(self) -> None:
        """Monitor the main loop; force-exit if it freezes."""
        interval = self.cfg["self_watchdog_interval"]
        timeout = self.cfg["self_watchdog_timeout"]
        site = self.cfg["site"]

        while not self._shutdown_event.is_set():
            self._shutdown_event.wait(interval)

            with self._heartbeat_lock:
                delta = time.time() - self._last_loop_heartbeat

            if delta > timeout:
                self.log.critical(
                    "\U0001f6d1 [%s] Self-watchdog triggered — main loop frozen for %d s",
                    site, int(delta),
                )
                self._write_event_log(
                    f"ZelloWatchdog [{site}]: main loop frozen for {int(delta)} s — force-restarting",
                    event_type=0,
                )
                self.send_telegram(
                    f"\U0001f6d1 [{site}] Internal watchdog detected freeze — restarting service",
                    force=True,
                )
                os._exit(1)  # HARD exit → NSSM restarts service

    # ------------------------------------------------------------------
    # HTTP SERVER (background thread)
    # ------------------------------------------------------------------

    def _start_http_server(self) -> None:
        """Start a lightweight HTTP server for health checks."""
        if not self.cfg["http_enabled"]:
            return

        host = self.cfg["http_host"]
        port = self.cfg["http_port"]

        try:
            handler_class = _make_health_handler(self)
            server = HTTPServer((host, port), handler_class)
            self.log.info("HTTP health endpoint listening on %s:%d/health", host, port)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        except Exception as e:
            self.log.warning("Failed to start HTTP health endpoint: %s", e)

    # ------------------------------------------------------------------
    # STARTUP VALIDATION
    # ------------------------------------------------------------------

    def validate_startup(self) -> None:
        """Validate critical prerequisites. Aborts on failure."""
        errors: list[str] = []

        zello_dir = self.cfg["zello_dir"]
        exe_path = Path(self.cfg["exe_path"])
        task_name = self.cfg["task_name"]

        if not zello_dir.exists():
            errors.append(f"Zello data directory not found: {zello_dir}")

        if not exe_path.exists():
            errors.append(f"Zello executable not found: {exe_path}")

        try:
            result = subprocess.run(
                ["schtasks", "/query", "/tn", task_name],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                errors.append(f"Scheduled task not found: {task_name!r}")
        except Exception as e:
            errors.append(f"Cannot query scheduled tasks: {e}")

        if not self.cfg["telegram_bot_token"] or not self.cfg["telegram_chat_id"]:
            self.log.warning("\u26a0\ufe0f Telegram credentials not set — notifications disabled")

        if errors:
            for err in errors:
                self.log.error("STARTUP CHECK FAILED: %s", err)
            self.log.error("Aborting due to startup validation failures.")
            print("\n".join(["STARTUP VALIDATION FAILED:"] + errors), file=sys.stderr)
            sys.exit(1)

        self.log.info("Startup validation passed.")

    # ------------------------------------------------------------------
    # SIGNAL HANDLING
    # ------------------------------------------------------------------

    def _handle_shutdown(self, sig, _frame) -> None:
        self.log.info("Received signal %s, shutting down…", sig)
        self._write_event_log(f"ZelloWatchdog shutting down (signal {sig})", event_type=2)
        self.send_telegram(
            f"\U0001f6d1 [{self.cfg['site']}] Watchdog shutting down (signal {sig})",
            force=True,
        )
        self._shutdown_event.set()
        sys.exit(0)

    # ------------------------------------------------------------------
    # MAIN LOOP
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Entry point: validate, register signals, start threads, loop."""
        self.setup_logging()
        self.validate_startup()

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        site = self.cfg["site"]
        self._write_event_log(f"ZelloWatchdog [{site}] started", event_type=2)
        self.send_telegram(f"\U0001f7e2 [{site}] ZelloWatchdog started.", force=True)
        self.log.info("\U0001f7e2 [%s] ZelloWatchdog started.", site)

        # Start background threads
        threading.Thread(target=self._self_watchdog, daemon=True).start()
        threading.Thread(target=self._poll_telegram_commands, daemon=True).start()
        self._start_http_server()

        while not self._shutdown_event.is_set():
            with self._heartbeat_lock:
                self._last_loop_heartbeat = time.time()

            try:
                healthy, file_ok, process_ok = self._check_health()

                # Daily report check
                self._check_daily_report()

                # ---- PAUSED MODE ----
                if self._paused:
                    time.sleep(self.cfg["check_interval"])
                    continue

                # ---- OK STATE ----
                if healthy:
                    if self._first_error_time is not None:
                        self.send_telegram(f"\u2705 [{site}] Zello recovered — file and process OK")
                        self.log.info("\u2705 [%s] Zello recovered. Error timer reset.", site)
                        self._write_event_log(f"ZelloWatchdog [{site}]: Zello recovered", event_type=2)
                    self._first_error_time = None
                    self._relaunch_attempts = 0

                    if time.time() - self._last_heartbeat_time >= self.cfg["heartbeat_interval"]:
                        self._send_heartbeat()
                        self._last_heartbeat_time = time.time()

                # ---- ERROR STATE ----
                else:
                    if self._first_error_time is None:
                        self._first_error_time = time.time()

                        reason = []
                        if not file_ok:
                            reason.append("file missing")
                        if not process_ok:
                            reason.append("process not running")

                        msg = f"\u26a0\ufe0f [{site}] Zello error detected — " + " + ".join(reason)
                        self.send_telegram(msg)
                        self.log.warning(msg)
                        self._write_event_log(f"ZelloWatchdog [{site}]: {msg}", event_type=1)

                    elapsed = time.time() - self._first_error_time
                    self.log.info(
                        "\u23f1 Error active for %d s (file_ok=%s, process_ok=%s)",
                        int(elapsed), file_ok, process_ok,
                    )

                    # Attempt relaunch with exponential backoff
                    current_backoff = self._backoff_delay()
                    if (
                        elapsed >= self.cfg["relaunch_after"]
                        and (
                            self._last_relaunch_time is None
                            or time.time() - self._last_relaunch_time > current_backoff
                        )
                    ):
                        self._try_relaunch()

                    # Hard reboot (with loop protection)
                    if elapsed >= self.cfg["timeout_seconds"]:
                        if self._is_reboot_allowed():
                            self.send_telegram(
                                f"\U0001f534 [{site}] Zello persistent error — rebooting system",
                                force=True,
                            )
                            self.log.error(
                                "\U0001f534 [%s] Persistent error. Rebooting system.", site
                            )
                            self._write_event_log(
                                f"ZelloWatchdog [{site}]: persistent error — rebooting system",
                                event_type=0,
                            )
                            self._restart_windows()
                        else:
                            # Reboot blocked — alert once
                            if not self._state.get("reboot_blocked_notified"):
                                self.send_telegram(
                                    f"\U0001f6ab [{site}] Reboot BLOCKED — "
                                    f"max {self.cfg['max_reboots_per_window']} reboots in "
                                    f"{self.cfg['reboot_window_seconds']} s already reached. "
                                    f"Manual intervention required.",
                                    force=True,
                                )
                                self.log.critical(
                                    "[%s] Reboot loop protection triggered — manual intervention needed",
                                    site,
                                )
                                self._write_event_log(
                                    f"ZelloWatchdog [{site}]: reboot loop protection activated",
                                    event_type=0,
                                )
                                self._state.set("reboot_blocked_notified", True)

                time.sleep(self.cfg["check_interval"])

            except Exception as e:
                self.log.exception("\U0001f6d1 Unhandled exception: %s", e)
                time.sleep(10)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Zello Watchdog Service")
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=None,
        help="Path to config.ini (default: config.ini next to this script)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    watchdog = ZelloWatchdog(cfg)
    watchdog.run()


if __name__ == "__main__":
    main()

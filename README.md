# Zello Watchdog

A Windows watchdog service that monitors [Zello](https://zello.com/) (push-to-talk radio app) and ensures it stays running 24/7. When Zello crashes or becomes unhealthy, the watchdog takes **escalating recovery actions** — from relaunching the app to rebooting the entire machine — and keeps you informed via Telegram.

Designed for headless/unattended Windows stations running Zello as critical infrastructure (dispatch desks, remote radio gateways, etc.).

---

## Features

| Feature | Description |
|---|---|
| **Health monitoring** | Checks every 5 s that the Zello process is running and its WAL database file exists |
| **Auto-relaunch** | Kills and relaunches Zello via Windows Task Scheduler with verification |
| **Exponential backoff** | Relaunch delays increase (15 s → 30 s → 60 s) to avoid hammering a broken system |
| **System reboot** | If Zello stays down past a timeout, the machine is rebooted automatically |
| **Reboot loop protection** | Limits reboots to N per time window (persisted to disk) to prevent infinite reboot cycles |
| **Telegram notifications** | Real-time alerts for errors, recoveries, relaunches, reboots, and heartbeats |
| **Telegram command interface** | `/status`, `/restart`, `/pause`, `/resume`, `/report`, `/help` |
| **Daily summary report** | Automated uptime %, relaunch count, and system telemetry report via Telegram |
| **System telemetry** | CPU, RAM, and disk usage included in heartbeats and reports |
| **HTTP health endpoint** | `GET /health` returns JSON — plug into Uptime Kuma, Nagios, etc. |
| **Windows Event Log** | Warnings and errors written to Event Viewer (optional, requires `pywin32`) |
| **Persistent state** | Reboot timestamps and flags survive restarts via a JSON state file |
| **Self-watchdog** | Background thread detects if the main loop freezes and force-restarts the service |
| **Auto-detect Zello path** | Finds `Zello.exe` via Windows registry, common paths, or `PATH` |

---

## Prerequisites

### 1. Windows OS

This project is designed for **Windows 10/11** (x64 or x86). It uses Windows-specific features: Task Scheduler, `shutdown.exe`, `winreg`, NSSM, and optionally the Windows Event Log.

### 2. Zello Desktop v2.6

Download and install **Zello for Windows v2.6** from [zello.com](https://zello.com/). Log in to your Zello account and ensure it works properly before setting up the watchdog.

> **Note:** After installing, run Zello at least once and log in. The watchdog checks for a WAL database file in `%APPDATA%\ZelloDesktop\` — this file is only created after Zello has been opened.

### 3. Python 3.12+

Download and install Python from [python.org](https://www.python.org/downloads/).

During installation:
- ✅ Check **"Add Python to PATH"**
- ✅ Check **"Install for all users"** (recommended for service use)

Verify the installation:
```powershell
python --version
```

### 4. NSSM (Non-Sucking Service Manager)

NSSM allows you to run the Python script as a Windows service that starts on boot and auto-restarts on failure.

1. Download from [nssm.cc](https://nssm.cc/download)
2. Extract and place `nssm.exe` somewhere on your PATH (e.g., `C:\Windows\System32\nssm.exe`)
3. Verify:
   ```powershell
   nssm version
   ```

### 5. Telegram Bot (optional but recommended)

To receive notifications:

1. Open Telegram and message [@BotFather](https://t.me/BotFather)
2. Send `/newbot` and follow the prompts to create a bot
3. Copy the **Bot Token** (e.g., `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`)
4. Message your new bot, then visit:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
   Find your **Chat ID** in the JSON response under `message.chat.id`

---

## Windows Host Preparation

Before installing the watchdog, prepare the Windows machine for unattended/headless operation.

### Set a Local Account Password

The local user account **must** have a password set. Scheduled tasks and Remote Desktop require it.

1. Press `Win + I` → **Accounts** → **Sign-in options** → **Password** → **Add**
2. Or via command prompt (elevated):
   ```powershell
   net user <USERNAME> <PASSWORD>
   ```

### Enable Automatic Login (netplwiz)

Since the machine runs headless, it needs to log in automatically on boot so Zello can start in the user's interactive session.

1. Press `Win + R`, type `netplwiz`, press Enter
2. **Uncheck** "Users must enter a user name and password to use this computer"
3. Click **Apply** → enter the user credentials when prompted
4. Restart to verify the machine logs in automatically

Alternatively, via the registry (elevated PowerShell):

```powershell
$username = "YOUR_USERNAME"
$password = "YOUR_PASSWORD"

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $username
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $password
```

> **Security note:** The password is stored in plaintext in the registry. This is acceptable for dedicated kiosk/radio machines on a private network, but not recommended for general-purpose workstations.

### Enable Remote Desktop

Enable Remote Desktop for remote management of the headless machine.

1. Press `Win + I` → **System** → **Remote Desktop** → toggle **On**
2. Or via PowerShell (elevated):
   ```powershell
   # Enable Remote Desktop
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
       -Name "fDenyTSConnections" -Value 0

   # Allow through firewall
   Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
   ```

**Disable NLA (Network Level Authentication)** — required if connecting from older clients or non-domain machines that have issues authenticating:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 0
```

> **Note:** Disabling NLA reduces security. Only do this if you experience connection issues on a trusted network.

### Power Configuration (Laptops)

If the machine is a laptop, prevent it from sleeping, hibernating, or turning off the display while on AC power:

```powershell
# Disable sleep on AC power (0 = never)
powercfg /change standby-timeout-ac 0

# Disable hibernation on AC power (0 = never)
powercfg /change hibernate-timeout-ac 0

# Turn off display after 5 minutes on AC power
powercfg /change monitor-timeout-ac 5

# Disable idle standby
powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0

# Apply changes
powercfg /setactive SCHEME_CURRENT
```

If you want the machine to sleep/wake on a schedule (e.g., sleep at 8 PM, wake at 7 AM), leave the power settings as-is and use the scheduled tasks in the `tasks/` folder instead — see [Step 4](#step-4-import-windows-scheduled-tasks).

> **Tip:** To prevent the laptop lid from triggering sleep, go to **Control Panel** → **Power Options** → **Choose what closing the lid does** → set to **"Do nothing"** for both battery and plugged in.

---

## Installation

### Step 1: Clone the repository

```powershell
git clone https://github.com/marcoagbarreto/ZelloWatchdog.git
cd ZelloWatchdog
```

### Step 2: Determine your architecture

Check whether your Python installation is 32-bit (x86) or 64-bit (x64):

```powershell
python -c "import struct; print(f'{struct.calcsize('P') * 8}-bit')"
```

### Step 3: Install Python dependencies

**For x64 (64-bit) Python:**
```powershell
pip install -r requirements_x64.txt
```

**For x86 (32-bit) Python:**
```powershell
pip install -r requirements_x86.txt
```

**Optional — Windows Event Log support:**
```powershell
pip install pywin32
```

### Step 4: Import Windows Scheduled Tasks

The `tasks/` folder contains three XML files for Windows Task Scheduler. Import them from an **elevated** (Administrator) PowerShell:

```powershell
schtasks /create /xml "tasks\[Radio] Application - LaunchZelloGUI.xml" /tn "[Radio] Application - LaunchZelloGUI"
schtasks /create /xml "tasks\[Radio] Power Management - Scheduled Sleep.xml" /tn "[Radio] Power Management - Scheduled Sleep"
schtasks /create /xml "tasks\[Radio] Power Management - Scheduled Wake.xml" /tn "[Radio] Power Management - Scheduled Wake"
```

**What each task does:**

| Task | Purpose |
|---|---|
| `[Radio] Application - LaunchZelloGUI` | Launches `Zello.exe` in the user's interactive session. The watchdog triggers this task via `schtasks /run` when relaunching Zello. This is required because a service (Session 0) cannot launch GUI apps directly in the user desktop. |
| `[Radio] Power Management - Scheduled Wake` | Wakes the PC from sleep daily at **7:00 AM** (adjustable). Uses `WakeToRun = true` so the BIOS/OS wakes the machine. |
| `[Radio] Power Management - Scheduled Sleep` | Hibernates the PC daily at **8:00 PM** (adjustable) using `shutdown /h`. |

> **Important:** After importing, open **Task Scheduler** (`taskschd.msc`) and update each task:
> - Right-click the task → **Properties** → **General** tab → click **"Change User or Group..."** and set it to **your local user account**
> - For the sleep/wake tasks, go to the **Triggers** tab and adjust the times to your schedule
> - The sleep and wake tasks are optional — only import them if you want automated power management

### Step 5: Configure the watchdog

Edit `config.ini`:

```ini
[zello]
# Leave exe_path blank to auto-detect, or set it explicitly
exe_path =
# Must match the imported task name exactly
task_name = [Radio] Application - LaunchZelloGUI

[telegram]
bot_token = YOUR_BOT_TOKEN_HERE
chat_id = YOUR_CHAT_ID_HERE
```

You can also set Telegram credentials as environment variables instead:
```powershell
setx TELEGRAM_BOT_TOKEN "YOUR_TOKEN" /M
setx TELEGRAM_CHAT_ID "YOUR_CHAT_ID" /M
```

See `config.ini` for all available options with detailed comments.

### Step 6: Test manually

Before installing as a service, run it interactively to verify everything works:

```powershell
python zello_watchdog.py
```

You should see:
```
2026-02-24 10:00:00 [INFO] Windows Event Log handler registered.
2026-02-24 10:00:00 [INFO] Startup validation passed.
2026-02-24 10:00:01 [INFO] 🟢 [MY-PC] ZelloWatchdog started.
2026-02-24 10:00:01 [INFO] HTTP health endpoint listening on 127.0.0.1:8095/health
2026-02-24 10:00:01 [INFO] [MY-PC] Heartbeat sent
```

Press `Ctrl+C` to stop.

### Step 7: Install as a Windows service with NSSM

Open an **elevated** (Administrator) command prompt:

```powershell
nssm install ZelloWatchdog "C:\Python312\python.exe" "C:\path\to\zello_watchdog.py"
```

> Replace the paths with your actual Python and script locations. Find your Python path with `where python`.

Configure the service for auto-restart:

```powershell
nssm set ZelloWatchdog AppStdout C:\path\to\zello_watchdog\stdout.log
nssm set ZelloWatchdog AppStderr C:\path\to\zello_watchdog\stderr.log
nssm set ZelloWatchdog AppRestartDelay 5000
nssm set ZelloWatchdog AppStopMethodSkip 6
nssm set ZelloWatchdog AppExit Default Restart
nssm set ZelloWatchdog DisplayName "Zello Watchdog Service"
nssm set ZelloWatchdog Description "Monitors Zello and restarts it if it stops running"
nssm set ZelloWatchdog Start SERVICE_AUTO_START
```

Start the service:

```powershell
nssm start ZelloWatchdog
```

Verify it's running:

```powershell
nssm status ZelloWatchdog
```

---

## Usage

### Telegram Commands

Once running, send commands to your Telegram bot:

| Command | Description |
|---|---|
| `/status` | Current health state, relaunch attempts, uptime, CPU/RAM/disk |
| `/restart` | Force an immediate Zello relaunch |
| `/pause` | Pause all recovery actions (monitoring continues) |
| `/resume` | Resume recovery actions |
| `/report` | Generate the daily summary report on demand |
| `/help` | List all commands |

**Example `/status` response:**
```
📋 [MY-PC] Status
  Process running: True
  WAL file present: True
  Paused: no
  Relaunch attempts: 0
  Watchdog uptime: 12h 34m 56s
  CPU 5.2% | RAM 3.8/16.0 GB (23.8%) | Disk C: 120.5 GB free (45.2% used)
```

### HTTP Health Endpoint

When enabled (default), the watchdog exposes a JSON endpoint:

```powershell
curl http://127.0.0.1:8095/health
```

Response:
```json
{
  "site": "MY-PC",
  "healthy": true,
  "file_ok": true,
  "process_ok": true,
  "paused": false,
  "relaunch_attempts": 0,
  "uptime_seconds": 45296,
  "telemetry": {
    "cpu_pct": 5.2,
    "ram_pct": 23.8,
    "ram_used_gb": 3.8,
    "ram_total_gb": 16.0,
    "disk_pct": 45.2,
    "disk_free_gb": 120.5
  },
  "stats": {
    "period_start": "2026-02-24 08:00",
    "total_checks": 9059,
    "healthy_checks": 9055,
    "unhealthy_checks": 4,
    "uptime_pct": 99.9,
    "relaunches": 1,
    "successful_relaunches": 1,
    "reboots_requested": 0
  }
}
```

Use this with monitoring tools like [Uptime Kuma](https://github.com/louislam/uptime-kuma), Nagios, Zabbix, etc.

### Custom Config Path

```powershell
python zello_watchdog.py -c "D:\configs\my_config.ini"
```

---

## How It Works

### Recovery Escalation Timeline

```
0s        Error detected → Telegram alert
          |
15s       Kill Zello → Relaunch attempt #1 → Verify after 5s
          |
30s       Relaunch attempt #2 (exponential backoff)
          |
60s       Relaunch attempt #3 (exponential backoff)
          |          
60s+      All relaunches failed → REBOOT SYSTEM
          |
          (after reboot, if Zello still fails...)
          |
          Reboot loop protection kicks in after 3 reboots/hour
          → Telegram alert: "Manual intervention required"
```

### Monitoring Flow

1. **Every 5 seconds**, the main loop checks:
   - Is the `Zello.exe` process running?
   - Does a `*-wal` file exist in `%APPDATA%\ZelloDesktop\`?
2. **If both pass** → healthy. Reset error timers.
3. **If either fails** → start error timer, send Telegram alert.
4. **After 15 s** → kill Zello and relaunch via Task Scheduler, then verify the process started.
5. **Exponential backoff** → subsequent relaunches wait longer (15 s, 30 s, 60 s).
6. **After 60 s total error time** → reboot the machine (if allowed by reboot loop protection).
7. **Self-watchdog thread** → if the main loop freezes for 180 s, force-exit the process so NSSM restarts it.

---

## Project Structure

```
zello-watchdog/
├── zello_watchdog.py          # Main watchdog script
├── config.ini                 # Configuration file
├── requirements_x64.txt       # Python dependencies (64-bit)
├── requirements_x86.txt       # Python dependencies (32-bit)
├── tasks/
│   ├── [Radio] Application - LaunchZelloGUI.xml
│   ├── [Radio] Power Management - Scheduled Sleep.xml
│   └── [Radio] Power Management - Scheduled Wake.xml
└── README.md
```

**Runtime files** (created automatically):

| File | Purpose |
|---|---|
| `zello_watchdog.log` | Rotating log file (5 MB × 3 backups) |
| `watchdog_state.json` | Persistent state (reboot timestamps, flags) |

---

## Configuration Reference

All settings are in `config.ini`. See the inline comments in the file for details. Key sections:

| Section | What it controls |
|---|---|
| `[watchdog]` | Check interval, timeouts, relaunch attempts, backoff, heartbeat frequency |
| `[zello]` | WAL file glob, process name, scheduled task name, exe path |
| `[telegram]` | Bot credentials, rate limiting, command polling interval |
| `[reboot_protection]` | Max reboots per time window |
| `[daily_report]` | Enable/disable, time of day to send |
| `[http]` | Health endpoint host, port, enable/disable |
| `[event_log]` | Windows Event Log integration on/off |

---

## Troubleshooting

### "STARTUP VALIDATION FAILED: Zello data directory not found"
Zello has never been run. Open Zello manually, log in, and close it. Then retry.

### "STARTUP VALIDATION FAILED: Scheduled task not found"
The Windows Scheduled Task hasn't been imported. See [Step 4](#step-4-import-windows-scheduled-tasks).

### "UnicodeEncodeError: 'charmap' codec can't encode character"
This was fixed — the console handler now uses UTF-8. If you still see this on a very old Python version, upgrade to Python 3.12+.

### Zello relaunches but immediately dies
Check that the Task Scheduler task runs under the correct user account and that the user session is logged in (not just at the lock screen on some configurations). The `LaunchZelloGUI` task requires an **interactive session** (`InteractiveToken`).

### NSSM service shows "Paused" or "Stopped"
```powershell
nssm restart ZelloWatchdog
```
Check the log file (`zello_watchdog.log`) for details.

### No Telegram messages
- Verify your bot token and chat ID are correct
- Make sure you've sent at least one message to the bot first (bots can't initiate conversations)
- Check if the values are in `config.ini` or environment variables

---

## Uninstall

```powershell
# Stop and remove the service
nssm stop ZelloWatchdog
nssm remove ZelloWatchdog confirm

# Remove scheduled tasks
schtasks /delete /tn "[Radio] Application - LaunchZelloGUI" /f
schtasks /delete /tn "[Radio] Power Management - Scheduled Sleep" /f
schtasks /delete /tn "[Radio] Power Management - Scheduled Wake" /f
```

---

## License

This project is licensed under the [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)](https://creativecommons.org/licenses/by-nc-sa/4.0/).

You are free to share and adapt this project for **non-commercial purposes**, as long as you give appropriate credit and distribute any derivatives under the same license.

See the [LICENSE](LICENSE) file for details.

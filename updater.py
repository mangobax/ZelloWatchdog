import os
import sys
import shutil
import zipfile
import requests
import subprocess
from pathlib import Path
from datetime import datetime

# ==========================
# CONFIGURATION
# ==========================

REPO = "mangobax/ZelloWatchdog"  # CHANGE THIS
SERVICE_NAME = "ZelloWatchdog"
INSTALL_DIR = Path(__file__).parent
VERSION_FILE = INSTALL_DIR / "version.txt"
AUTO_UPDATE_FLAG = INSTALL_DIR / "auto_update.enabled"
STAGING_DIR = INSTALL_DIR / "_update_staging"
BACKUP_DIR = INSTALL_DIR / "_backup"

# Optional: for private repo
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # set in system env if needed

GITHUB_API = f"https://api.github.com/repos/{REPO}/releases/latest"


# ==========================
# HELPERS
# ==========================

def log(msg):
    print(f"[Updater] {msg}")


def get_current_version():
    if VERSION_FILE.exists():
        return VERSION_FILE.read_text().strip()
    return "0.0.0"


def get_latest_release():
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    r = requests.get(GITHUB_API, headers=headers, timeout=10)
    r.raise_for_status()
    data = r.json()

    return {
        "tag": data["tag_name"].lstrip("v"),
        "zip_url": data["zipball_url"]
    }


def stop_service():
    log("Stopping service...")
    subprocess.run(["nssm", "stop", SERVICE_NAME], check=False)


def start_service():
    log("Starting service...")
    subprocess.run(["nssm", "start", SERVICE_NAME], check=False)


def download_release(zip_url):
    log("Downloading release...")
    STAGING_DIR.mkdir(exist_ok=True)

    zip_path = STAGING_DIR / "release.zip"

    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    r = requests.get(zip_url, headers=headers, timeout=60)
    r.raise_for_status()

    with open(zip_path, "wb") as f:
        f.write(r.content)

    return zip_path


def extract_release(zip_path):
    log("Extracting release...")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(STAGING_DIR)


def backup_current_install():
    log("Creating backup...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / timestamp
    backup_path.mkdir(parents=True, exist_ok=True)

    for item in INSTALL_DIR.iterdir():
        if item.name in ("_update_staging", "_backup", "auto_update.enabled"):
            continue
        shutil.move(str(item), backup_path)

    return backup_path


def restore_config_if_needed(backup_path):
    old_config = backup_path / "config.ini"
    new_config = INSTALL_DIR / "config.ini"

    if old_config.exists() and not new_config.exists():
        shutil.copy(old_config, new_config)


def install_new_version():
    log("Installing new version...")

    # GitHub zipball extracts into a single root folder
    extracted_root = next(
        p for p in STAGING_DIR.iterdir()
        if p.is_dir()
    )

    for item in extracted_root.iterdir():
        shutil.move(str(item), INSTALL_DIR)


def write_version(version):
    VERSION_FILE.write_text(version)


def cleanup():
    shutil.rmtree(STAGING_DIR, ignore_errors=True)


# ==========================
# MAIN
# ==========================

def main():
    log("Checking for updates...")

    if not AUTO_UPDATE_FLAG.exists():
        log("Auto-update disabled (flag file missing).")
        return

    try:
        current = get_current_version()
        latest = get_latest_release()

        if latest["tag"] == current:
            log("Already up to date.")
            return

        log(f"Updating {current} → {latest['tag']}")

        stop_service()

        zip_path = download_release(latest["zip_url"])
        extract_release(zip_path)

        backup_path = backup_current_install()
        install_new_version()
        restore_config_if_needed(backup_path)
        write_version(latest["tag"])

        cleanup()

        start_service()

        log("Update successful.")

    except Exception as e:
        log(f"Update FAILED: {e}")
        log("Attempting to restart service...")
        start_service()
        sys.exit(1)


if __name__ == "__main__":
    main()
import os
import sys
import time
import sqlite3
import shutil
import platform
import json
import logging
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# --- CONFIGURATION ---
LOG_FILE_PATH = "browser_history.log" 
# STATE_FILE is no longer a constant path here, we determine it dynamically per user
SCAN_INTERVAL = 60

# --- CONSTANTS ---
CHROME_EPOCH_DIFF = 11644473600
MAC_EPOCH_DIFF = 978307200

class BrowserMonitor:
    def __init__(self):
        self.os_type = platform.system()
        self.user_home = Path.home()
        self.hostname = socket.gethostname()
        self.state = self.load_state()
        self.setup_logging()

    def setup_logging(self):
        # We still want the log in the shared folder C:\BrowserMonitor so the Wazuh Agent can find it easily
        # The Installer grants "Modify" permissions to this folder, so User1 can write to it.
        log_path = Path(LOG_FILE_PATH)
        if not log_path.is_absolute():
            # If relative, assumes C:\BrowserMonitor\ (script dir)
            script_dir = Path(__file__).parent
            log_path = script_dir / LOG_FILE_PATH

        try:
            if not log_path.parent.exists():
                log_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.logger = logging.getLogger("BrowserMonitor")
            self.logger.setLevel(logging.INFO)
            
            # Syslog Format
            syslog_fmt = f'%(asctime)s {self.hostname} browser-monitor: %(message)s'
            date_fmt = '%b %d %H:%M:%S'
            
            formatter = logging.Formatter(syslog_fmt, datefmt=date_fmt)
            
            fh = logging.FileHandler(str(log_path), encoding='utf-8')
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
            
            self.logger.info(f"Starting Browser Monitor. Logging to: {log_path}")

        except Exception as e:
            # If we can't log to file, we are flying blind.
            # But in background mode, print doesn't help much.
            pass

    def load_state(self):
        # FIX: Save state in the USER'S home directory, not the shared folder.
        # This prevents User1 from reading Admin's timestamps.
        state_path = self.user_home / "browser_monitor_state.json"
        if state_path.exists():
            try:
                with open(state_path, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_state(self):
        # FIX: Save state in the USER'S home directory.
        state_path = self.user_home / "browser_monitor_state.json"
        try:
            with open(state_path, 'w') as f:
                json.dump(self.state, f)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Error saving state to {state_path}: {e}")

    def get_browser_paths(self):
        paths = []
        if self.os_type == "Windows":
            local_app_data = os.environ.get('LOCALAPPDATA')
            app_data = os.environ.get('APPDATA')
            
            if local_app_data:
                paths.append(("Chrome", Path(local_app_data) / r"Google\Chrome\User Data"))
                paths.append(("Edge", Path(local_app_data) / r"Microsoft\Edge\User Data"))
                paths.append(("Brave", Path(local_app_data) / r"BraveSoftware\Brave-Browser\User Data"))
            
            if app_data:
                paths.append(("Opera", Path(app_data) / r"Opera Software\Opera Stable"))
                paths.append(("OperaGX", Path(app_data) / r"Opera Software\Opera GX Stable"))
                paths.append(("Firefox", Path(app_data) / r"Mozilla\Firefox\Profiles"))

        elif self.os_type == "Darwin":
            lib_support = self.user_home / "Library/Application Support"
            paths.append(("Chrome", lib_support / "Google/Chrome"))
            paths.append(("Edge", lib_support / "Microsoft Edge"))
            paths.append(("Firefox", lib_support / "Firefox/Profiles"))
            paths.append(("Safari", self.user_home / "Library/Safari"))
            paths.append(("Opera", lib_support / "com.operasoftware.Opera"))

        elif self.os_type == "Linux":
            config = self.user_home / ".config"
            mozilla = self.user_home / ".mozilla"
            paths.append(("Chrome", config / "google-chrome"))
            paths.append(("Edge", config / "microsoft-edge"))
            paths.append(("Chromium", config / "chromium"))
            paths.append(("Firefox", mozilla / "firefox"))
            paths.append(("Opera", config / "opera"))

        return paths

    def find_profiles(self):
        browser_paths = self.get_browser_paths()
        found_profiles = []

        for browser_name, browser_root in browser_paths:
            if not browser_root.exists(): continue

            if browser_name == "Safari":
                history_db = browser_root / "History.db"
                if history_db.exists():
                    found_profiles.append({
                        "browser": "Safari",
                        "profile_name": "Default",
                        "path": browser_root,
                        "db_file": "History.db",
                        "type": "safari"
                    })
                continue

            if browser_name == "Firefox":
                for item in browser_root.iterdir():
                    if item.is_dir() and (item / "places.sqlite").exists():
                        found_profiles.append({
                            "browser": browser_name,
                            "profile_name": item.name,
                            "path": item,
                            "db_file": "places.sqlite",
                            "type": "firefox"
                        })
                continue

            # Chromium/Opera
            if (browser_root / "History").exists():
                 found_profiles.append({
                    "browser": browser_name,
                    "profile_name": "Root/Default",
                    "path": browser_root,
                    "db_file": "History",
                    "type": "chrome"
                })

            if (browser_root / "Default" / "History").exists():
                 found_profiles.append({
                    "browser": browser_name,
                    "profile_name": "Default",
                    "path": browser_root / "Default",
                    "db_file": "History",
                    "type": "chrome"
                })
            
            for item in browser_root.glob("Profile *"):
                if item.is_dir() and (item / "History").exists():
                    found_profiles.append({
                        "browser": browser_name,
                        "profile_name": item.name,
                        "path": item,
                        "db_file": "History",
                        "type": "chrome"
                    })

        return found_profiles

    # --- TIME HELPERS ---
    def get_chrome_time(self, timestamp):
        if not timestamp: return "N/A"
        try:
            seconds = (timestamp / 1_000_000) - CHROME_EPOCH_DIFF
            dt = datetime.fromtimestamp(seconds, timezone.utc).astimezone()
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except: return str(timestamp)

    def get_firefox_time(self, timestamp):
        if not timestamp: return "N/A"
        try:
            seconds = timestamp / 1_000_000
            dt = datetime.fromtimestamp(seconds, timezone.utc).astimezone()
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except: return str(timestamp)

    def get_safari_time(self, timestamp):
        if not timestamp: return "N/A"
        try:
            unix_ts = timestamp + MAC_EPOCH_DIFF
            dt = datetime.fromtimestamp(unix_ts, timezone.utc).astimezone()
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except: return str(timestamp)

    # --- EXTENSION SCANNING ---
    def scan_extensions(self, profile):
        extensions = {}
        if profile["type"] == "chrome":
            ext_dir = profile["path"] / "Extensions"
            if ext_dir.exists():
                for item in ext_dir.iterdir():
                    if item.is_dir():
                        ext_id = item.name
                        versions = [d for d in item.iterdir() if d.is_dir()]
                        if not versions: continue
                        versions.sort(key=lambda x: x.name, reverse=True)
                        manifest = versions[0] / "manifest.json"
                        if manifest.exists():
                            try:
                                with open(manifest, 'r', encoding='utf-8', errors='ignore') as f:
                                    data = json.load(f)
                                    name = data.get('name', 'Unknown')
                                    if name.startswith("__MSG_"): name = f"{name} (Localized)"
                                    version = data.get('version', '0.0')
                                    extensions[ext_id] = {"name": name, "version": version}
                            except: pass
        elif profile["type"] == "firefox":
            json_path = profile["path"] / "extensions.json"
            if json_path.exists():
                try:
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for addon in data.get('addons', []):
                            if addon.get('active', False):
                                ext_id = addon.get('id', 'Unknown')
                                name = addon.get('defaultLocale', {}).get('name') or addon.get('name', 'Unknown')
                                version = addon.get('version', '0.0')
                                extensions[ext_id] = {"name": name, "version": version}
                except: pass
        return extensions

    def process_extensions(self, profile):
        current_exts = self.scan_extensions(profile)
        if not current_exts: return
        state_key = f"ext_{profile['browser']}_{profile['profile_name']}"
        known_exts = self.state.get(state_key, {})
        for ext_id, details in current_exts.items():
            if ext_id not in known_exts or known_exts[ext_id]["version"] != details["version"]:
                msg = f"[Extension] {profile['browser']} {profile['profile_name']} {details['name']} ({ext_id}) v{details['version']}"
                self.logger.info(msg)
        self.state[state_key] = current_exts

    # --- HISTORY PROCESSING ---
    def process_history(self, profile):
        db_path = profile["path"] / profile["db_file"]
        state_key = f"hist_{profile['browser']}_{profile['profile_name']}"
        last_scan_time = self.state.get(state_key, 0)
        
        # FIX: Use system temp directory for copies to avoid permission issues
        # User1 might not be able to delete/overwrite a temp file created by Admin in C:\BrowserMonitor
        temp_dir = Path(tempfile.gettempdir())
        temp_db = temp_dir / f"temp_{state_key}.sqlite"
        
        try:
            if not db_path.exists(): return
            shutil.copy2(db_path, temp_db)
        except Exception as e:
            # self.logger.error(f"Failed to copy DB {db_path}: {e}")
            return

        conn = None
        new_max_time = last_scan_time

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            rows = []

            if profile["type"] == "chrome":
                query = "SELECT last_visit_time, url, title FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time ASC"
                cursor.execute(query, (last_scan_time,))
                rows = cursor.fetchall()
            elif profile["type"] == "firefox":
                query = """SELECT h.visit_date, p.url, p.title FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id WHERE h.visit_date > ? ORDER BY h.visit_date ASC"""
                cursor.execute(query, (last_scan_time,))
                rows = cursor.fetchall()
            elif profile["type"] == "safari":
                scan_threshold = 0
                if last_scan_time > 0: scan_threshold = last_scan_time - MAC_EPOCH_DIFF
                query = """SELECT v.visit_time, i.url, v.title FROM history_visits v JOIN history_items i ON v.history_item = i.id WHERE v.visit_time > ? ORDER BY v.visit_time ASC"""
                cursor.execute(query, (scan_threshold,))
                rows = cursor.fetchall()

            for row in rows:
                raw_time, url, title = row
                if raw_time > new_max_time: new_max_time = raw_time
                
                readable_time = ""
                if profile["type"] == "chrome": readable_time = self.get_chrome_time(raw_time)
                elif profile["type"] == "firefox": readable_time = self.get_firefox_time(raw_time)
                elif profile["type"] == "safari": readable_time = self.get_safari_time(raw_time)

                clean_title = (title or "No Title").replace('\n', ' ').replace('\r', '')
                self.logger.info(f"{readable_time} {profile['browser']} {profile['profile_name']} {url} {clean_title}")

        except Exception as e:
            self.logger.error(f"Error querying DB {profile['profile_name']}: {e}")
        finally:
            if conn: conn.close()
            if temp_db.exists(): 
                try: os.remove(temp_db)
                except: pass

        self.state[state_key] = new_max_time

    def run(self):
        try:
            while True:
                profiles = self.find_profiles()
                for profile in profiles:
                    self.process_extensions(profile)
                    self.process_history(profile)
                self.save_state()
                time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("Stopping Browser Monitor.")

if __name__ == "__main__":
    monitor = BrowserMonitor()
    monitor.run()

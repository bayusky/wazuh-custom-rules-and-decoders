import os
import sys
import time
import sqlite3
import shutil
import platform
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path

# --- CONFIGURATION ---
LOG_FILE_PATH = "browser_history.log" 
STATE_FILE = "browser_monitor_state.json"
SCAN_INTERVAL = 60

# --- CONSTANTS ---
CHROME_EPOCH_DIFF = 11644473600
MAC_EPOCH_DIFF = 978307200 # Seconds between 1970-01-01 and 2001-01-01

class BrowserMonitor:
    def __init__(self):
        self.os_type = platform.system()
        self.user_home = Path.home()
        self.hostname = socket.gethostname()
        self.state = self.load_state()
        self.setup_logging()

    def setup_logging(self):
        # Determine appropriate log path based on OS if relative path is used
        log_path = Path(LOG_FILE_PATH)
        if not log_path.is_absolute():
            # If relative, store in the same dir as the script (usually ~/.browser-monitor/)
            # This fixes the Read-only file system error on macOS LaunchAgents
            script_dir = Path(__file__).parent
            log_path = script_dir / LOG_FILE_PATH

        try:
            if not log_path.parent.exists():
                log_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.logger = logging.getLogger("BrowserMonitor")
            self.logger.setLevel(logging.INFO)
            
            # --- SYSLOG FORMATTING ---
            # Format: Month Day HH:MM:SS Hostname Tag: Message
            # Example: Nov 26 10:00:00 my-laptop browser-monitor: [Log Data]
            syslog_fmt = f'%(asctime)s {self.hostname} browser-monitor: %(message)s'
            date_fmt = '%b %d %H:%M:%S'
            
            formatter = logging.Formatter(syslog_fmt, datefmt=date_fmt)
            
            fh = logging.FileHandler(str(log_path), encoding='utf-8')
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

            # Console handler (Keep simple for debugging)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(ch)
            
            self.logger.info(f"Starting Browser Monitor. Logging to: {log_path}")

        except PermissionError:
            print(f"CRITICAL ERROR: No write permission for log file: {log_path}")
            sys.exit(1)

    def load_state(self):
        # Store state in same directory as script
        state_path = Path(__file__).parent / STATE_FILE
        if state_path.exists():
            try:
                with open(state_path, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_state(self):
        state_path = Path(__file__).parent / STATE_FILE
        try:
            with open(state_path, 'w') as f:
                json.dump(self.state, f)
        except Exception as e:
            print(f"Error saving state: {e}")

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
                paths.append(("Firefox", Path(app_data) / r"Mozilla\Firefox\Profiles"))

        elif self.os_type == "Darwin": # macOS
            lib_support = self.user_home / "Library/Application Support"
            paths.append(("Chrome", lib_support / "Google/Chrome"))
            paths.append(("Edge", lib_support / "Microsoft Edge"))
            paths.append(("Firefox", lib_support / "Firefox/Profiles"))
            # ADD SAFARI
            paths.append(("Safari", self.user_home / "Library/Safari"))
            
        elif self.os_type == "Linux":
            config = self.user_home / ".config"
            mozilla = self.user_home / ".mozilla"
            paths.append(("Chrome", config / "google-chrome"))
            paths.append(("Edge", config / "microsoft-edge"))
            paths.append(("Chromium", config / "chromium"))
            paths.append(("Firefox", mozilla / "firefox"))

        return paths

    def find_profiles(self):
        browser_paths = self.get_browser_paths()
        found_profiles = []

        for browser_name, browser_root in browser_paths:
            if not browser_root.exists():
                continue

            # Handle Safari (Single profile, specific DB name)
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

            # Handle Firefox
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

            # Handle Chromium (Chrome, Edge, Brave)
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
            # Safari uses seconds since 2001-01-01
            unix_ts = timestamp + MAC_EPOCH_DIFF
            dt = datetime.fromtimestamp(unix_ts, timezone.utc).astimezone()
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except: return str(timestamp)

    def process_profile(self, profile):
        db_path = profile["path"] / profile["db_file"]
        state_key = f"{profile['browser']}_{profile['profile_name']}"
        last_scan_time = self.state.get(state_key, 0)
        
        # Temp copy to avoid locks
        temp_db = Path(__file__).parent / f"temp_{state_key}.sqlite"
        try:
            shutil.copy2(db_path, temp_db)
        except (PermissionError, FileNotFoundError, OSError):
            # Often happens with Safari if Full Disk Access is not granted
            return

        conn = None
        new_max_time = last_scan_time

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            query = ""
            params = ()

            if profile["type"] == "chrome":
                query = "SELECT last_visit_time, url, title FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time ASC"
                params = (last_scan_time,)
            
            elif profile["type"] == "firefox":
                query = """
                    SELECT h.visit_date, p.url, p.title
                    FROM moz_historyvisits h
                    JOIN moz_places p ON h.place_id = p.id
                    WHERE h.visit_date > ?
                    ORDER BY h.visit_date ASC
                """
                params = (last_scan_time,)

            elif profile["type"] == "safari":
                # Safari time is float seconds since 2001. We must adjust our last_scan_time (Unix) to match.
                # If last_scan_time is 0, we start from 0.
                # If last_scan_time is a Unix timestamp, convert to Mac timestamp for comparison.
                scan_threshold = 0
                if last_scan_time > 0:
                     scan_threshold = last_scan_time - MAC_EPOCH_DIFF

                query = """
                    SELECT v.visit_time, i.url, v.title
                    FROM history_visits v
                    JOIN history_items i ON v.history_item = i.id
                    WHERE v.visit_time > ?
                    ORDER BY v.visit_time ASC
                """
                params = (scan_threshold,)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            for row in rows:
                raw_time, url, title = row
                
                # Logic to update max time seen (Store as Raw DB value to compare next time)
                if raw_time > new_max_time:
                    new_max_time = raw_time

                readable_time = ""
                if profile["type"] == "chrome":
                    readable_time = self.get_chrome_time(raw_time)
                elif profile["type"] == "firefox":
                    readable_time = self.get_firefox_time(raw_time)
                elif profile["type"] == "safari":
                    readable_time = self.get_safari_time(raw_time)

                clean_title = (title or "No Title").replace('\n', ' ').replace('\r', '')
                log_entry = f"{readable_time} {profile['browser']} {profile['profile_name']} {url} {clean_title}"
                self.logger.info(log_entry)

        except sqlite3.Error:
            pass
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
                    self.process_profile(profile)
                self.save_state()
                time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("Stopping Browser Monitor.")

if __name__ == "__main__":
    monitor = BrowserMonitor()
    monitor.run()

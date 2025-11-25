import os
import sys
import time
import sqlite3
import shutil
import platform
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# --- CONFIGURATION ---

# The output log file for Wazuh to monitor.
# Windows Example: r"C:\Program Files (x86)\ossec-agent\logs\browser_history.log"
# Linux/Mac Example: "/var/ossec/logs/browser_history.log" or "/tmp/browser_history.log"
# NOTE: Ensure the user running this script has WRITE permissions to this path.
LOG_FILE_PATH = "browser_history.log" 

# Where to store the state (last scanned timestamps) to prevent duplicates on restart
STATE_FILE = "browser_monitor_state.json"

# Scan interval in seconds
SCAN_INTERVAL = 60

# --- CONSTANTS ---
CHROME_EPOCH_DIFF = 11644473600
# Chrome/Edge use microseconds since 1601-01-01
# Firefox uses microseconds since 1970-01-01 (Unix epoch)

class BrowserMonitor:
    def __init__(self):
        self.os_type = platform.system()
        self.user_home = Path.home()
        self.profiles = []
        self.state = self.load_state()
        self.setup_logging()

    def setup_logging(self):
        """Sets up the logging to the specified file for Wazuh."""
        # Ensure directory exists
        log_path = Path(LOG_FILE_PATH)
        try:
            if not log_path.parent.exists():
                log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # We use a specific format for the log file as requested
            # Format: Timestamp browser-brand profile url title
            self.logger = logging.getLogger("BrowserMonitor")
            self.logger.setLevel(logging.INFO)
            
            # File handler
            fh = logging.FileHandler(LOG_FILE_PATH, encoding='utf-8')
            fh.setLevel(logging.INFO)
            # We format the message manually in the processing loop, so we just pass message here
            formatter = logging.Formatter('%(message)s') 
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

            # Console handler (for debugging/status)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(ch)
            
            self.logger.info(f"Starting Browser Monitor. Logging to: {LOG_FILE_PATH}")

        except PermissionError:
            print(f"CRITICAL ERROR: No write permission for log file: {LOG_FILE_PATH}")
            sys.exit(1)

    def load_state(self):
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_state(self):
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(self.state, f)
        except Exception as e:
            print(f"Error saving state: {e}")

    def get_browser_paths(self):
        """Identifies browser paths based on OS."""
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
            
        elif self.os_type == "Linux":
            config = self.user_home / ".config"
            mozilla = self.user_home / ".mozilla"
            
            paths.append(("Chrome", config / "google-chrome"))
            paths.append(("Edge", config / "microsoft-edge")) # Linux Edge
            paths.append(("Chromium", config / "chromium"))
            paths.append(("Firefox", mozilla / "firefox"))

        return paths

    def find_profiles(self):
        """Scans the browser paths for valid profiles (Default, Profile X, etc.)."""
        browser_paths = self.get_browser_paths()
        found_profiles = []

        for browser_name, browser_root in browser_paths:
            if not browser_root.exists():
                continue

            # Handle Firefox specifically (profiles are random strings)
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

            # Handle Chromium-based (Chrome, Edge, Brave)
            # Check 'Default'
            if (browser_root / "Default" / "History").exists():
                found_profiles.append({
                    "browser": browser_name,
                    "profile_name": "Default",
                    "path": browser_root / "Default",
                    "db_file": "History",
                    "type": "chrome"
                })
            
            # Check 'Profile X'
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
        """Convert WebKit timestamp to readable string."""
        if not timestamp: return "N/A"
        try:
            # Timestamp is microseconds since 1601-01-01
            seconds = (timestamp / 1_000_000) - CHROME_EPOCH_DIFF
            dt = datetime.fromtimestamp(seconds, timezone.utc).astimezone()
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(timestamp)

    def get_firefox_time(self, timestamp):
        """Convert Firefox timestamp to readable string."""
        if not timestamp: return "N/A"
        try:
            # Timestamp is microseconds since 1970-01-01
            seconds = timestamp / 1_000_000
            dt = datetime.fromtimestamp(seconds, timezone.utc).astimezone()
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(timestamp)

    def process_profile(self, profile):
        """Copies DB, Queries new entries, Logs them."""
        db_path = profile["path"] / profile["db_file"]
        
        # Unique ID for state tracking: Browser_ProfileName
        state_key = f"{profile['browser']}_{profile['profile_name']}"
        last_scan_time = self.state.get(state_key, 0)
        
        # Create temp copy
        temp_db = f"temp_{state_key}.sqlite"
        try:
            shutil.copy2(db_path, temp_db)
        except (PermissionError, FileNotFoundError):
            # Browser might be locking file heavily or file deleted
            return

        conn = None
        new_max_time = last_scan_time

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = ""
            params = ()

            if profile["type"] == "chrome":
                query = """
                    SELECT last_visit_time, url, title 
                    FROM urls 
                    WHERE last_visit_time > ? 
                    ORDER BY last_visit_time ASC
                """
                params = (last_scan_time,)
            
            elif profile["type"] == "firefox":
                # Join tables to get URL and Time
                query = """
                    SELECT h.visit_date, p.url, p.title
                    FROM moz_historyvisits h
                    JOIN moz_places p ON h.place_id = p.id
                    WHERE h.visit_date > ?
                    ORDER BY h.visit_date ASC
                """
                params = (last_scan_time,)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            for row in rows:
                raw_time, url, title = row
                
                # Update max time seen
                if raw_time > new_max_time:
                    new_max_time = raw_time

                # Format Time
                readable_time = ""
                if profile["type"] == "chrome":
                    readable_time = self.get_chrome_time(raw_time)
                else:
                    readable_time = self.get_firefox_time(raw_time)

                # Clean Title (remove newlines or pipes that might break one-liner)
                clean_title = (title or "No Title").replace('\n', ' ').replace('\r', '')
                
                # LOG FORMAT: Timestamp browser-brand profile url visited
                # Example: 2025-11-25 10:00:00 Chrome Default https://google.com Google Search
                log_entry = f"{readable_time} {profile['browser']} {profile['profile_name']} {url} {clean_title}"
                self.logger.info(log_entry)

        except sqlite3.Error as e:
            pass # Silent fail to retry next loop
        finally:
            if conn:
                conn.close()
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass

        # Update state
        self.state[state_key] = new_max_time

    def run(self):
        try:
            while True:
                profiles = self.find_profiles()
                if not profiles:
                    self.logger.debug("No browser profiles found.")
                
                for profile in profiles:
                    self.process_profile(profile)
                
                self.save_state()
                time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("Stopping Browser Monitor.")

if __name__ == "__main__":
    monitor = BrowserMonitor()
    monitor.run()

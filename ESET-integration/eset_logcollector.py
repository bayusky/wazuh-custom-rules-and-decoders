import requests
import json
import time
import logging

# === Configuration ===
USERNAME = "mail@email.example"
PASSWORD = "strongpassword"
IAM_URL = "https://eu.business-account.iam.eset.systems/oauth/token" #change eu to other region accordingly
API_BASE = "https://eu.incident-management.eset.systems"  #change eu to other region accordingly
OUTPUT_FILE = "/var/log/eset-integration.log"
INTERVAL = 300  # seconds between checks (e.g., 5 minutes)

# === Logging setup ===
logging.basicConfig(filename="eset-daemon.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def fetch_and_save_detections():
    try:
        # Get Access Token
        token_data = {
            "grant_type": "password",
            "username": USERNAME,
            "password": PASSWORD,
            "refresh_token": ""
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = requests.post(IAM_URL, data=token_data, headers=headers)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if not access_token:
            raise Exception("Failed to obtain access token")

        # Get Detections
        api_headers = {"Authorization": f"Bearer {access_token}"}
        detections_url = f"{API_BASE}/v1/detections"
        detections_resp = requests.get(detections_url, headers=api_headers)
        detections_resp.raise_for_status()
        detections = detections_resp.json().get("detections", [])

        # Save to file, each wrapped in "eset" with providerName
        with open(OUTPUT_FILE, "a") as f:  # append mode
            for detection in detections:
                detection["providerName"] = "ESET"
                wrapped = {"eset": detection}
                f.write(json.dumps(wrapped) + "\n")

        logging.info(f"{len(detections)} detections saved.")
    except Exception as e:
        logging.error(f"Error: {e}")

# === Daemon loop ===
if __name__ == "__main__":
    logging.info("ESET detection daemon started.")
    while True:
        fetch_and_save_detections()
        time.sleep(INTERVAL)

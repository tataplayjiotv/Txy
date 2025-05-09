import os
import logging
from flask import Flask, request, jsonify
import requests
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__)

# Base directory and provisioning file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICE_FILENAME = "xiaomi_mi_a1_15.0.0_60ceee88_8159_l3.wvd"
FILE_PATH = os.path.join(BASE_DIR, DEVICE_FILENAME)

def fetch_pssh_data(id_param: str, begin: str = None, end: str = None) -> Dict[str, Any]:
    """Fetches PSSH data from an external API, ensuring begin & end are correctly passed"""
    params = {"begin": begin or "", "end": end or ""}
    url = f"https://jasssaini.xyz/tplay/ja.php?id={id_param}"
    logging.info(f"Fetching PSSH data from {url} with params: {params}")
    
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError:
            logging.error("API response is not valid JSON")
            raise ValueError("API response is not valid JSON")
        
        logging.info(f"Received PSSH data: {data}")
        pssh_value = data.get("pssh")
        license_url = data.get("wvlicence")
        
        if not pssh_value or not license_url:
            error_msg = "Invalid response: Missing PSSH or license URL"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        return data
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Network request failed: {req_err}, Response: {response.text if 'response' in locals() else 'No response'}")
        raise

@app.route("/jass_keys", methods=["GET"])
def get_keys():
    """Endpoint to retrieve Widevine keys"""
    id_param = request.args.get("id")
    begin = request.args.get("begin")
    end = request.args.get("end")

    if not id_param:
        return jsonify({"error": "ID parameter is required"}), 400

    logging.info(f"Processing request for ID: {id_param}, Begin: {begin}, End: {end}")

    try:
        if not os.path.isfile(FILE_PATH):
            error_msg = "Provisioning file not found"
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 500

        try:
            device = Device.load(FILE_PATH)
        except Exception as device_err:
            error_msg = f"Failed to load device file: {device_err}"
            logging.error(error_msg)
            return jsonify({"error": error_msg}), 500

        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        logging.info(f"CDM session opened with session_id: {session_id}")

        # Fetch PSSH data
        data = fetch_pssh_data(id_param, begin, end)
        pssh_value = data.get("pssh")
        license_url = data.get("wvlicence")

        pssh = PSSH(pssh_value)
        challenge = cdm.get_license_challenge(session_id, pssh)
        logging.info("License challenge generated.")

        logging.info(f"Sending license challenge to: {license_url}")
        headers = {"Content-Type": "application/octet-stream"}
        license_response = requests.post(license_url, data=challenge, headers=headers, timeout=10)
        license_response.raise_for_status()
        logging.info("License response received from Widevine server.")

        cdm.parse_license(session_id, license_response.content)
        logging.info("License parsed successfully.")

        keys = []
        for key in cdm.get_keys(session_id):
            if key.type == "SIGNING":
                continue
            kid_hex = key.kid.hex().replace("-", "") if isinstance(key.kid, bytes) else str(key.kid).replace("-", "")
            key_hex = key.key.hex() if isinstance(key.key, bytes) else str(key.key)
            keys.append({"type": key.type, "kid": kid_hex, "key": key_hex})

        logging.info(f"Successfully retrieved {len(keys)} keys (SIGNING keys excluded).")
        return jsonify({"keys": keys})

    except requests.exceptions.RequestException as req_err:
        logging.error(f"Network request error occurred: {req_err}")
        return jsonify({"error": "Network request failed"}), 500

    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        try:
            if 'cdm' in locals() and 'session_id' in locals():
                cdm.close(session_id)
                logging.info(f"CDM session {session_id} closed.")
        except Exception as close_ex:
            logging.error(f"Failed to close CDM session: {close_ex}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

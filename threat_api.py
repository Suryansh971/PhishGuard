import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("THREAT_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses"


def scan_url(url):
    headers = {
        "x-apikey": API_KEY
    }

    data = {
        "url": url
    }

    response = requests.post(
        VT_URL,
        headers=headers,
        data=data,
        timeout=15
    )

    response.raise_for_status()

    return response.json()


def get_analysis(analysis_id):
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(
        f"{VT_ANALYSIS_URL}/{analysis_id}",
        headers=headers,
        timeout=15
    )

    response.raise_for_status()

    return response.json()


def wait_for_analysis(analysis_id, max_attempts=10):
    for attempt in range(max_attempts):

        result = get_analysis(analysis_id)

        status = (
            result
            .get("data", {})
            .get("attributes", {})
            .get("status")
        )

        print(f"Attempt {attempt + 1}: {status}")

        if status == "completed":
            return result

        time.sleep(3)

    return None


def get_stats(analysis_result):

    if not analysis_result:
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    stats = (
        analysis_result
        .get("data", {})
        .get("attributes", {})
        .get("stats", {})
    )

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }
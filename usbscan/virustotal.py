from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from usbscan.models import Finding

API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
FREE_TIER_DELAY_SECONDS = 15.5
REQUEST_TIMEOUT_SECONDS = 20


class VirusTotalClient:
    def __init__(self, api_key: str, delay_seconds: float = FREE_TIER_DELAY_SECONDS):
        self._api_key = api_key
        self._delay_seconds = delay_seconds
        self._last_request_at = 0.0

    def lookup(self, sha256: str) -> list[Finding]:
        self._wait_for_rate_limit()
        request = urllib.request.Request(API_URL.format(sha256=sha256), headers={"x-apikey": self._api_key})
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return []
            raise
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        if malicious >= 5:
            return [Finding("virustotal", "vt_detections", "critical", f"{malicious} engines flag this hash as malicious")]
        if malicious or suspicious:
            return [Finding("virustotal", "vt_low_detections", "medium", f"{malicious} malicious, {suspicious} suspicious")]
        return []

    def _wait_for_rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self._delay_seconds:
            time.sleep(self._delay_seconds - elapsed)
        self._last_request_at = time.monotonic()

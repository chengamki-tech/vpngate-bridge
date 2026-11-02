"""Fetch VPNGate's public OpenVPN candidates; fetching does not qualify them."""
import base64
import binascii
import csv
import io
import ipaddress
import re
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

API = "https://www.vpngate.net/api/iphone/"
MAX_RESPONSE = 32 * 1024 * 1024
MAX_CONFIG = 256 * 1024


@dataclass(frozen=True)
class Candidate:
    ip: str
    country: str
    uptime_ms: int
    advertised_speed_bps: int
    config: str


def parse_csv(data: str) -> Dict[str, List[Candidate]]:
    lines = data.splitlines()
    header = next((i for i, line in enumerate(lines) if line.startswith("#HostName,")), None)
    if header is None:
        raise ValueError("VPNGate CSV header missing")
    lines[header] = lines[header][1:]
    grouped = defaultdict(list)
    for row in csv.DictReader(io.StringIO("\n".join(lines[header:]))):
        try:
            ip = str(ipaddress.ip_address(row["IP"]))
            country = row["CountryShort"].upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                continue
            uptime = int(row["Uptime"])
            speed = int(row["Speed"])
            if uptime < 0 or speed < 0:
                continue
            raw = base64.b64decode(row["OpenVPN_ConfigData_Base64"], validate=True)
            if not raw or len(raw) > MAX_CONFIG:
                continue
            config = raw.decode("utf-8-sig")
            if "\x00" in config or not re.search(r"(?im)^\s*remote\s+\S+", config):
                continue
        except (KeyError, ValueError, TypeError, UnicodeError, binascii.Error):
            continue
        grouped[country].append(Candidate(ip, country, uptime, speed, config))
    return dict(grouped)


def fetch() -> Dict[str, List[Candidate]]:
    request = urllib.request.Request(API, headers={"User-Agent": "vpngate-bridge/0.1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        data = response.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise ValueError("VPNGate response exceeds size limit")
    return parse_csv(data.decode("utf-8-sig"))

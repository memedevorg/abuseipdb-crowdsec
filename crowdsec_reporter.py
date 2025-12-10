#!/usr/bin/env python3
"""
CrowdSec to AbuseIPDB Reporter
Reports locally-detected malicious IPs from CrowdSec to AbuseIPDB.
"""

import ipaddress
import hashlib
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import requests
import yaml

VERSION = "2.0.0"
USER_AGENT = f"CrowdSec-AbuseIPDB-Reporter/{VERSION}"
BASE_DIR = Path(__file__).parent

SCENARIO_CATEGORIES = {
    "ssh-bf": [18, 22],
    "ssh-slow-bf": [18, 22],
    "http-bf": [18, 21],
    "http-crawl-non_statics": [21],
    "http-probing": [21],
    "http-bad-user-agent": [21],
    "http-path-traversal-probing": [21],
    "http-sqli-probing": [21],
    "http-xss-probing": [21],
    "mysql-bf": [18],
    "mariadb-bf": [18],
    "postgres-bf": [18],
    "ftp-bf": [18, 5],
    "rdp-bf": [18],
    "smb-bf": [18],
    "telnet-bf": [18],
    "vnc-bf": [18],
    "default": [14],
}


@dataclass
class Config:
    crowdsec_url: str = "http://127.0.0.1:8080"
    crowdsec_api_key: str = ""
    abuseipdb_api_key: str = ""
    poll_interval: int = 300
    hours_back: int = 24
    daemon_mode: bool = True
    throttle_seconds: int = 10
    log_level: str = "INFO"
    log_file: str = "crowdsec_reporter.log"
    database_file: str = "crowdsec_reports.db"
    retention_days: int = 30
    machine_creds_file: str = "local_api_credentials.yaml"

    @classmethod
    def load(cls, config_path: Path) -> "Config":
        if not config_path.exists():
            return cls()
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            crowdsec_url=data.get("crowdsec", {}).get("url", cls.crowdsec_url),
            crowdsec_api_key=data.get("crowdsec", {}).get("api_key", cls.crowdsec_api_key),
            abuseipdb_api_key=data.get("abuseipdb", {}).get("api_key", cls.abuseipdb_api_key),
            poll_interval=data.get("settings", {}).get("poll_interval", cls.poll_interval),
            hours_back=data.get("settings", {}).get("hours_back", cls.hours_back),
            daemon_mode=data.get("settings", {}).get("daemon_mode", cls.daemon_mode),
            throttle_seconds=data.get("settings", {}).get("abuseipdb_throttle", cls.throttle_seconds),
            log_level=data.get("logging", {}).get("level", cls.log_level),
            log_file=data.get("logging", {}).get("file", cls.log_file),
            database_file=data.get("persistence", {}).get("database_file", cls.database_file),
            retention_days=data.get("persistence", {}).get("history_retention_days", cls.retention_days),
        )


@dataclass
class Alert:
    ip: str
    scenario: str
    alert_id: str = ""
    timestamp: str = ""


@dataclass
class FailedReport:
    ip: str
    scenario: str
    categories: list[int]
    comment: str
    retry_count: int


class Database:
    def __init__(self, db_path: Path, retention_days: int):
        self.db_path = db_path
        self.retention_days = retention_days
        self._init_schema()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reported_ips (
                    ip_hash TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    reported_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS failed_reports (
                    ip_hash TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    last_attempt TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reported_at ON reported_ips(reported_at)")

    @staticmethod
    def _hash(ip: str, scenario: str) -> str:
        return hashlib.sha256(f"{ip}:{scenario}".encode()).hexdigest()[:32]

    def is_reported(self, ip: str, scenario: str) -> bool:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM reported_ips WHERE ip_hash = ?",
                (self._hash(ip, scenario),)
            ).fetchone()
            return row is not None

    def mark_reported(self, ip: str, scenario: str):
        ip_hash = self._hash(ip, scenario)
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reported_ips (ip_hash, ip_address, scenario, reported_at) VALUES (?, ?, ?, ?)",
                (ip_hash, ip, scenario, now)
            )
            conn.execute("DELETE FROM failed_reports WHERE ip_hash = ?", (ip_hash,))

    def add_failed(self, ip: str, scenario: str, categories: list[int], comment: str):
        ip_hash = self._hash(ip, scenario)
        now = datetime.now(timezone.utc).isoformat()
        cats = ",".join(map(str, categories))
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT retry_count FROM failed_reports WHERE ip_hash = ?", (ip_hash,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE failed_reports SET last_attempt = ?, retry_count = ? WHERE ip_hash = ?",
                    (now, existing[0] + 1, ip_hash)
                )
            else:
                conn.execute(
                    "INSERT INTO failed_reports (ip_hash, ip_address, scenario, categories, comment, last_attempt) VALUES (?, ?, ?, ?, ?, ?)",
                    (ip_hash, ip, scenario, cats, comment, now)
                )

    def get_failed_for_retry(self, min_hours: int = 24, max_retries: int = 5) -> list[FailedReport]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=min_hours)).isoformat()
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT ip_address, scenario, categories, comment, retry_count FROM failed_reports WHERE last_attempt < ? AND retry_count < ?",
                (cutoff, max_retries)
            ).fetchall()
        return [
            FailedReport(ip=r[0], scenario=r[1], categories=[int(x) for x in r[2].split(",")], comment=r[3], retry_count=r[4])
            for r in rows
        ]

    def cleanup(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        with self._connection() as conn:
            conn.execute("DELETE FROM reported_ips WHERE reported_at < ?", (cutoff,))
            conn.execute("DELETE FROM failed_reports WHERE last_attempt < ?", (cutoff,))

    def stats(self) -> dict[str, int]:
        with self._connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM reported_ips").fetchone()[0]
            failed = conn.execute("SELECT COUNT(*) FROM failed_reports").fetchone()[0]
            recent_cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            recent = conn.execute("SELECT COUNT(*) FROM reported_ips WHERE reported_at > ?", (recent_cutoff,)).fetchone()[0]
        return {"total": total, "failed": failed, "last_24h": recent}


class CrowdSecClient:
    def __init__(self, config: Config, logger: logging.Logger):
        self.url = config.crowdsec_url.rstrip("/")
        self.api_key = config.crowdsec_api_key
        self.logger = logger
        self.jwt_token: str | None = None
        self._load_machine_creds(BASE_DIR / config.machine_creds_file)

    def _load_machine_creds(self, path: Path):
        self.machine_id: str | None = None
        self.machine_password: str | None = None
        if path.exists():
            try:
                with open(path) as f:
                    creds = yaml.safe_load(f)
                self.machine_id = creds.get("login")
                self.machine_password = creds.get("password")
                if creds.get("url"):
                    self.url = creds["url"].rstrip("/")
                self.logger.info("Loaded machine credentials")
            except Exception as e:
                self.logger.warning(f"Could not load machine credentials: {e}")

    def _authenticate(self) -> bool:
        if not self.machine_id or not self.machine_password:
            return False
        try:
            resp = requests.post(
                f"{self.url}/v1/watchers/login",
                json={"machine_id": self.machine_id, "password": self.machine_password},
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
                timeout=10
            )
            resp.raise_for_status()
            self.jwt_token = resp.json().get("token")
            return bool(self.jwt_token)
        except Exception as e:
            self.logger.error(f"Machine auth failed: {e}")
            return False

    def get_local_decisions(self) -> list[Alert]:
        alerts = self._fetch_from_alerts_endpoint()
        if alerts:
            return alerts
        return self._fetch_from_stream_endpoint()

    def _fetch_from_alerts_endpoint(self) -> list[Alert]:
        if not self.machine_id:
            return []
        if not self.jwt_token and not self._authenticate():
            return []
        try:
            resp = requests.get(
                f"{self.url}/v1/alerts",
                params={"limit": 200, "since": "24h"},
                headers={"Authorization": f"Bearer {self.jwt_token}", "User-Agent": USER_AGENT},
                timeout=30
            )
            if resp.status_code == 401:
                if self._authenticate():
                    resp = requests.get(
                        f"{self.url}/v1/alerts",
                        params={"limit": 200, "since": "24h"},
                        headers={"Authorization": f"Bearer {self.jwt_token}", "User-Agent": USER_AGENT},
                        timeout=30
                    )
            resp.raise_for_status()
            return self._parse_alerts(resp.json())
        except Exception as e:
            self.logger.warning(f"Alerts endpoint failed: {e}")
            return []

    def _parse_alerts(self, data: list[dict]) -> list[Alert]:
        alerts = []
        for alert in data:
            scenario = alert.get("scenario", "")
            if not scenario or self._is_system_scenario(scenario):
                continue
            for decision in alert.get("decisions") or []:
                if decision.get("scope", "").lower() == "ip":
                    ip = decision.get("value")
                    if ip:
                        alerts.append(Alert(
                            ip=ip,
                            scenario=self._normalize_scenario(scenario),
                            alert_id=str(alert.get("id", "")),
                            timestamp=alert.get("created_at", "")
                        ))
        self.logger.info(f"Alerts endpoint: {len(alerts)} local IPs")
        return alerts

    def _fetch_from_stream_endpoint(self) -> list[Alert]:
        if not self.api_key:
            self.logger.warning("No bouncer API key for stream endpoint")
            return []
        try:
            resp = requests.get(
                f"{self.url}/v1/decisions/stream",
                params={"startup": "true"},
                headers={"X-Api-Key": self.api_key, "User-Agent": USER_AGENT},
                timeout=30
            )
            resp.raise_for_status()
            return self._parse_stream(resp.json())
        except Exception as e:
            self.logger.error(f"Stream endpoint failed: {e}")
            return []

    def _parse_stream(self, data: dict) -> list[Alert]:
        alerts = []
        skipped = 0
        for decision in data.get("new") or []:
            origin = decision.get("origin", "").lower()
            scenario = decision.get("scenario", "")
            # Only process local detections (origin: crowdsec), skip CAPI/lists
            if origin != "crowdsec" or self._is_system_scenario(scenario):
                skipped += 1
                continue
            if decision.get("scope", "").lower() == "ip":
                ip = decision.get("value")
                if ip:
                    alerts.append(Alert(ip=ip, scenario=self._normalize_scenario(scenario)))
        self.logger.info(f"Stream endpoint: {len(alerts)} local, {skipped} community/lists skipped")
        return alerts

    @staticmethod
    def _is_system_scenario(scenario: str) -> bool:
        lower = scenario.lower()
        skip = ["update", "capi", "lists", "firehol", "botscout", "whitelist", "sync"]
        return any(s in lower for s in skip)

    @staticmethod
    def _normalize_scenario(scenario: str) -> str:
        s = scenario.replace("crowdsecurity/", "").replace(":", "-").lower()
        mappings = {
            "ssh-bruteforce": "ssh-bf",
            "ssh-slowbruteforce": "ssh-slow-bf",
            "http-bruteforce": "http-bf",
            "mysql-bruteforce": "mysql-bf",
            "ftp-bruteforce": "ftp-bf",
            "rdp-bruteforce": "rdp-bf",
            "smb-bruteforce": "smb-bf",
            "telnet-bruteforce": "telnet-bf",
        }
        return mappings.get(s, s)


class AbuseIPDBClient:
    API_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, logger: logging.Logger):
        self.session = requests.Session()
        self.session.headers.update({"Key": api_key, "Accept": "application/json", "User-Agent": USER_AGENT})
        self.logger = logger

    def report(self, ip: str, categories: list[int], comment: str) -> bool:
        try:
            resp = self.session.post(
                f"{self.API_URL}/report",
                data={"ip": ip, "categories": ",".join(map(str, categories)), "comment": comment[:1024]},
                timeout=15
            )
            if resp.status_code == 429:
                self.logger.warning(f"Rate limited, skipping {ip}")
                return False
            resp.raise_for_status()
            if resp.json().get("data", {}).get("ipAddress"):
                return True
            self.logger.warning(f"Unexpected response for {ip}: {resp.text[:200]}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to report {ip}: {e}")
            return False


class Reporter:
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.db = Database(BASE_DIR / config.database_file, config.retention_days)
        self.crowdsec = CrowdSecClient(config, logger)
        self.abuseipdb = AbuseIPDBClient(config.abuseipdb_api_key, logger)

    def run_once(self):
        self.logger.info("Starting reporting cycle")
        self._retry_failed()
        alerts = self.crowdsec.get_local_decisions()
        if not alerts:
            self.logger.info("No new local alerts")
            return
        reported = self._process_alerts(alerts)
        self.db.cleanup()
        stats = self.db.stats()
        self.logger.info(f"Reported {reported} IPs. DB: {stats['total']} total, {stats['last_24h']} last 24h, {stats['failed']} failed")

    def _retry_failed(self):
        failed = self.db.get_failed_for_retry()
        if not failed:
            return
        self.logger.info(f"Retrying {len(failed)} failed reports")
        for f in failed:
            if self.abuseipdb.report(f.ip, f.categories, f.comment):
                self.db.mark_reported(f.ip, f.scenario)
                self.logger.info(f"Retry success: {f.ip}")
            else:
                self.db.add_failed(f.ip, f.scenario, f.categories, f.comment)
            time.sleep(self.config.throttle_seconds)

    def _process_alerts(self, alerts: list[Alert]) -> int:
        reported = 0
        total = len(alerts)
        for i, alert in enumerate(alerts, 1):
            if self.db.is_reported(alert.ip, alert.scenario):
                continue
            if self._is_private(alert.ip):
                continue
            categories = self._get_categories(alert.scenario)
            comment = f"CrowdSec: {alert.scenario}"
            if total > 10:
                self.logger.info(f"[{i}/{total}] Reporting {alert.ip} ({alert.scenario})")
            if self.abuseipdb.report(alert.ip, categories, comment):
                self.db.mark_reported(alert.ip, alert.scenario)
                reported += 1
            else:
                self.db.add_failed(alert.ip, alert.scenario, categories, comment)
            if i < total:
                time.sleep(self.config.throttle_seconds)
        return reported

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return True

    @staticmethod
    def _get_categories(scenario: str) -> list[int]:
        base = scenario.split("-")[0]
        return SCENARIO_CATEGORIES.get(scenario, SCENARIO_CATEGORIES.get(f"{base}-bf", SCENARIO_CATEGORIES["default"]))

    def run_daemon(self):
        self.logger.info(f"Daemon mode: polling every {self.config.poll_interval}s")
        while True:
            try:
                self.run_once()
            except Exception as e:
                self.logger.error(f"Cycle error: {e}")
            self.logger.info(f"Sleeping {self.config.poll_interval}s")
            time.sleep(self.config.poll_interval)


def setup_logging(config: Config) -> logging.Logger:
    logger = logging.getLogger("crowdsec_reporter")
    logger.setLevel(getattr(logging, config.log_level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh = logging.FileHandler(BASE_DIR / config.log_file)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def main():
    config = Config.load(BASE_DIR / "config.yml")
    for key, env in [("crowdsec_url", "CROWDSEC_URL"), ("crowdsec_api_key", "CROWDSEC_API_KEY"),
                     ("abuseipdb_api_key", "ABUSEIPDB_API_KEY")]:
        if os.getenv(env):
            setattr(config, key, os.getenv(env))

    logger = setup_logging(config)
    logger.info(f"CrowdSec Reporter v{VERSION}")

    if not config.abuseipdb_api_key or config.abuseipdb_api_key == "YOUR_ABUSEIPDB_API_KEY_HERE":
        logger.error("AbuseIPDB API key not configured")
        return

    stats = Database(BASE_DIR / config.database_file, config.retention_days).stats()
    logger.info(f"Database: {stats['total']} reported, {stats['failed']} failed")

    reporter = Reporter(config, logger)
    try:
        if config.daemon_mode:
            reporter.run_daemon()
        else:
            reporter.run_once()
    except KeyboardInterrupt:
        logger.info("Shutting down")


if __name__ == "__main__":
    main()

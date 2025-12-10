#!/usr/bin/env python3
"""
CrowdSec to AbuseIPDB IP Reporter
Polls CrowdSec alerts and reports malicious IPs to AbuseIPDB
Configuration is loaded from config.yml
"""

import requests
import json
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
import os
import yaml
import hashlib
import sqlite3
from dataclasses import dataclass

def load_config():
    """Load configuration from config.yml file"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.yml')
    
    # Default configuration
    default_config = {
        'crowdsec': {
            'url': 'http://localhost:8080',
            'api_key': 'YOUR_CROWDSEC_API_KEY_HERE'
        },
        'abuseipdb': {
            'api_key': 'YOUR_ABUSEIPDB_API_KEY_HERE'
        },
        'settings': {
            'poll_interval': 300,
            'hours_back': 24,
            'daemon_mode': True,
            'abuseipdb_throttle': 10
        },
        'logging': {
            'level': 'INFO',
            'file': 'crowdsec_reporter.log'
        },
        'persistence': {
            'database_file': 'crowdsec_reports.db',
            'history_retention_days': 30
        }
    }
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                # Merge with defaults to ensure all keys exist
                for section in default_config:
                    if section not in config:
                        config[section] = default_config[section]
                    else:
                        for key in default_config[section]:
                            if key not in config[section]:
                                config[section][key] = default_config[section][key]
                return config
        else:
            # Create default config file if it doesn't exist
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
            print(f"Created default config file at {config_path}")
            print("Please edit the API keys in config.yml and run again.")
            return default_config
    except Exception as e:
        print(f"Error loading config: {e}")
        return default_config

# Load configuration
config = load_config()

# Configure logging
log_level = getattr(logging, config['logging']['level'].upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config['logging']['file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Represents a CrowdSec alert"""
    id: str
    ip: str
    scenario: str
    timestamp: str
    source_country: str
    source_range: str

@dataclass 
class FailedReport:
    """Represents a failed report to retry later"""
    ip: str
    categories: List[int]
    comment: str
    first_attempt: datetime
    last_attempt: datetime
    retry_count: int
    scenario: str

class ReportHistory:
    """Manages history of reported IPs and failed reports using SQLite"""
    
    def __init__(self, database_file: str, retention_days: int = 30):
        self.database_file = database_file
        self.retention_days = retention_days
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            # Table for successfully reported IPs (using TEXT for timestamps)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reported_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_hash TEXT UNIQUE NOT NULL,
                    ip_address TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    reported_at TEXT NOT NULL,
                    comment TEXT
                )
            ''')
            
            # Table for failed reports to retry (using TEXT for timestamps)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS failed_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_hash TEXT UNIQUE NOT NULL,
                    ip_address TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    first_attempt TEXT NOT NULL,
                    last_attempt TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 1
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_reported_ips_hash ON reported_ips(ip_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_reported_ips_date ON reported_ips(reported_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_failed_reports_hash ON failed_reports(ip_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_failed_reports_attempt ON failed_reports(last_attempt)')
            
            conn.commit()
            conn.close()
            
            # Log statistics
            self.log_statistics()
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def log_statistics(self):
        """Log current database statistics"""
        try:
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM reported_ips')
            reported_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM failed_reports')
            failed_count = cursor.fetchone()[0]
            
            conn.close()
            
            logger.info(f"Loaded database: {reported_count} reported IPs, {failed_count} failed reports")
            
        except Exception as e:
            logger.warning(f"Could not get database statistics: {e}")
    
    def _get_ip_hash(self, ip: str, scenario: str) -> str:
        """Create a hash for IP+scenario combination for deduplication"""
        return hashlib.md5(f"{ip}:{scenario}".encode()).hexdigest()
    
    def is_already_reported(self, ip: str, scenario: str) -> bool:
        """Check if IP+scenario combination was already reported"""
        try:
            ip_hash = self._get_ip_hash(ip, scenario)
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT 1 FROM reported_ips WHERE ip_hash = ? LIMIT 1',
                (ip_hash,)
            )
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
            
        except Exception as e:
            logger.error(f"Error checking if IP was reported: {e}")
            return False  # If in doubt, allow reporting
    
    def mark_as_reported(self, ip: str, scenario: str, comment: str = ""):
        """Mark IP+scenario as successfully reported"""
        try:
            ip_hash = self._get_ip_hash(ip, scenario)
            now = datetime.now(timezone.utc).isoformat()
            
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            # Insert into reported_ips
            cursor.execute('''
                INSERT OR REPLACE INTO reported_ips 
                (ip_hash, ip_address, scenario, reported_at, comment)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_hash, ip, scenario, now, comment))
            
            # Remove from failed_reports if it exists
            cursor.execute('DELETE FROM failed_reports WHERE ip_hash = ?', (ip_hash,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error marking IP as reported: {e}")
    
    def add_failed_report(self, ip: str, scenario: str, categories: List[int], comment: str):
        """Add a failed report for retry later"""
        try:
            ip_hash = self._get_ip_hash(ip, scenario)
            now = datetime.now(timezone.utc).isoformat()
            categories_str = ','.join(map(str, categories))
            
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            # Check if this failed report already exists
            cursor.execute(
                'SELECT retry_count FROM failed_reports WHERE ip_hash = ?',
                (ip_hash,)
            )
            result = cursor.fetchone()
            
            if result:
                # Update existing failed report
                retry_count = result[0] + 1
                cursor.execute('''
                    UPDATE failed_reports 
                    SET last_attempt = ?, retry_count = ?
                    WHERE ip_hash = ?
                ''', (now, retry_count, ip_hash))
            else:
                # Insert new failed report
                cursor.execute('''
                    INSERT INTO failed_reports 
                    (ip_hash, ip_address, scenario, categories, comment, first_attempt, last_attempt, retry_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ''', (ip_hash, ip, scenario, categories_str, comment, now, now))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error adding failed report: {e}")
    
    def get_failed_reports_to_retry(self, min_retry_interval_hours: int = 24) -> List[FailedReport]:
        """Get failed reports that are ready for retry"""
        try:
            now = datetime.now(timezone.utc)
            retry_cutoff = now - timedelta(hours=min_retry_interval_hours)
            retry_cutoff_str = retry_cutoff.isoformat()
            
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ip_address, scenario, categories, comment, 
                       first_attempt, last_attempt, retry_count
                FROM failed_reports 
                WHERE last_attempt < ? AND retry_count < 5
                ORDER BY first_attempt ASC
            ''', (retry_cutoff_str,))
            
            results = cursor.fetchall()
            conn.close()
            
            failed_reports = []
            for row in results:
                categories = [int(x) for x in row[2].split(',')]
                failed_reports.append(FailedReport(
                    ip=row[0],
                    scenario=row[1],
                    categories=categories,
                    comment=row[3],
                    first_attempt=datetime.fromisoformat(row[4]),
                    last_attempt=datetime.fromisoformat(row[5]),
                    retry_count=row[6]
                ))
            
            return failed_reports
            
        except Exception as e:
            logger.error(f"Error getting failed reports to retry: {e}")
            return []
    
    def cleanup_old_entries(self):
        """Clean up old entries from database"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
            cutoff_str = cutoff_date.isoformat()
            
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            # Clean old reported IPs
            cursor.execute('DELETE FROM reported_ips WHERE reported_at < ?', (cutoff_str,))
            reported_deleted = cursor.rowcount
            
            # Clean old failed reports
            cursor.execute('DELETE FROM failed_reports WHERE first_attempt < ?', (cutoff_str,))
            failed_deleted = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            if reported_deleted > 0 or failed_deleted > 0:
                logger.info(f"Cleaned up {reported_deleted} old reported IPs and {failed_deleted} old failed reports")
                
        except Exception as e:
            logger.error(f"Error cleaning up old entries: {e}")
    
    def get_statistics(self) -> Dict[str, int]:
        """Get database statistics"""
        try:
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            
            # Count reported IPs
            cursor.execute('SELECT COUNT(*) FROM reported_ips')
            reported_count = cursor.fetchone()[0]
            
            # Count failed reports
            cursor.execute('SELECT COUNT(*) FROM failed_reports')
            failed_count = cursor.fetchone()[0]
            
            # Count reports in last 24 hours
            yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
            yesterday_str = yesterday.isoformat()
            cursor.execute('SELECT COUNT(*) FROM reported_ips WHERE reported_at > ?', (yesterday_str,))
            recent_count = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_reported': reported_count,
                'failed_reports': failed_count,
                'reported_last_24h': recent_count
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {'total_reported': 0, 'failed_reports': 0, 'reported_last_24h': 0}

class CrowdSecClient:
    """Client for CrowdSec API with both bouncer and machine authentication"""
    
    def __init__(self, api_url: str, api_key: str = None, machine_creds_file: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.machine_creds_file = machine_creds_file
        self.session = requests.Session()
        self.jwt_token = None
        
        # Try to load machine credentials if provided
        self.machine_login = None
        self.machine_password = None
        if machine_creds_file and os.path.exists(machine_creds_file):
            try:
                with open(machine_creds_file, 'r') as f:
                    creds = yaml.safe_load(f)
                    self.machine_login = creds.get('login')
                    self.machine_password = creds.get('password')
                    logger.info("Loaded machine credentials - will use alerts endpoint")
            except Exception as e:
                logger.warning(f"Could not load machine credentials: {e}")
        
        # Set up session headers for bouncer auth (fallback)
        if api_key:
            self.session.headers.update({
                'X-Api-Key': str(api_key).strip(),
                'Content-Type': 'application/json',
                'User-Agent': 'CrowdSec-AbuseIPDB-Reporter/1.0'
            })
    
    def _get_jwt_token(self) -> bool:
        """Get JWT token for machine authentication"""
        if not self.machine_login or not self.machine_password:
            return False
        
        try:
            auth_data = {
                "machine_id": self.machine_login,
                "password": self.machine_password
            }
            
            response = requests.post(
                f"{self.api_url}/v1/watchers/login",
                json=auth_data,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            
            result = response.json()
            self.jwt_token = result.get('token')
            
            if self.jwt_token:
                logger.info("Successfully authenticated with machine credentials")
                return True
            else:
                logger.error("No token received from machine authentication")
                return False
                
        except Exception as e:
            logger.error(f"Failed to get JWT token: {e}")
            return False
    
    def _make_authenticated_request(self, endpoint: str, params: dict = None) -> requests.Response:
        """Make request with appropriate authentication method"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'CrowdSec-AbuseIPDB-Reporter/1.0'
        }
        
        # Try machine auth first (for alerts endpoint)
        if self.machine_login and self.machine_password:
            if not self.jwt_token and not self._get_jwt_token():
                raise Exception("Failed to authenticate with machine credentials")
            
            headers['Authorization'] = f'Bearer {self.jwt_token}'
            
            try:
                response = requests.get(f"{self.api_url}{endpoint}", headers=headers, params=params)
                if response.status_code == 401:
                    # Token might be expired, try to refresh
                    logger.info("JWT token expired, refreshing...")
                    if self._get_jwt_token():
                        headers['Authorization'] = f'Bearer {self.jwt_token}'
                        response = requests.get(f"{self.api_url}{endpoint}", headers=headers, params=params)
                return response
            except Exception as e:
                logger.warning(f"Machine auth failed: {e}, falling back to bouncer auth")
        
        # Fallback to bouncer auth
        if self.api_key:
            headers['X-Api-Key'] = self.api_key
            return requests.get(f"{self.api_url}{endpoint}", headers=headers, params=params)
        
        raise Exception("No valid authentication method available")
    
    def get_alerts(self, since: datetime = None, limit: int = 100) -> List[Alert]:
        """Fetch recent alerts/decisions from CrowdSec using the best available method"""
        try:
            cutoff_time = since if since else datetime.now(timezone.utc) - timedelta(hours=24)
            logger.info(f"Fetching recent activity since: {cutoff_time.isoformat()}")
            
            # Method 1: Try alerts endpoint with machine auth (best for recent detections)
            if self.machine_login and self.machine_password:
                alerts = self._get_alerts_from_alerts_endpoint(cutoff_time, limit)
                if alerts:
                    return alerts
                logger.warning("Alerts endpoint failed, trying stream endpoint")
            
            # Method 2: Try stream endpoint with bouncer auth
            alerts = self._get_alerts_from_stream_endpoint(cutoff_time)
            if alerts:
                return alerts
            
            # Method 3: Fallback to decisions endpoint with strict filtering
            logger.info("Stream endpoint returned no data, using fallback method")
            return self._get_alerts_fallback(cutoff_time, limit)
            
        except Exception as e:
            logger.error(f"Error fetching CrowdSec data: {e}")
            return []
    
    def _get_alerts_from_alerts_endpoint(self, cutoff_time: datetime, limit: int) -> List[Alert]:
        """Get recent alerts using machine authentication (preferred method)"""
        try:
            # Calculate hours back from cutoff_time
            now = datetime.now(timezone.utc)
            hours_back = int((now - cutoff_time).total_seconds() / 3600)
            
            # Use alerts endpoint with proper time filtering based on config
            params = {
                'limit': limit,
                'since': f'{hours_back}h'  # Use the actual hours_back setting
            }
            
            response = self._make_authenticated_request('/v1/alerts', params)
            response.raise_for_status()
            
            alerts_data = response.json()
            logger.info(f"Received {len(alerts_data)} alerts from alerts endpoint (last {hours_back} hours)")
            
            alerts = []
            decisions_processed = 0
            decisions_skipped = 0
            
            for alert_data in alerts_data:
                # Check alert timestamp first
                created_at = alert_data.get('created_at', '')
                if not created_at:
                    continue
                
                try:
                    alert_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    # Use the actual cutoff time from config
                    if alert_time < cutoff_time:
                        continue
                except Exception:
                    continue
                
                # Get alert metadata
                scenario = alert_data.get('scenario', 'unknown')
                source = alert_data.get('source', {})
                
                # Log the raw scenario for debugging
                logger.info(f"Processing alert with scenario: '{scenario}'")
                
                # Skip non-attack scenarios (system/maintenance activities)
                if scenario:
                    scenario_lower = scenario.lower()
                    skip_terms = [
                        'update', 'firehol', 'botscout', 'whitelist', 'reputation', 
                        'capi', 'central', 'sync', 'maintenance', 'system', 'lists'
                    ]
                    
                    if any(skip_term in scenario_lower for skip_term in skip_terms):
                        logger.info(f"Skipping system scenario: {scenario}")
                        continue
                
                # Only process actual attack scenarios
                attack_scenarios = [
                    'ssh-bf', 'ssh:bruteforce', 'ssh-slow-bf', 'ssh:slowbruteforce',
                    'http-bf', 'http:bruteforce', 'http-crawl', 'http-probing',
                    'mysql-bf', 'mysql:bruteforce', 'mariadb-user-enum',
                    'ftp-bf', 'ftp:bruteforce', 'rdp-bf', 'rdp:bruteforce',
                    'smb-bf', 'smb:bruteforce', 'database:bruteforce',
                    'telnet-bf', 'telnet:bruteforce'
                ]
                
                scenario_lower = scenario.lower() if scenario else ''
                is_attack_scenario = any(attack in scenario_lower for attack in attack_scenarios)
                
                if not is_attack_scenario:
                    logger.info(f"Skipping non-attack scenario: {scenario}")
                    continue
                
                # Extract decisions from recent attack alert
                decisions = alert_data.get('decisions', [])
                if not decisions:
                    continue
                
                # Process each decision in the alert, but limit to recent ones
                for decision in decisions[:50]:  # Limit to first 50 decisions per alert to avoid massive batches
                    scope = decision.get('scope', '')
                    value = decision.get('value', '')
                    
                    if scope.lower() == 'ip' and value:
                        decisions_processed += 1
                        
                        # Clean up scenario name
                        clean_scenario = scenario.replace('crowdsecurity/', '') if scenario else 'unknown'
                        
                        # Normalize scenario formats
                        scenario_mappings = {
                            'ssh:bruteforce': 'ssh-bf',
                            'http:bruteforce': 'http-bf',
                            'mysql:bruteforce': 'mysql-bf',
                            'ftp:bruteforce': 'ftp-bf',
                            'rdp:bruteforce': 'rdp-bf',
                            'smb:bruteforce': 'smb-bf',
                            'ssh:slowbruteforce': 'ssh-slow-bf',
                            'mariadb:user-enum': 'mariadb-user-enum',
                            'database:bruteforce': 'database-bf',
                            'telnet:bruteforce': 'telnet-bf'
                        }
                        clean_scenario = scenario_mappings.get(clean_scenario, clean_scenario)
                        
                        # Log the scenario for debugging
                        logger.info(f"Processing IP {value} with final scenario: '{clean_scenario}'")
                        
                        # Validate that we have a proper attack scenario
                        if clean_scenario in ['unknown', 'update', 'firehol_botscout_7d', 'lists']:
                            logger.warning(f"Skipping IP {value} with invalid scenario: {clean_scenario}")
                            decisions_skipped += 1
                            continue
                        
                        alert = Alert(
                            id=str(alert_data.get('id', '')),
                            ip=value,
                            scenario=clean_scenario,
                            timestamp=created_at,
                            source_country=source.get('cn', ''),
                            source_range=source.get('range', '')
                        )
                        alerts.append(alert)
                    else:
                        decisions_skipped += 1
            
            logger.info(f"Processed {decisions_processed} IP decisions from recent alerts, skipped {decisions_skipped} non-IP decisions")
            logger.info(f"Final result: {len(alerts)} recent IP threats to report")
            return alerts
            
        except Exception as e:
            logger.error(f"Error using alerts endpoint: {e}")
            return []
    
    def _get_alerts_from_stream_endpoint(self, cutoff_time: datetime) -> List[Alert]:
        """Get recent decisions using stream endpoint with bouncer auth"""
        try:
            if not self.api_key:
                logger.warning("No bouncer API key configured for stream endpoint")
                return []
            
            headers = {
                'X-Api-Key': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'CrowdSec-AbuseIPDB-Reporter/1.0'
            }
            response = requests.get(f"{self.api_url}/v1/decisions/stream?startup=true", headers=headers)
            response.raise_for_status()
            
            stream_data = response.json()
            new_decisions = stream_data.get('new', [])
            
            logger.info(f"Stream endpoint: {len(new_decisions)} new decisions available")
            
            if not new_decisions:
                return []
            
            alerts = []
            for decision_data in new_decisions:
                scope = decision_data.get('scope', '')
                value = decision_data.get('value', '')
                
                if scope.lower() == 'ip' and value:
                    # Extract scenario from reason field
                    reason = decision_data.get('reason', '')
                    scenario = 'unknown'
                    
                    if reason and "performed '" in reason:
                        start = reason.find("performed '") + len("performed '")
                        end = reason.find("'", start)
                        if end > start:
                            scenario = reason[start:end].replace('crowdsecurity/', '')
                    
                    alert = Alert(
                        id=str(decision_data.get('id', '')),
                        ip=value,
                        scenario=scenario,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        source_country='',
                        source_range=''
                    )
                    alerts.append(alert)
            
            logger.info(f"Processed {len(alerts)} decisions from stream endpoint")
            return alerts
            
        except Exception as e:
            logger.error(f"Error using stream endpoint: {e}")
            return []
    
    def _get_alerts_fallback(self, since: datetime = None, limit: int = 100) -> List[Alert]:
        """Fallback method using regular decisions endpoint with strict filtering"""
        try:
            cutoff_time = since if since else datetime.now(timezone.utc) - timedelta(hours=2)  # Much shorter window for fallback
            
            headers = {
                'X-Api-Key': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'CrowdSec-AbuseIPDB-Reporter/1.0'
            }
            
            response = requests.get(f"{self.api_url}/v1/decisions", headers=headers)
            response.raise_for_status()
            
            decisions_data = response.json()
            logger.info(f"Fallback: Received {len(decisions_data)} total decisions, filtering strictly")
            
            alerts = []
            filtered_count = 0
            
            for decision_data in decisions_data:
                scope = decision_data.get('scope', '')
                value = decision_data.get('value', '')
                
                if scope.lower() == 'ip' and value:
                    # Very strict time filtering for fallback
                    created_at = decision_data.get('created_at', '')
                    if not created_at:
                        filtered_count += 1
                        continue
                    
                    try:
                        if created_at.endswith('Z'):
                            decision_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        elif '+' in created_at or '-' in created_at[-6:]:
                            decision_time = datetime.fromisoformat(created_at)
                        else:
                            decision_time = datetime.fromisoformat(created_at).replace(tzinfo=timezone.utc)
                        
                        if decision_time < cutoff_time:
                            filtered_count += 1
                            continue
                            
                    except Exception:
                        filtered_count += 1
                        continue
                    
                    scenario = decision_data.get('scenario', 'unknown')
                    if scenario != 'unknown':
                        scenario = scenario.replace('crowdsecurity/', '')
                    
                    alert = Alert(
                        id=str(decision_data.get('id', '')),
                        ip=value,
                        scenario=scenario,
                        timestamp=created_at,
                        source_country='',
                        source_range=''
                    )
                    alerts.append(alert)
            
            logger.info(f"Fallback: Filtered out {filtered_count} old decisions, kept {len(alerts)} recent decisions")
            return alerts
            
        except Exception as e:
            logger.error(f"Fallback method also failed: {e}")
            return []

class AbuseIPDBClient:
    """Client for AbuseIPDB API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.abuseipdb.com/api/v2'
        self.session = requests.Session()
        self.session.headers.update({
            'Key': api_key,
            'Accept': 'application/json'
        })
    
    def report_ip(self, ip: str, categories: List[int], comment: str) -> bool:
        """Report an IP to AbuseIPDB"""
        try:
            data = {
                'ip': ip,
                'categories': ','.join(map(str, categories)),
                'comment': comment[:1024]  # AbuseIPDB has a comment limit
            }
            
            response = self.session.post(f"{self.base_url}/report", data=data)
            response.raise_for_status()
            
            result = response.json()
            if result.get('data', {}).get('ipAddress'):
                logger.info(f"Successfully reported {ip} to AbuseIPDB")
                return True
            else:
                logger.warning(f"Unexpected response when reporting {ip}: {result}")
                return False
                
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.warning(f"Rate limit reached for AbuseIPDB. Skipping {ip}")
            else:
                logger.error(f"HTTP error reporting {ip} to AbuseIPDB: {e}")
            return False
        except Exception as e:
            logger.error(f"Error reporting {ip} to AbuseIPDB: {e}")
            return False
    
    def check_ip(self, ip: str) -> Dict:
        """Check if IP is already reported (optional, for deduplication)"""
        try:
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            response = self.session.get(f"{self.base_url}/check", params=params)
            response.raise_for_status()
            return response.json().get('data', {})
        except Exception as e:
            logger.error(f"Error checking IP {ip}: {e}")
            return {}

class IPReporter:
    """Main class that coordinates between CrowdSec and AbuseIPDB"""
    
    def __init__(self, crowdsec_url: str, crowdsec_key: str, abuseipdb_key: str, throttle_seconds: int = 10):
        # Initialize CrowdSec client with both auth methods
        machine_creds_file = os.path.join(os.path.dirname(__file__), 'local_api_credentials.yaml')
        self.crowdsec = CrowdSecClient(crowdsec_url, crowdsec_key, machine_creds_file)
        self.abuseipdb = AbuseIPDBClient(abuseipdb_key)
        self.throttle_seconds = throttle_seconds  # Throttling between reports
        
        # Initialize report history manager
        self.history = ReportHistory(
            config['persistence']['database_file'],
            config['persistence']['history_retention_days']
        )
        
        # Map CrowdSec scenarios to AbuseIPDB categories
        self.scenario_categories = {
            'ssh-bf': [18, 22],  # Brute force, SSH
            'ssh:bruteforce': [18, 22],  # Brute force, SSH
            'ssh-slow-bf': [18, 22],
            'ssh:slowbruteforce': [18, 22],
            'http-bf': [18, 21],  # Brute force, Web attack
            'http:bruteforce': [18, 21],
            'mariadb-user-enum': [18],  # Brute force
            'mariadb:user-enum': [18],
            'mysql-bf': [18],
            'mysql:bruteforce': [18],
            'ftp-bf': [18, 5],  # Brute force, FTP
            'ftp:bruteforce': [18, 5],
            'rdp-bf': [18],
            'rdp:bruteforce': [18],
            'smb-bf': [18],
            'smb:bruteforce': [18],
            'database-bf': [18],  # Brute force
            'database:bruteforce': [18],
            'default': [14, 18]  # Malware, Brute force (fallback)
        }
    
    def get_categories_for_scenario(self, scenario: str) -> List[int]:
        """Map CrowdSec scenario to AbuseIPDB categories"""
        # Remove common prefixes/suffixes to find base scenario
        base_scenario = scenario.lower().replace('crowdsecurity/', '').split('-')[0:2]
        base_scenario = '-'.join(base_scenario)
        
        return self.scenario_categories.get(base_scenario, self.scenario_categories.get(scenario, self.scenario_categories['default']))
    
    def format_comment(self, alert: Alert) -> str:
        """Format comment for AbuseIPDB report"""
        return f"Security Alert: {alert.scenario}"
    
    def process_alerts(self, alerts: List[Alert]) -> int:
        """Process and report alerts to AbuseIPDB with throttling"""
        reported_count = 0
        total_alerts = len(alerts)
        
        # First, try to retry any failed reports from previous runs
        failed_reports = self.history.get_failed_reports_to_retry(24)  # Retry after 24 hours
        if failed_reports:
            logger.info(f"Retrying {len(failed_reports)} previously failed reports...")
            for failed_report in failed_reports:
                if self.abuseipdb.report_ip(failed_report.ip, failed_report.categories, failed_report.comment):
                    self.history.mark_as_reported(failed_report.ip, failed_report.scenario, failed_report.comment)
                    reported_count += 1
                    logger.info(f"Successfully retried report for {failed_report.ip}")
                else:
                    # Update failed report with new attempt
                    self.history.add_failed_report(
                        failed_report.ip, failed_report.scenario, 
                        failed_report.categories, failed_report.comment
                    )
                    logger.warning(f"Retry failed for {failed_report.ip}, will try again later")
                
                # Throttle between retries too
                if len(failed_reports) > 1:
                    time.sleep(self.throttle_seconds)
        
        # Now process new alerts
        logger.info(f"Processing {total_alerts} new alerts with {self.throttle_seconds}s throttling...")
        
        for i, alert in enumerate(alerts, 1):
            # Skip if already reported (using persistent history)
            if self.history.is_already_reported(alert.ip, alert.scenario):
                logger.debug(f"Skipping {alert.ip} ({alert.scenario}) - already reported")
                continue
            
            # Skip private/local IPs
            if self.is_private_ip(alert.ip):
                logger.debug(f"Skipping private IP: {alert.ip}")
                continue
            
            categories = self.get_categories_for_scenario(alert.scenario)
            comment = self.format_comment(alert)
            
            # Show progress for large batches
            if total_alerts > 10:
                logger.info(f"Reporting IP {i}/{total_alerts}: {alert.ip} ({alert.scenario})")
            
            if self.abuseipdb.report_ip(alert.ip, categories, comment):
                self.history.mark_as_reported(alert.ip, alert.scenario, comment)
                reported_count += 1
                logger.info(f"Successfully reported and logged {alert.ip} ({alert.scenario}) to database")
                
                # Throttle after successful report (except for the last one)
                if i < total_alerts:
                    logger.info(f"Waiting {self.throttle_seconds} seconds before next report...")
                    time.sleep(self.throttle_seconds)
            else:
                # Add to failed reports for retry later
                self.history.add_failed_report(alert.ip, alert.scenario, categories, comment)
                logger.warning(f"Failed to report {alert.ip}, saved to failed reports for retry later")
                
                # Still throttle on failures to avoid hammering the API
                if i < total_alerts:
                    time.sleep(self.throttle_seconds)
        
        # Clean up old entries periodically and show stats
        self.history.cleanup_old_entries()
        stats = self.history.get_statistics()
        logger.info(f"Database stats: {stats['total_reported']} total reported, {stats['failed_reports']} failed, {stats['reported_last_24h']} in last 24h")
        
        return reported_count
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private/local"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except:
            return True  # If invalid, skip it
    
    def run_once(self, hours_back: int = 24) -> None:
        """Run one iteration of polling and reporting"""
        logger.info("Starting CrowdSec to AbuseIPDB reporting cycle")
        
        # Fetch alerts from the last N hours using timezone-aware datetime
        since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        alerts = self.crowdsec.get_alerts(since=since)
        
        if not alerts:
            logger.info("No new alerts to process")
            return
        
        # Process and report
        reported_count = self.process_alerts(alerts)
        logger.info(f"Reported {reported_count} IPs to AbuseIPDB")
    
    def run_daemon(self, poll_interval: int = 300, hours_back: int = 24) -> None:
        """Run as a daemon, polling every poll_interval seconds"""
        logger.info(f"Starting daemon mode - polling every {poll_interval} seconds")
        
        while True:
            try:
                self.run_once(hours_back)
            except Exception as e:
                logger.error(f"Error in polling cycle: {e}")
            
            logger.info(f"Sleeping for {poll_interval} seconds...")
            time.sleep(poll_interval)

def main():
    """Main function"""
    # Check if API keys are configured
    if config['crowdsec']['api_key'] == "YOUR_CROWDSEC_API_KEY_HERE":
        logger.error("Please set your CrowdSec API key in config.yml")
        return
    
    if config['abuseipdb']['api_key'] == "YOUR_ABUSEIPDB_API_KEY_HERE":
        logger.error("Please set your AbuseIPDB API key in config.yml")
        return
    
    # Get configuration values (with environment variable override)
    crowdsec_url = os.getenv('CROWDSEC_URL', config['crowdsec']['url'])
    crowdsec_key = os.getenv('CROWDSEC_API_KEY', config['crowdsec']['api_key'])
    abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', config['abuseipdb']['api_key'])
    
    poll_interval = int(os.getenv('POLL_INTERVAL', str(config['settings']['poll_interval'])))
    hours_back = int(os.getenv('HOURS_BACK', str(config['settings']['hours_back'])))
    daemon_mode = os.getenv('DAEMON_MODE', str(config['settings']['daemon_mode'])).lower() in ('true', '1', 'yes')
    throttle_seconds = int(os.getenv('ABUSEIPDB_THROTTLE', str(config['settings']['abuseipdb_throttle'])))
    
    logger.info(f"Starting with config: Poll every {poll_interval}s, look back {hours_back}h, throttle {throttle_seconds}s")
    
    reporter = IPReporter(crowdsec_url, crowdsec_key, abuseipdb_key, throttle_seconds)
    
    try:
        if daemon_mode:
            reporter.run_daemon(poll_interval, hours_back)
        else:
            reporter.run_once(hours_back)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == '__main__':
    main()

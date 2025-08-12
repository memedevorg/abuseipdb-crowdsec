# CrowdSec to AbuseIPDB Reporter

Automatically report malicious IPs detected by CrowdSec to AbuseIPDB for community threat intelligence sharing.

## Features

- ✅ **Dual Authentication** - Supports both machine credentials (alerts endpoint) and bouncer API keys (decisions endpoint)
- ✅ **Smart Deduplication** - SQLite database prevents duplicate reports
- ✅ **Failed Report Retry** - Automatically retries failed reports when API limits reset
- ✅ **Scenario Filtering** - Only reports actual attacks, filters out system maintenance
- ✅ **Rate Limiting** - Configurable throttling to respect AbuseIPDB limits
- ✅ **Systemd Integration** - Runs as a secure system service
- ✅ **Comprehensive Logging** - Detailed logs for monitoring and debugging

## Requirements

- Ubuntu/Debian Linux server
- CrowdSec installed and running
- Python 3.8+
- Internet access for AbuseIPDB API

## Installation

### 1. Download and Setup

```bash
# Clone the repository
git clone https://github.com/memedevorg/abuseipdb-crowdsec.git
cd crowdsec-abuseipdb-reporter

# Create installation directory
sudo mkdir -p /opt/crowdsec-reporter
sudo cp crowdsec_reporter.py /opt/crowdsec-reporter/
sudo cp config.yml /opt/crowdsec-reporter/
sudo cp crowdsec-reporter.service /opt/crowdsec-reporter/
```

### 2. Install Dependencies

```bash
# Install Python dependencies
sudo apt update
sudo apt install python3 python3-yaml sqlite3

# Create user for the service
sudo useradd -r -s /bin/false crowdsec-reporter
sudo chown -R crowdsec-reporter:crowdsec-reporter /opt/crowdsec-reporter
```

### 3. Configure API Keys

#### Get CrowdSec Machine Credentials (Recommended)
```bash
# Generate machine credentials for alerts access
sudo cscli machines add abuseipdb-reporter --auto

# Copy credentials to reporter directory
sudo cp /etc/crowdsec/local_api_credentials.yaml /opt/crowdsec-reporter/
sudo chown crowdsec-reporter:crowdsec-reporter /opt/crowdsec-reporter/local_api_credentials.yaml
```

#### Get CrowdSec Bouncer API Key (Fallback)
```bash
# Generate bouncer API key
sudo cscli bouncers add abuseipdb-reporter

# Note the API key for configuration
```

#### Get AbuseIPDB API Key
1. Create a free account at [abuseipdb.com](https://www.abuseipdb.com)
2. Go to Account Settings → API
3. Generate an API key (free tier: 1000 reports/day)

### 4. Configure the Application

Edit the configuration file:
```bash
sudo nano /opt/crowdsec-reporter/config.yml
```

```yaml
# CrowdSec Configuration
crowdsec:
  url: "http://localhost:8080"
  api_key: "YOUR_CROWDSEC_BOUNCER_API_KEY"  # Fallback auth

# AbuseIPDB Configuration  
abuseipdb:
  api_key: "YOUR_ABUSEIPDB_API_KEY"

# Operational Settings
settings:
  poll_interval: 300        # Seconds between polls (5 minutes)
  hours_back: 24           # How far back to look for alerts
  daemon_mode: true        # Run continuously
  abuseipdb_throttle: 10   # Seconds between reports

# Logging Configuration
logging:
  level: "INFO"
  file: "crowdsec_reporter.log"

# Persistence Configuration
persistence:
  database_file: "crowdsec_reports.db"
  history_retention_days: 30
```

### 5. Install as System Service

```bash
# Install systemd service
sudo cp /opt/crowdsec-reporter/crowdsec-reporter.service /etc/systemd/system/

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable crowdsec-reporter
sudo systemctl start crowdsec-reporter

# Check status
sudo systemctl status crowdsec-reporter
```

## Usage

### Monitor the Service

```bash
# Check service status
sudo systemctl status crowdsec-reporter

# View logs
sudo journalctl -u crowdsec-reporter -f

# View application logs
sudo tail -f /opt/crowdsec-reporter/crowdsec_reporter.log
```

### Database Management

```bash
# View reported IPs
sqlite3 /opt/crowdsec-reporter/crowdsec_reports.db "SELECT ip_address, scenario, reported_at FROM reported_ips ORDER BY reported_at DESC LIMIT 10;"

# Check statistics
sqlite3 /opt/crowdsec-reporter/crowdsec_reports.db "SELECT COUNT(*) as total_reported FROM reported_ips;"

# View failed reports
sqlite3 /opt/crowdsec-reporter/crowdsec_reports.db "SELECT ip_address, scenario, retry_count FROM failed_reports;"
```

### Manual Testing

```bash
# Run once manually (for testing)
cd /opt/crowdsec-reporter
sudo -u crowdsec-reporter python3 crowdsec_reporter.py
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `poll_interval` | Seconds between CrowdSec polls | 300 (5 min) |
| `hours_back` | Hours of alerts to process | 24 |
| `abuseipdb_throttle` | Seconds between reports | 10 |
| `daemon_mode` | Run continuously vs once | true |
| `history_retention_days` | Days to keep report history | 30 |

## Scenario Mapping

The script maps CrowdSec scenarios to appropriate AbuseIPDB categories:

| CrowdSec Scenario | AbuseIPDB Categories | Description |
|-------------------|---------------------|-------------|
| `ssh:bruteforce` | 18, 22 | Brute-Force, SSH |
| `http:bruteforce` | 18, 21 | Brute-Force, Web Attack |
| `database:bruteforce` | 18 | Database Brute-Force |
| `ftp:bruteforce` | 18, 5 | Brute-Force, FTP |
| `rdp:bruteforce` | 18 | RDP Brute-Force |

## File Structure

```
/opt/crowdsec-reporter/
├── crowdsec_reporter.py          # Main application
├── config.yml                    # Configuration file
├── local_api_credentials.yaml    # CrowdSec machine credentials
├── crowdsec_reports.db           # SQLite database
├── crowdsec_reporter.log         # Application logs
└── crowdsec-reporter.service     # Systemd service file
```

## Troubleshooting

### Common Issues

**Authentication Errors:**
```bash
# Check CrowdSec service
sudo systemctl status crowdsec

# Test machine credentials
sudo cscli alerts list --limit 5

# Test bouncer API key
curl -H "X-Api-Key: YOUR_API_KEY" http://localhost:8080/v1/decisions
```

**Rate Limiting:**
- Free AbuseIPDB accounts: 1000 reports/day
- Increase `abuseipdb_throttle` to slow down reporting
- Check failed reports will be retried automatically

**No Alerts Found:**
```bash
# Check CrowdSec has recent alerts
sudo cscli alerts list --since 24h

# Verify alerts endpoint access
sudo cscli alerts list --limit 5
```

### Logs Analysis

```bash
# Service logs
sudo journalctl -u crowdsec-reporter --since "1 hour ago"

# Application logs with errors
sudo grep ERROR /opt/crowdsec-reporter/crowdsec_reporter.log

# Monitor real-time
sudo tail -f /opt/crowdsec-reporter/crowdsec_reporter.log
```

## Security

The service runs with minimal privileges:
- Dedicated `crowdsec-reporter` user
- Restricted filesystem access
- No network capabilities beyond HTTPS
- Memory and process limits
- System call filtering

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- **Issues:** Open an issue on GitHub
- **CrowdSec Community:** [Discord](https://discord.gg/crowdsec)
- **AbuseIPDB:** [Documentation](https://docs.abuseipdb.com/)

## Changelog

### v1.0.0
- Initial release with dual authentication
- SQLite database for deduplication
- Automatic retry for failed reports
- Systemd service integration
- Comprehensive logging and monitoring

---

**⚠️ Important:** Always test in a non-production environment first. The script will report IPs to a public database that other security tools may use for blocking.

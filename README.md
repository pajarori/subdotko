# Subdotko

A fast, multi-threaded subdomain takeover scanner with fingerprint-based detection.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/subdotko.git
cd subdotko

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Scan a single domain
python3 subdotko.py -d example.com

# Scan a list of domains
python3 subdotko.py -l domains.txt

# Scan with custom thread count
python3 subdotko.py -l domains.txt -t 50
```

### Options

| Flag | Description |
|------|-------------|
| `-d, --domain` | Single domain to scan |
| `-l, --list` | File containing list of domains |
| `-t, --threads` | Number of threads (default: 20) |

## Fingerprints

Fingerprints are stored in `fingerprints/` directory as YAML files. Each fingerprint contains:

- **CNAME patterns** - CNAMEs that indicate a specific service
- **Matcher rules** - Status codes and body content to match
- **Service name** - Name of the vulnerable service

### Adding Custom Fingerprints

Create a new YAML file in `fingerprints/`:

```yaml
identifiers:
  cnames:
  - type: word
    value: example.service.com
  ips: []
  nameservers: []
  not_cnames: []
matcher_rule:
  matchers:
  - condition: or
    part: body
    type: word
    words:
    - "Page not found"
  matchers-condition: and
mode: http
service_name: Example Service
source: custom
```

## Blacklist

Edit `blacklists.txt` to add CNAMEs that should be ignored (false positives):

```
vercel-dns
cloudflare-dns
awsdns
```

## Credits & References

- [BadDNS](https://github.com/blacklanternsecurity/baddns) - Fingerprint database reference
- [DNSReaper](https://github.com/punk-security/dnsReaper) - Additional fingerprints
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) - Takeover templates

## License

MIT License

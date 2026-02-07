<div align="center">

# subdotko
A fast, multi-threaded subdomain takeover scanner with fingerprint-based detection.
Designed for bug bounty hunters and red teamers.

![subdotko Demo](subdotko.gif)

</div>

## Installation

```bash
pipx install git+https://github.com/pajarori/subdotko.git
```

## Usage

### Basic Scans
```bash
# Scan a single domain
subdotko -d hackerone.com -e

# Scan a list of domains
subdotko -l domains.txt
```

### Pipeline Mode
You can pipe domains directly into `subdotko`.

```bash
# Scan with subfinder
subfinder -d hackerone.com -silent | subdotko

# Scan with custom list
cat domains.txt | subdotko

# Scan with enumeration flag (runs subfinder internally)
echo "hackerone.com" | subdotko -e
```

### Options

| Flag | Description |
|------|-------------|
| `-d, --domain` | Single domain to scan |
| `-l, --list` | File containing list of domains |
| `-t, --threads` | Number of threads (default: 20) |
| `-e, --enumerate` | Enumerate subdomains with `subfinder` |

## Fingerprints

Fingerprints are stored in `fingerprints/` as YAML files supporting:

- **CNAME patterns** - CNAMEs that indicate a specific service
- **IP patterns** - IP addresses for IP-based detection (e.g. Wix, Heroku)
- **Matcher rules** - Status codes, body content, and header matching

### Adding Custom Fingerprints

You can define advanced rules using `not_word` and `not_status` to avoid false positives.

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
    part: body  # or 'header'
    type: word
    words:
    - "Page not found"
  
  - type: not_word
    words:
    - "Service Verified"
    - "Welcome"
    
  - type: not_status
    status: 200

  matchers-condition: and
mode: http
service_name: Example Service
source: custom
```

## Blacklist

Edit `blacklists.txt` inside the package to exclude false-positive CNAMEs that are technically takeover-able but practically impossible or safe (e.g. authoritative DNS signatures):

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

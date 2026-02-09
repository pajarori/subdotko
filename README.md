<div align="center">

# subdotko

A fast, async subdomain takeover scanner with fingerprint-based detection.

![subdotko Demo](subdotko.gif)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/pajarori/subdotko?style=flat&logo=github)](https://github.com/pajarori/subdotko/stargazers)
[![Forks](https://img.shields.io/github/forks/pajarori/subdotko?style=flat&logo=github)](https://github.com/pajarori/subdotko/network/members)
[![Issues](https://img.shields.io/github/issues/pajarori/subdotko?style=flat&logo=github)](https://github.com/pajarori/subdotko/issues)
[![Last Commit](https://img.shields.io/github/last-commit/pajarori/subdotko?style=flat&logo=github)](https://github.com/pajarori/subdotko/commits/main)

</div>

## Installation

```bash
pipx install git+https://github.com/pajarori/subdotko.git
```

## Usage

```bash
# Scan a single domain
subdotko -d example.com

# Scan with subdomain enumeration (requires subfinder)
subdotko -d example.com -e

# Scan from stdin (pipe)
cat domains.txt | subdotko

# Scan a list of domains
subdotko -l domains.txt

# Scan with custom concurrency
subdotko -l domains.txt -t 50

# Scan and save output to a file (JSON, CSV, or TXT)
subdotko -d example.com -o results.json

# Output results as JSON to stdout (useful for piping)
subdotko -d example.com --json
```

### Options

| Flag | Description |
|------|-------------|
| `-d, --domain` | Single domain to scan |
| `-l, --list` | File containing list of domains |
| `-t, --threads` | Number of concurrent scans (default: 20) |
| `-s, --sleep` | Sleep time between requests in seconds (default: 0) |
| `-o, --output` | Output file (.txt, .json, .csv) |
| `-e, --enumerate` | Enumerate subdomains with subfinder first |
| `--json` | Output results as JSON to stdout |

## Fingerprints

Fingerprints support:

- **CNAME patterns** - CNAMEs that indicate a specific service
- **IP patterns** - IP addresses for IP-based detection
- **Matcher rules** - Status codes, body content, and header matching

### Adding Custom Fingerprints

All fingerprints are stored in `~/.local/subdotko/fingerprints/` as YAML files.

```yaml
identifiers:
  cnames:
  - type: word
    value: example.service.com
  ips: []
matcher_rule:
  matchers:
  - condition: or
    part: body
    type: word
    words:
    - "Page not found"
  matchers-condition: and
service_name: Example Service
```

## Blacklist

Edit `~/.local/subdotko/blacklists.txt` to exclude false-positive CNAMEs:

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

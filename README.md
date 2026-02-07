# Subdotko

A fast, multi-threaded subdomain takeover scanner with fingerprint-based detection.

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

# Scan a list of domains
subdotko -l domains.txt

# Scan with custom thread count
subdotko -l domains.txt -t 50
```

### Options

| Flag | Description |
|------|-------------|
| `-d, --domain` | Single domain to scan |
| `-l, --list` | File containing list of domains |
| `-t, --threads` | Number of threads (default: 20) |
| `-e, --enumerate` | Enumerate subdomains with subfinder first |

## Fingerprints

Fingerprints are stored in `fingerprints/` as YAML files supporting:

- **CNAME patterns** - CNAMEs that indicate a specific service
- **IP patterns** - IP addresses for IP-based detection
- **Matcher rules** - Status codes, body content, and header matching

### Adding Custom Fingerprints

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
  matchers-condition: and
mode: http
service_name: Example Service
source: custom
```

## Blacklist

Edit `blacklists.txt` to exclude false-positive CNAMEs:

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

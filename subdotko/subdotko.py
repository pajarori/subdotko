import dns.resolver, requests, re, os, yaml, argparse, subprocess, time, sys, tldextract
from pathlib import Path
from functools import wraps
from rich.text import Text
from rich.panel import Panel
from rich.console import Console
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def retry(tries=3, delay=0.5):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(tries):
                try:
                    result = func(*args, **kwargs)
                    if result is not None:
                        return result
                except Exception:
                    pass
                if attempt < tries - 1:
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

def get_package_dir():
    return Path(__file__).parent

class Subdotko:
    resolvers_url = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
    
    def __init__(self, fingerprint_dir=None):
        pkg_dir = get_package_dir()
        self.fingerprint_dir = fingerprint_dir or str(pkg_dir / "fingerprints")
        self.blacklist_path = str(pkg_dir / "blacklists.txt")
        self.blacklist = self._load_blacklist()
        self.resolvers = self._load_resolvers()
        self.fingerprints = self._load_fingerprints()
    
    def _load_blacklist(self):
        if os.path.isfile(self.blacklist_path):
            with open(self.blacklist_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        return []
    
    def _load_resolvers(self):
        try:
            r = requests.get(self.resolvers_url, timeout=5)
            return r.text.splitlines()
        except:
            return ["8.8.8.8", "1.1.1.1"]
    
    def _load_fingerprints(self):
        cnames, cnames_data = [], {}
        ips, ips_data = [], {}
        
        if not os.path.isdir(self.fingerprint_dir):
            return {"cnames": cnames, "cnames_data": cnames_data, "ips": ips, "ips_data": ips_data}
        
        for filename in os.listdir(self.fingerprint_dir):
            if not filename.endswith(".yml"):
                continue
                
            file_path = os.path.join(self.fingerprint_dir, filename)
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                
            if not data or not data.get('matcher_rule'):
                continue
            
            if data.get("identifiers", {}).get("cnames"):
                for cname in data["identifiers"]["cnames"]:
                    cname_value = cname["value"]
                    cnames.append(cname_value)
                    cnames_data[cname_value] = {
                        "service_name": data.get('service_name', 'Unknown'),
                        "matcher_rule": data['matcher_rule']
                    }
            
            if data.get("identifiers", {}).get("ips"):
                for ip in data["identifiers"]["ips"]:
                    if isinstance(ip, dict):
                        ip_value = ip.get("value", "")
                    else:
                        ip_value = str(ip)
                    
                    if ip_value:
                        ips.append(ip_value)
                        ips_data[ip_value] = {
                            "service_name": data.get('service_name', 'Unknown'),
                            "matcher_rule": data['matcher_rule']
                        }
        
        return {"cnames": cnames, "cnames_data": cnames_data, "ips": ips, "ips_data": ips_data}
    
    @retry(tries=3, delay=0.5)
    def dns_query(self, domain, record_type):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.resolvers
        resolver.timeout = 3
        resolver.lifetime = 5
        try:
            answers = resolver.resolve(domain, record_type)
            return {"status": "found", "records": [answer.to_text() for answer in answers]}
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain", "records": []}
        except dns.resolver.NoAnswer:
            return {"status": "no_answer", "records": []}
        except dns.resolver.NoNameservers:
            return {"status": "no_ns", "records": []}
        except Exception:
            return {"status": "error", "records": []}
    
    @retry(tries=2, delay=0.5)
    def http_query(self, domain):
        for protocol in ["https", "http"]:
            try:
                r = requests.get(f"{protocol}://{domain}", timeout=5, verify=False)
                title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                return {
                    "title": title_match.group(1) if title_match else "",
                    "status_code": r.status_code,
                    "body": r.text,
                    "headers": dict(r.headers),
                    "protocol": protocol
                }
            except:
                continue
        return None
    
    def _check_status_matcher(self, response, matcher):
        status = matcher.get('status')
        negative = matcher.get('negative', False)
        
        result = False
        if isinstance(status, list):
            result = response['status_code'] in status
        else:
            result = response['status_code'] == status
            
        return not result if negative else result
    
    def _check_word_matcher(self, response, matcher):
        words = matcher.get('words', [])
        condition = matcher.get('condition', 'or')
        part = matcher.get('part', 'body')
        negative = matcher.get('negative', False)
        
        if part == 'body':
            text = response.get('body', '')
        elif part == 'header':
            text = str(response.get('headers', {}))
        else:
            text = response.get('body', '')
        
        if isinstance(words, str):
            result = words in text
            return not result if negative else result
        
        results = [word in text for word in words]
        final_result = all(results) if condition == 'and' else any(results)
        return not final_result if negative else final_result
    
    def check_matcher(self, response, matcher_rule):
        if not response:
            return False
        
        condition = matcher_rule.get('matchers-condition', 'or')
        results = []
        
        for matcher in matcher_rule.get('matchers', []):
            matcher_type = matcher.get('type')
            
            if matcher_type == 'status':
                results.append(self._check_status_matcher(response, matcher))
            elif matcher_type == 'word':
                results.append(self._check_word_matcher(response, matcher))
            elif matcher_type == 'not_word':
                matcher['negative'] = True
                results.append(self._check_word_matcher(response, matcher))
            elif matcher_type == 'not_status':
                matcher['negative'] = True
                results.append(self._check_status_matcher(response, matcher))
            else:
                results.append(False)
        
        return all(results) if condition == 'and' or condition == 'and_all' else any(results)
    
    def _is_blacklisted(self, value, domain=None):
        if domain and domain.split('.')[-2] in value:
            return True
        return any(bl in value for bl in self.blacklist)
    
    def check_domain_available(self, cname):
        try:
            extracted = tldextract.extract(cname.rstrip('.'))
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            if not base_domain or base_domain == '.':
                return None
            
            result = self.dns_query(base_domain, 'NS')
            if result and result.get('status') == 'nxdomain':
                return base_domain
            return None
        except Exception:
            return None
    
    def _find_matching_cname_service(self, cname, http_response):
        for fp_cname in self.fingerprints["cnames"]:
            if fp_cname in cname:
                data = self.fingerprints["cnames_data"][fp_cname]
                if self.check_matcher(http_response, data['matcher_rule']):
                    reason = ""
                    for matcher in data['matcher_rule'].get('matchers', []):
                        if matcher.get('type') == 'word' and matcher.get('words'):
                            reason = matcher['words'][0][:50] if matcher['words'] else ""
                            break
                    return data['service_name'], reason
        return None, None
    
    def _find_matching_ip_service(self, ip, http_response):
        for fp_ip in self.fingerprints["ips"]:
            if fp_ip == ip or fp_ip in ip:
                data = self.fingerprints["ips_data"][fp_ip]
                if self.check_matcher(http_response, data['matcher_rule']):
                    reason = f"IP: {ip}"
                    return data['service_name'], reason
        return None, None
    
    def scan(self, domain):
        cname_result = self.dns_query(domain, "CNAME")
        a_result = self.dns_query(domain, "A")
        
        cnames = cname_result.get('records', []) if cname_result else []
        a_records = a_result.get('records', []) if a_result else []
        
        if not cnames and not a_records:
            return None
        
        http_response = self.http_query(domain)
        cname_cnames = []
        
        for cname in cnames:
            if self._is_blacklisted(cname, domain):
                return None
            
            available_domain = self.check_domain_available(cname)
            if available_domain:
                return ("dead", f"[bold magenta][DED][/] [cyan]{domain}[/] → [red]{available_domain}[/] [dim](Available for registration!)[/]")
            
            service, reason = self._find_matching_cname_service(cname, http_response)
            if service:
                reason_text = f" [dim]({reason})[/]" if reason else ""
                return ("vuln", f"[bold red][VLN][/] [cyan]{domain}[/] → [yellow]{service}[/]{reason_text}")
            
            nested = self.dns_query(cname, "CNAME")
            if nested and nested.get('records'):
                cname_cnames.extend(nested['records'])
        
        for ip in a_records:
            service, reason = self._find_matching_ip_service(ip, http_response)
            if service:
                reason_text = f" [dim]({reason})[/]" if reason else ""
                return ("vuln", f"[bold red][VLN][/] [cyan]{domain}[/] → [yellow]{service}[/]{reason_text}")
        
        if cnames:
            status = http_response.get('status_code', '?') if http_response else '?'
            status_color = "green" if status == 200 else "yellow" if isinstance(status, int) and status < 400 else "red"
            return ("info", f"[[{status_color}]{status}[/]] [blue]{domain}[/] → {cnames[0]} [dim]{cname_cnames or ''}[/]")
        
        return None
    
    @staticmethod
    def enumerate_subdomains(domain):
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            subdomains = result.stdout.strip().splitlines()
            return [s.strip() for s in subdomains if s.strip()]
        except FileNotFoundError:
            console.print("[red]Error:[/] subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return []
        except subprocess.TimeoutExpired:
            console.print("[yellow]Warning:[/] subfinder timed out")
            return []


def main():
    parser = argparse.ArgumentParser(description="Subdotko - Subdomain fingerprinting tool")
    parser.add_argument("-d", "--domain", help="Domain to scan")
    parser.add_argument("-l", "--list", help="List of domains to scan")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("-e", "--enumerate", action="store_true", help="Enumerate subdomains with subfinder first")
    args = parser.parse_args()

    banner = """[bold cyan]
    ▌  ▌  ▗ ▌   
▛▘▌▌▛▌▛▌▛▌▜▘▙▘▛▌
▄▌▙▌▙▌▙▌▙▌▐▖▛▖▙▌ [/bold cyan][dim]v1.0.3[/dim]
[white][dim]pajarori[/dim][/white]
    """
    console.print(banner)

    subdotko = Subdotko()
    console.print(f"[dim]Loaded [cyan]{len(subdotko.fingerprints['cnames'])}[/] CNAME + [cyan]{len(subdotko.fingerprints['ips'])}[/] IP fingerprints[/]")

    domains = []
    
    if not sys.stdin.isatty():
        domains.extend([line.strip() for line in sys.stdin if line.strip()])

    if args.domain:
        domains.append(args.domain)
    elif args.list:
        with open(args.list, "r") as f:
            domains.extend([line.strip() for line in f if line.strip()])
    
    domains = list(set(domains))
    
    if args.enumerate:
        expanded_domains = []
        for domain in domains:
            console.print(f"[dim]Enumerating subdomains for [cyan]{domain}[/]...[/]")
            subs = subdotko.enumerate_subdomains(domain)
            if subs:
                expanded_domains.extend(subs)
                console.print(f"[dim]Found [cyan]{len(subs)}[/] subdomains for [cyan]{domain}[/][/]")
            else:
                expanded_domains.append(domain)
        domains = list(set(expanded_domains))
    
    if not domains:
        console.print("[red]No domains provided. Use -d, -l, or pipe input.[/]")
        return
    
    if len(domains) == 1:
        console.print(f"[dim]Scanning [cyan]{domains[0]}[/][/]\n")
        result = subdotko.scan(domains[0])
        if result:
            console.print(result[1])
    else:
        console.print(f"[dim]Scanning [cyan]{len(domains)}[/] domains with [cyan]{args.threads}[/] threads[/]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=24),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("", total=len(domains))
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(subdotko.scan, domain): domain for domain in domains}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        progress.console.print(result[1])
                    progress.advance(task)
    
    console.print(f"\n[bold green]✓[/] Scan complete!")

if __name__ == "__main__":
    main()

import dns.resolver, dns.asyncresolver, re, os, yaml, argparse, subprocess, sys, asyncio, hashlib, json, tldextract, httpx, shutil
from pathlib import Path
from datetime import datetime, timedelta
from rich.text import Text
from rich.panel import Panel
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn

console = Console()

RESOLVER_CACHE_TTL_HOURS = 24
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

def get_package_dir():
    return Path(__file__).parent

def get_data_dir():
    data_dir = Path.home() / ".local" / "subdotko"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir

def get_cache_dir():
    cache_dir = get_data_dir() / ".cache"
    cache_dir.mkdir(exist_ok=True)
    return cache_dir

def ensure_data_files():
    pkg_dir = get_package_dir()
    data_dir = get_data_dir()
    
    dst_fingerprints = data_dir / "fingerprints"
    if not dst_fingerprints.exists():
        src_fingerprints = pkg_dir / "fingerprints"
        if src_fingerprints.exists():
            shutil.copytree(src_fingerprints, dst_fingerprints)
    
    dst_blacklist = data_dir / "blacklists.txt"
    if not dst_blacklist.exists():
        src_blacklist = pkg_dir / "blacklists.txt"
        if src_blacklist.exists():
            shutil.copy2(src_blacklist, dst_blacklist)

class ResolverManager:
    RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
    
    def __init__(self):
        self.cache_file = get_cache_dir() / "resolvers.json"
        self.resolvers = self._load_resolvers()
        self._resolver = None
        self._async_resolver = None
    
    def _load_resolvers(self):
        cached = self._load_from_cache()
        if cached:
            return cached
        
        fetched = self._fetch_from_remote()
        if fetched:
            self._save_to_cache(fetched)
            return fetched
        
        return DEFAULT_RESOLVERS.copy()
    
    def _load_from_cache(self):
        if not self.cache_file.exists():
            return None
        
        try:
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            
            cached_time = datetime.fromisoformat(data.get("timestamp", ""))
            if datetime.now() - cached_time < timedelta(hours=RESOLVER_CACHE_TTL_HOURS):
                resolvers = data.get("resolvers", [])
                if resolvers:
                    return resolvers
        except (json.JSONDecodeError, ValueError, KeyError, OSError) as e:
            console.print(f"[dim]Cache read warning: {e}[/]")
        
        return None
    
    def _fetch_from_remote(self):
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(self.RESOLVERS_URL)
                response.raise_for_status()
                resolvers = [line.strip() for line in response.text.splitlines() if line.strip()]
                if resolvers:
                    return resolvers
        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            console.print(f"[yellow]Warning:[/] Could not fetch resolvers: {e}")
        
        return None
    
    def _save_to_cache(self, resolvers):
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "resolvers": resolvers
            }
            with open(self.cache_file, "w") as f:
                json.dump(data, f)
        except OSError as e:
            console.print(f"[yellow]Warning:[/] Could not cache resolvers: {e}")
    
    def get_resolver(self):
        if self._resolver is None:
            self._resolver = dns.resolver.Resolver()
            self._resolver.nameservers = self.resolvers[:10]
            self._resolver.timeout = 3
            self._resolver.lifetime = 5
        return self._resolver
    
    def get_async_resolver(self):
        if self._async_resolver is None:
            self._async_resolver = dns.asyncresolver.Resolver()
            self._async_resolver.nameservers = self.resolvers[:10]
            self._async_resolver.timeout = 3
            self._async_resolver.lifetime = 5
        return self._async_resolver


class Subdotko:
    def __init__(self, fingerprint_dir=None, resolver_manager=None):
        data_dir = get_data_dir()
        self.fingerprint_dir = fingerprint_dir or str(data_dir / "fingerprints")
        self.blacklist_path = str(data_dir / "blacklists.txt")
        self.blacklist = self._load_blacklist()
        self.resolver_manager = resolver_manager or ResolverManager()
        self.fingerprints = self._load_fingerprints()
    
    def _load_blacklist(self):
        if os.path.isfile(self.blacklist_path):
            try:
                with open(self.blacklist_path, "r") as f:
                    return [line.strip() for line in f if line.strip()]
            except OSError as e:
                console.print(f"[yellow]Warning:[/] Could not load blacklist: {e}")
        return []
    
    def _load_fingerprints(self):
        cnames, cnames_data = [], {}
        ips, ips_data = [], {}
        
        if not os.path.isdir(self.fingerprint_dir):
            return {"cnames": cnames, "cnames_data": cnames_data, "ips": ips, "ips_data": ips_data}
        
        try:
            for filename in os.listdir(self.fingerprint_dir):
                if not filename.endswith(".yml"):
                    continue
                    
                file_path = os.path.join(self.fingerprint_dir, filename)
                try:
                    with open(file_path, "r") as f:
                        try:
                            data = yaml.load(f, Loader=yaml.CSafeLoader)
                        except AttributeError:
                            data = yaml.safe_load(f)
                except (yaml.YAMLError, OSError) as e:
                    console.print(f"[yellow]Warning:[/] Could not load {filename}: {e}")
                    continue
                        
                if not data or not data.get('matcher_rule'):
                    continue
                
                if data.get("identifiers", {}).get("cnames"):
                    for cname in data["identifiers"]["cnames"]:
                        cname_value = cname.get("value", "")
                        if cname_value:
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
        except OSError as e:
            console.print(f"[yellow]Warning:[/] Could not read fingerprints directory: {e}")
        
        return {"cnames": cnames, "cnames_data": cnames_data, "ips": ips, "ips_data": ips_data}
    
    async def dns_query(self, domain, record_type, retries=3):
        """Async DNS query with retries."""
        resolver = self.resolver_manager.get_async_resolver()
        
        for attempt in range(retries):
            try:
                answers = await resolver.resolve(domain, record_type)
                return {"status": "found", "records": [answer.to_text() for answer in answers]}
            except dns.resolver.NXDOMAIN:
                return {"status": "nxdomain", "records": []}
            except dns.resolver.NoAnswer:
                return {"status": "no_answer", "records": []}
            except dns.resolver.NoNameservers:
                return {"status": "no_ns", "records": []}
            except (dns.resolver.Timeout, dns.resolver.LifetimeTimeout) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                return {"status": "timeout", "records": []}
            except dns.exception.DNSException as e:
                if attempt < retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                return {"status": "error", "records": []}
        
        return {"status": "error", "records": []}
    
    async def http_query(self, client, domain, retries=2):
        """Async HTTP query with connection pooling via shared client."""
        for attempt in range(retries):
            for protocol in ["https", "http"]:
                try:
                    response = await client.get(
                        f"{protocol}://{domain}",
                        timeout=5.0,
                        follow_redirects=True
                    )
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                    return {
                        "title": title_match.group(1) if title_match else "",
                        "status_code": response.status_code,
                        "body": response.text,
                        "headers": dict(response.headers),
                        "protocol": protocol
                    }
                except (httpx.HTTPError, httpx.TimeoutException, OSError):
                    continue
            
            if attempt < retries - 1:
                await asyncio.sleep(0.5)
        
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
        
        return all(results) if condition in ('and', 'and_all') else any(results)
    
    def _is_blacklisted(self, value, domain=None):
        if domain and domain.split('.')[-2] in value:
            return True
        return any(bl in value for bl in self.blacklist)
    
    async def check_domain_available(self, cname):
        try:
            extracted = tldextract.extract(cname.rstrip('.'))
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            if not base_domain or base_domain == '.':
                return None
            
            result = await self.dns_query(base_domain, 'NS')
            if result and result.get('status') == 'nxdomain':
                return base_domain
            return None
        except (ValueError, AttributeError) as e:
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
    
    async def scan(self, client, domain):
        cname_task = asyncio.create_task(self.dns_query(domain, "CNAME"))
        a_task = asyncio.create_task(self.dns_query(domain, "A"))
        
        cname_result, a_result = await asyncio.gather(cname_task, a_task)
        
        cnames = cname_result.get('records', []) if cname_result else []
        a_records = a_result.get('records', []) if a_result else []
        
        if not cnames and not a_records:
            return None
        
        http_response = await self.http_query(client, domain)
        cname_cnames = []
        
        for cname in cnames:
            if self._is_blacklisted(cname, domain):
                return None
            
            available_domain = await self.check_domain_available(cname)
            if available_domain:
                return ("dead", f"[bold magenta][DED][/] [cyan]{domain}[/] → [red]{available_domain}[/] [dim](Available for registration!)[/]")
            
            service, reason = self._find_matching_cname_service(cname, http_response)
            if service:
                reason_text = f" [dim]({reason})[/]" if reason else ""
                return ("vuln", f"[bold red][VLN][/] [cyan]{domain}[/] → [yellow]{service}[/]{reason_text}")
            
            nested = await self.dns_query(cname, "CNAME")
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


async def scan_domains(subdotko, domains, max_concurrent=20):
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_semaphore(client, domain):
        async with semaphore:
            return await subdotko.scan(client, domain)
    
    limits = httpx.Limits(max_keepalive_connections=max_concurrent, max_connections=max_concurrent * 2)
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        limits=limits,
        timeout=httpx.Timeout(10.0, connect=5.0)
    ) as client:
        tasks = [scan_with_semaphore(client, domain) for domain in domains]
        
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
            
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    progress.console.print(result[1])
                    results.append(result)
                progress.advance(task)
    
    return results

async def scan_single(subdotko, domain):
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        limits=limits,
        timeout=httpx.Timeout(10.0, connect=5.0)
    ) as client:
        return await subdotko.scan(client, domain)

def main():
    parser = argparse.ArgumentParser(description="Subdotko - Subdomain fingerprinting tool")
    parser.add_argument("-d", "--domain", help="Domain to scan")
    parser.add_argument("-l", "--list", help="List of domains to scan")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent scans (default: 20)")
    parser.add_argument("-e", "--enumerate", action="store_true", help="Enumerate subdomains with subfinder first")
    args = parser.parse_args()

    banner = """[bold cyan]
    ▌  ▌  ▗ ▌   
▛▘▌▌▛▌▛▌▛▌▜▘▙▘▛▌
▄▌▙▌▙▌▙▌▙▌▐▖▛▖▙▌ [/bold cyan][dim]v1.1.0[/dim]
[white][dim]pajarori[/dim][/white]
    """
    console.print(banner)

    resolver_manager = ResolverManager()
    
    subdotko = Subdotko(resolver_manager=resolver_manager)
    console.print(f"[dim]Loaded [cyan]{len(subdotko.fingerprints['cnames'])}[/] CNAME + [cyan]{len(subdotko.fingerprints['ips'])}[/] IP fingerprints[/]")

    domains = []
    
    if not sys.stdin.isatty():
        domains.extend([line.strip() for line in sys.stdin if line.strip()])

    if args.domain:
        domains.append(args.domain)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                domains.extend([line.strip() for line in f if line.strip()])
        except OSError as e:
            console.print(f"[red]Error:[/] Could not read file: {e}")
            return
    
    domains = list(set(domains))
    
    if args.enumerate:
        expanded_domains = []
        for domain in domains:
            console.print(f"[dim]Enumerating subdomains for [cyan]{domain}[/]...[/]")
            subs = subdotko.enumerate_subdomains(domain)
            if subs:
                expanded_domains.extend(subs)
            else:
                expanded_domains.append(domain)
        domains = list(set(expanded_domains))
    
    if not domains:
        console.print("[red]No domains provided. Use -d, -l, or pipe input.[/]")
        return
    
    if len(domains) == 1:
        console.print(f"[dim]Scanning [cyan]{domains[0]}[/][/]\n")
        result = asyncio.run(scan_single(subdotko, domains[0]))
        if result:
            console.print(result[1])
    else:
        console.print(f"[dim]Scanning [cyan]{len(domains)}[/] domains with [cyan]{args.threads}[/] concurrent connections[/]\n")
        asyncio.run(scan_domains(subdotko, domains, max_concurrent=args.threads))
    
    console.print(f"\n[bold green]✓[/] Scan complete!")

if __name__ == "__main__":
    main()

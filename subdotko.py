import dns.resolver, requests, re, os, yaml, argparse
from rich.text import Text
from rich.panel import Panel
from rich.console import Console
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn

console = Console()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Subdotko:
    resolvers_url = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"
    
    def __init__(self, fingerprint_dir="fingerprints"):
        self.fingerprint_dir = fingerprint_dir
        self.blacklist = self._load_blacklist()
        self.resolvers = self._load_resolvers()
        self.fingerprints = self._load_fingerprints()
    
    def _load_blacklist(self, filepath = "blacklists.txt"):
        if os.path.isfile(filepath):
            with open(filepath, "r") as f:
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
        
        if not os.path.isdir(self.fingerprint_dir):
            return {"cnames": cnames, "cnames_data": cnames_data}
        
        for filename in os.listdir(self.fingerprint_dir):
            if not filename.endswith(".yml"):
                continue
                
            file_path = os.path.join(self.fingerprint_dir, filename)
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                
            if not data or not data.get("identifiers", {}).get("cnames") or not data.get('matcher_rule'):
                continue
                
            for cname in data["identifiers"]["cnames"]:
                cname_value = cname["value"]
                cnames.append(cname_value)
                cnames_data[cname_value] = {
                    "service_name": data.get('service_name', 'Unknown'),
                    "matcher_rule": data['matcher_rule']
                }
        
        return {"cnames": cnames, "cnames_data": cnames_data}
    
    def dns_query(self, domain, record_type):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.resolvers
        resolver.timeout = 3
        resolver.lifetime = 5

        try:
            answers = resolver.resolve(domain, record_type)
            return [answer.to_text() for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return None
        except Exception:
            return None
    
    def http_query(self, domain):
        try:
            r = requests.get(f"http://{domain}", timeout=5, verify=False)
            title_match = re.search(r'<title>(.*?)</title>', r.text)
            return {
                "title": title_match.group(1) if title_match else "",
                "status_code": r.status_code,
                "body": r.text
            }
        except Exception:
            return None
    
    def _check_status_matcher(self, response, matcher):
        status = matcher.get('status')
        if isinstance(status, list):
            return response['status_code'] in status
        return response['status_code'] == status
    
    def _check_word_matcher(self, response, matcher):
        words = matcher.get('words', [])
        condition = matcher.get('condition', 'or')
        part = matcher.get('part', 'body')
        
        text = response['body'] if part == 'body' else ""
        
        if isinstance(words, str):
            return words in text
        
        results = [word in text for word in words]
        return all(results) if condition == 'and' else any(results)
    
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
            else:
                results.append(False)
        
        return all(results) if condition == 'and' else any(results)
    
    def _is_blacklisted(self, cname):
        return any(bl in cname for bl in self.blacklist)
    
    def _find_matching_service(self, cname, http_response):
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
    
    def scan(self, domain):
        cnames = self.dns_query(domain, "CNAME") or []
        if not cnames:
            return None
        
        http_response = self.http_query(domain)
        cname_cnames = []
        
        for cname in cnames:
            if self._is_blacklisted(cname):
                return None
            
            service, reason = self._find_matching_service(cname, http_response)
            if service:
                reason_text = f" [dim]({reason})[/]" if reason else ""
                return ("vuln", f"[bold red][VLN][/] [cyan]{domain}[/] → [yellow]{service}[/]{reason_text}")
            
            nested = self.dns_query(cname, "CNAME")
            if nested:
                cname_cnames.extend(nested)
        
        status = http_response.get('status_code', '?') if http_response else '?'
        status_color = "green" if status == 200 else "yellow" if isinstance(status, int) and status < 400 else "red"
        return ("info", f"[[{status_color}]{status}[/]] [blue]{domain}[/] → [dim]{cnames[0]}[/] {cname_cnames or ''}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdotko - Subdomain fingerprinting tool")
    parser.add_argument("-d", "--domain", help="Domain to scan")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-l", "--list", help="List of domains to scan")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    args = parser.parse_args()

    console.print(Panel.fit(
        Text("SUBDOTKO", style="bold cyan") + Text(" - Subdomain Takeover Scanner", style="dim"),
        border_style="cyan"
    ))

    subdotko = Subdotko()
    console.print(f"[dim]Loaded [cyan]{len(subdotko.fingerprints['cnames'])}[/] fingerprints[/]")

    if args.domain:
        result = subdotko.scan(args.domain)
        if result:
            console.print(result[1])
    elif args.list:
        with open(args.list, "r") as f:
            domains = f.read().splitlines()
        
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

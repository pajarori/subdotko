import dns.resolver, dns.exception, re, os, yaml, subprocess, asyncio, tldextract
import httpx
from .utils import get_data_dir, console
from .resolver import ResolverManager

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
            except (dns.resolver.Timeout, dns.resolver.LifetimeTimeout):
                if attempt < retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                return {"status": "timeout", "records": []}
            except dns.exception.DNSException:
                if attempt < retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                return {"status": "error", "records": []}
        
        return {"status": "error", "records": []}
    
    async def http_query(self, client, domain, retries=2):
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
        except (ValueError, AttributeError):
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
        http_status = http_response.get('status_code') if http_response else None
        cname_cnames = []
        
        for cname in cnames:
            if self._is_blacklisted(cname, domain):
                return None
            
            available_domain = await self.check_domain_available(cname)
            if available_domain:
                return {
                    "domain": domain,
                    "status": "dead",
                    "cname": cname,
                    "nested_cnames": cname_cnames,
                    "service": None,
                    "reason": f"Available for registration: {available_domain}",
                    "http_status": http_status
                }
            
            service, reason = self._find_matching_cname_service(cname, http_response)
            if service:
                return {
                    "domain": domain,
                    "status": "vuln",
                    "cname": cname,
                    "nested_cnames": cname_cnames,
                    "service": service,
                    "reason": reason,
                    "http_status": http_status
                }
            
            nested = await self.dns_query(cname, "CNAME")
            if nested and nested.get('records'):
                cname_cnames.extend(nested['records'])
        
        for ip in a_records:
            service, reason = self._find_matching_ip_service(ip, http_response)
            if service:
                return {
                    "domain": domain,
                    "status": "vuln",
                    "cname": None,
                    "nested_cnames": [],
                    "service": service,
                    "reason": reason,
                    "http_status": http_status,
                    "ip": ip
                }
        
        if cnames:
            return {
                "domain": domain,
                "status": "info",
                "cname": cnames[0],
                "nested_cnames": cname_cnames,
                "service": None,
                "reason": None,
                "http_status": http_status
            }
        
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

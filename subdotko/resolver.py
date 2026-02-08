import dns.resolver, dns.asyncresolver, json, httpx
from datetime import datetime, timedelta
from .utils import get_cache_dir, console, RESOLVER_CACHE_TTL_HOURS, DEFAULT_RESOLVERS

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

import dns.resolver, dns.asyncresolver, json, httpx, random
from datetime import datetime, timedelta
from .utils import get_cache_dir, console, RESOLVER_CACHE_TTL_HOURS, DEFAULT_RESOLVERS


class ResolverManager:
    RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"

    def __init__(self, pool_size=50, nameservers_per_resolver=3):
        self.cache_file = get_cache_dir() / "resolvers.json"
        self.all_resolvers = self._load_resolvers()
        self.pool_size = min(pool_size, max(1, len(self.all_resolvers) // nameservers_per_resolver))
        self.nameservers_per_resolver = nameservers_per_resolver
        self._pool = self._build_pool()
        self._index = 0

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

    def _build_pool(self):
        shuffled = self.all_resolvers.copy()
        random.shuffle(shuffled)

        pool = []
        for i in range(self.pool_size):
            start = (i * self.nameservers_per_resolver) % len(shuffled)
            ns_list = []
            for j in range(self.nameservers_per_resolver):
                ns_list.append(shuffled[(start + j) % len(shuffled)])
            pool.append(ns_list)

        return pool

    def _next_nameservers(self):
        ns = self._pool[self._index % len(self._pool)]
        self._index += 1
        return ns

    def get_resolver(self):
        r = dns.resolver.Resolver()
        r.nameservers = self._next_nameservers()
        r.timeout = 3
        r.lifetime = 5
        return r

    def get_async_resolver(self):
        r = dns.asyncresolver.Resolver()
        r.nameservers = self._next_nameservers()
        r.timeout = 3
        r.lifetime = 5
        return r

    def resolver_count(self):
        return len(self.all_resolvers)

    def pool_count(self):
        return self.pool_size

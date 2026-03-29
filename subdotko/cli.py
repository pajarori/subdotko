import sys, asyncio, argparse, httpx, json, csv, os, time
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskProgressColumn
from .utils import console, ensure_data_files, get_session_dir, calculate_session_hash, clean_old_sessions, VERSION
from .resolver import ResolverManager
from .scanner import Subdotko, ScanResult

_silent = False

MAX_HTTP_CONNECTIONS = 100


def cprint(*args, **kwargs):
    if not _silent:
        console.print(*args, **kwargs)


def format_result(result):
    if not result:
        return None

    domain = result["domain"]
    status = result["status"]
    cname = result.get("cname", "")
    nested = result.get("nested_cnames", [])
    service = result.get("service", "")
    reason = result.get("reason", "")
    http_status = result.get("http_status")

    if status == ScanResult.DEAD:
        return f"[bold magenta][DED][/] [cyan]{domain}[/] → [red]{cname}[/] [dim]({reason})[/]"
    elif status == ScanResult.VULN:
        reason_text = f" [dim]({reason})[/]" if reason else ""
        return f"[bold red][VLN][/] [cyan]{domain}[/] → [yellow]{service}[/]{reason_text}"
    elif status == ScanResult.INFO:
        if http_status is None:
            status_color = "white"
            http_status_display = "SKP"
        else:
            status_color = "green" if http_status == 200 else "yellow" if isinstance(http_status, int) and http_status < 400 else "red"
            http_status_display = http_status
        nested_str = f" [dim]{nested}[/]" if nested else ""
        return f"[[{status_color}]{http_status_display}[/]] [blue]{domain}[/] → {cname}{nested_str}"

    return None


class OutputWriter:
    CSV_FIELDS = ["domain", "status", "cname", "nested_cnames", "service", "reason", "http_status"]

    def __init__(self, output_path=None, json_stdout=False):
        self.output_path = output_path
        self.json_stdout = json_stdout
        self.ext = output_path.lower().split('.')[-1] if output_path and '.' in output_path else 'txt'
        self._file = None
        self._csv_writer = None
        self._results_for_json = []

    def open(self):
        if self.json_stdout:
            return
        if not self.output_path:
            return
        try:
            if self.ext == 'json':
                self._file = open(self.output_path, 'w')
                self._file.write('[\n')
            elif self.ext == 'csv':
                self._file = open(self.output_path, 'w', newline='')
                self._csv_writer = csv.DictWriter(self._file, fieldnames=self.CSV_FIELDS, extrasaction='ignore')
                self._csv_writer.writeheader()
                self._file.flush()
            else:
                self._file = open(self.output_path, 'w')
        except OSError as e:
            cprint(f"[red]Error:[/] Could not open {self.output_path}: {e}")

    def write(self, result):
        if not result or result.get("status") == ScanResult.TIMEOUT:
            return
        if self.json_stdout:
            self._results_for_json.append(result)
            return
        if not self._file:
            return
        try:
            if self.ext == 'json':
                prefix = '  ' if self._file.tell() <= 2 else ',\n  '
                self._file.write(prefix + json.dumps(result, default=str))
                self._file.flush()
            elif self.ext == 'csv':
                row = result.copy()
                row["nested_cnames"] = ",".join(row.get("nested_cnames", []))
                self._csv_writer.writerow(row)
                self._file.flush()
            else:
                line = f"{result['domain']},{result['status']}"
                if result.get('cname'):
                    line += f",{result['cname']}"
                if result.get('service'):
                    line += f",{result['service']}"
                if result.get('reason'):
                    line += f",{result['reason']}"
                self._file.write(line + "\n")
                self._file.flush()
        except OSError:
            pass

    def close(self):
        if self.json_stdout:
            print(json.dumps(self._results_for_json, indent=2, default=str))
            return
        if not self._file:
            return
        try:
            if self.ext == 'json':
                self._file.write('\n]\n')
            self._file.close()
            cprint(f"[dim]Results saved to [cyan]{self.output_path}[/][/]")
        except OSError:
            pass


class ScanStats:
    def __init__(self):
        self.vuln = 0
        self.dead = 0
        self.info = 0
        self.timeout = 0
        self.scanned = 0

    def update(self, result):
        self.scanned += 1
        if not result:
            return
        s = result.get("status")
        if s == ScanResult.VULN:
            self.vuln += 1
        elif s == ScanResult.DEAD:
            self.dead += 1
        elif s == ScanResult.INFO:
            self.info += 1
        elif s == ScanResult.TIMEOUT:
            self.timeout += 1

    def render(self):
        return (
            f"[bold red]VLN:{self.vuln}[/] "
            f"[bold magenta]DED:{self.dead}[/] "
            f"[blue]INF:{self.info}[/] "
            f"[yellow]TMO:{self.timeout}[/]"
        )


async def scan_domains(subdotko, domains, max_concurrent=20, sleep_time=0.0, session_file=None, output_writer=None):
    results = []
    timeout_domains = []
    stats = ScanStats()

    queue = asyncio.Queue(maxsize=max_concurrent * 2)

    http_max = min(MAX_HTTP_CONNECTIONS, max_concurrent * 2)
    limits = httpx.Limits(max_keepalive_connections=min(max_concurrent, MAX_HTTP_CONNECTIONS), max_connections=http_max)
    client = httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        limits=limits,
        timeout=httpx.Timeout(10.0, connect=5.0)
    )

    async def worker():
        while True:
            domain = await queue.get()
            if domain is None:
                queue.task_done()
                break
            try:
                result = await subdotko.scan(client, domain)

                if session_file:
                    session_file.write(json.dumps({"d": domain, "r": result}) + "\n")
                    session_file.flush()

                stats.update(result)

                if result and result.get("status") == ScanResult.TIMEOUT:
                    timeout_domains.append(domain)
                elif result:
                    results.append(result)
                    if output_writer:
                        output_writer.write(result)
                    if not _silent:
                        display = format_result(result)
                        if display:
                            progress.console.print(display)

                progress.advance(task_id)
                progress.update(task_id, status_line=build_status(stats.scanned, total))

                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            except Exception:
                progress.advance(task_id)
                progress.update(task_id, status_line=build_status(stats.scanned, total))
            finally:
                queue.task_done()

    start_time = time.monotonic()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.fields[status_line]}"),
        console=console,
        transient=True,
        disable=_silent
    )

    def build_status(done, total):
        elapsed = time.monotonic() - start_time
        rate = done / elapsed if elapsed > 0 else 0.0
        remaining = (total - done) / rate if rate > 0 else 0
        mins, secs = divmod(int(remaining), 60)
        eta = f"{mins}m{secs:02d}s" if mins else f"{secs}s"
        pct = int(done / total * 100) if total else 0
        return f"{done}/{total} ({pct}%) | {rate:.1f}/s | {stats.render()} | ETA {eta}"

    with progress:
        task_id = progress.add_task("", total=len(domains), status_line="")

        workers = [asyncio.create_task(worker()) for _ in range(max_concurrent)]

        total = len(domains)

        for domain in domains:
            await queue.put(domain)

        for _ in range(max_concurrent):
            await queue.put(None)

        await asyncio.gather(*workers)

    await client.aclose()
    return results, timeout_domains, stats


async def retry_timeouts(subdotko, timeout_domains, session_file=None, output_writer=None):
    if not timeout_domains:
        return [], 0

    cprint(f"\n[dim]Retrying [yellow]{len(timeout_domains)}[/] timed-out domains at low concurrency...[/]")

    retry_results = []
    still_timeout = 0

    retry_dns_sem = asyncio.Semaphore(10)
    retry_http_sem = asyncio.Semaphore(10)
    subdotko.dns_semaphore = retry_dns_sem
    subdotko.http_semaphore = retry_http_sem

    limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        limits=limits,
        timeout=httpx.Timeout(15.0, connect=8.0)
    ) as client:
        sem = asyncio.Semaphore(5)

        async def retry_one(domain):
            nonlocal still_timeout
            async with sem:
                result = await subdotko.scan(client, domain)
                if session_file:
                    session_file.write(json.dumps({"d": domain, "r": result}) + "\n")
                    session_file.flush()
                if result and result.get("status") == ScanResult.TIMEOUT:
                    still_timeout += 1
                elif result:
                    retry_results.append(result)
                    if output_writer:
                        output_writer.write(result)
                    display = format_result(result)
                    if display:
                        cprint(display)

        tasks = [retry_one(d) for d in timeout_domains]
        await asyncio.gather(*tasks)

    return retry_results, still_timeout


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
    global _silent

    parser = argparse.ArgumentParser(description="Subdotko - Subdomain fingerprinting tool")
    parser.add_argument("-d", "--domain", help="Domain to scan")
    parser.add_argument("-l", "--list", help="List of domains to scan")
    parser.add_argument("-o", "--output", help="Output file (.txt, .json, .csv)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent scans (default: 20)")
    parser.add_argument("-s", "--sleep", type=float, default=0.0, help="Sleep time between requests in seconds (default: 0)")
    parser.add_argument("-e", "--enumerate", action="store_true", help="Enumerate subdomains with subfinder first")
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP/HTTPS checks")
    parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    parser.add_argument("--fresh", action="store_true", help="Ignore existing session and start fresh")
    parser.add_argument("--no-retry", action="store_true", help="Skip retry pass for timed-out domains")
    args = parser.parse_args()

    concurrency = args.threads
    _silent = args.json

    banner = f"""[bold cyan]
    ▌  ▌  ▗ ▌
▛▘▌▌▛▌▛▌▛▌▜▘▙▘▛▌
▄▌▙▌▙▌▙▌▙▌▐▖▛▖▙▌ [/bold cyan][dim]v{VERSION}[/dim]
[white][dim]pajarori[/dim][/white]
    """
    cprint(banner)

    ensure_data_files()
    resolver_manager = ResolverManager()

    dns_semaphore = asyncio.Semaphore(concurrency * 3)
    http_semaphore = asyncio.Semaphore(min(concurrency * 2, MAX_HTTP_CONNECTIONS))

    subdotko = Subdotko(
        resolver_manager=resolver_manager,
        no_http=args.no_http,
        dns_semaphore=dns_semaphore,
        http_semaphore=http_semaphore
    )
    cprint(f"[dim]Loaded [cyan]{len(subdotko.fingerprints['cnames'])}[/] CNAME + [cyan]{len(subdotko.fingerprints['ips'])}[/] IP fingerprints[/]")
    cprint(f"[dim]Resolvers: [cyan]{resolver_manager.resolver_count()}[/] available, [cyan]{resolver_manager.pool_count()}[/] pool instances[/]")
    if args.no_http:
        cprint("[dim]HTTP/HTTPS checks disabled[/]")

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
            cprint(f"[red]Error:[/] Could not read file: {e}")
            return

    domains = list(set(domains))

    if args.enumerate:
        expanded_domains = []
        for domain in domains:
            cprint(f"[dim]Enumerating subdomains for [cyan]{domain}[/]...[/]")
            subs = subdotko.enumerate_subdomains(domain)
            if subs:
                expanded_domains.extend(subs)
            else:
                expanded_domains.append(domain)
        domains = list(set(expanded_domains))

    if not domains:
        cprint("[red]No domains provided. Use -d, -l, or pipe input.[/]")
        return

    results = []
    writer = OutputWriter(output_path=args.output, json_stdout=args.json)
    writer.open()

    if len(domains) == 1:
        cprint(f"[dim]Scanning [cyan]{domains[0]}[/][/]\n")
        result = asyncio.run(scan_single(subdotko, domains[0]))
        if result:
            results.append(result)
            writer.write(result)
            display = format_result(result)
            if display:
                cprint(display)
    else:
        clean_old_sessions()
        session_hash = calculate_session_hash(domains)
        session_path = get_session_dir() / f"{session_hash}.jsonl"

        scanned_domains = set()
        previous_results = []

        if session_path.exists():
            if args.fresh:
                try:
                    session_path.unlink()
                    cprint(f"[dim]Starting fresh session (cleared previous session)[/]")
                except OSError:
                    pass
            else:
                cprint(f"[dim]Resuming from last saved session...[/]")
                try:
                    with open(session_path, "r") as f:
                        for line in f:
                            try:
                                record = json.loads(line)
                                scanned_domains.add(record["d"])
                                if record["r"]:
                                    previous_results.append(record["r"])
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

        initial_count = len(domains)
        domains = [d for d in domains if d not in scanned_domains]
        skipped_count = initial_count - len(domains)

        if skipped_count > 0:
            cprint(f"[dim]Skipping [cyan]{skipped_count}[/] already scanned domains[/]")
            results.extend(previous_results)
            for r in previous_results:
                writer.write(r)

        if not domains:
            cprint(f"[bold green]✓[/] All domains already scanned!")
        else:
            cprint(f"[dim]Scanning [cyan]{len(domains)}[/] domains with [cyan]{concurrency}[/] concurrent workers[/]\n")

            with open(session_path, "a") as f:
                new_results, timeout_domains, stats = asyncio.run(
                    scan_domains(subdotko, domains, max_concurrent=concurrency, sleep_time=args.sleep, session_file=f, output_writer=writer)
                )
                results.extend(new_results)

                if timeout_domains and not args.no_retry:
                    retry_results, still_timeout = asyncio.run(
                        retry_timeouts(subdotko, timeout_domains, session_file=f, output_writer=writer)
                    )
                    results.extend(retry_results)
                    if still_timeout > 0:
                        cprint(f"[yellow]{still_timeout}[/] domains still timed out after retry")

    writer.close()

    cprint(f"\n[bold green]✓[/] Scan complete! ({len(results)} results)")


if __name__ == "__main__":
    main()

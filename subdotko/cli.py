import sys, asyncio, argparse, httpx, json, csv
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from .utils import console, ensure_data_files, VERSION
from .resolver import ResolverManager
from .scanner import Subdotko

_silent = False

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
    http_status = result.get("http_status", "?")
    
    if status == "dead":
        return f"[bold magenta][DED][/] [cyan]{domain}[/] → [red]{cname}[/] [dim]({reason})[/]"
    elif status == "vuln":
        reason_text = f" [dim]({reason})[/]" if reason else ""
        return f"[bold red][VLN][/] [cyan]{domain}[/] → [yellow]{service}[/]{reason_text}"
    elif status == "info":
        status_color = "green" if http_status == 200 else "yellow" if isinstance(http_status, int) and http_status < 400 else "red"
        nested_str = f" [dim]{nested}[/]" if nested else ""
        return f"[[{status_color}]{http_status}[/]] [blue]{domain}[/] → {cname}{nested_str}"
    
    return None


def export_results(results, output_path):
    ext = output_path.lower().split('.')[-1] if '.' in output_path else 'txt'
    
    try:
        if ext == 'json':
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        elif ext == 'csv':
            if not results:
                return
            fieldnames = ["domain", "status", "cname", "nested_cnames", "service", "reason", "http_status"]
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for r in results:
                    row = r.copy()
                    row["nested_cnames"] = ",".join(row.get("nested_cnames", []))
                    writer.writerow(row)
        else:
            with open(output_path, 'w') as f:
                for r in results:
                    line = f"{r['domain']},{r['status']}"
                    if r.get('cname'):
                        line += f",{r['cname']}"
                    if r.get('service'):
                        line += f",{r['service']}"
                    if r.get('reason'):
                        line += f",{r['reason']}"
                    f.write(line + "\n")
        
        cprint(f"[dim]Results saved to [cyan]{output_path}[/][/]")
    except OSError as e:
        cprint(f"[red]Error:[/] Could not write to {output_path}: {e}")


async def scan_domains(subdotko, domains, max_concurrent=20, sleep_time=0.0):
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_semaphore(client, domain):
        async with semaphore:
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
            return await subdotko.scan(client, domain)
    
    limits = httpx.Limits(max_keepalive_connections=max_concurrent, max_connections=max_concurrent * 2)
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        limits=limits,
        timeout=httpx.Timeout(10.0, connect=5.0)
    ) as client:
        tasks = [scan_with_semaphore(client, domain) for domain in domains]
        
        if _silent:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    results.append(result)
        else:
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
                        display = format_result(result)
                        if display:
                            progress.console.print(display)
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
    global _silent
    
    parser = argparse.ArgumentParser(description="Subdotko - Subdomain fingerprinting tool")
    parser.add_argument("-d", "--domain", help="Domain to scan")
    parser.add_argument("-l", "--list", help="List of domains to scan")
    parser.add_argument("-o", "--output", help="Output file (.txt, .json, .csv)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent scans (default: 20)")
    parser.add_argument("-s", "--sleep", type=float, default=0.0, help="Sleep time between requests in seconds (default: 0)")
    parser.add_argument("-e", "--enumerate", action="store_true", help="Enumerate subdomains with subfinder first")
    parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    args = parser.parse_args()

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
    
    subdotko = Subdotko(resolver_manager=resolver_manager)
    cprint(f"[dim]Loaded [cyan]{len(subdotko.fingerprints['cnames'])}[/] CNAME + [cyan]{len(subdotko.fingerprints['ips'])}[/] IP fingerprints[/]")

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
    
    if len(domains) == 1:
        cprint(f"[dim]Scanning [cyan]{domains[0]}[/][/]\n")
        result = asyncio.run(scan_single(subdotko, domains[0]))
        if result:
            results.append(result)
            display = format_result(result)
            if display:
                cprint(display)
    else:
        cprint(f"[dim]Scanning [cyan]{len(domains)}[/] domains with [cyan]{args.threads}[/] concurrent connections[/]\n")
        results = asyncio.run(scan_domains(subdotko, domains, max_concurrent=args.threads, sleep_time=args.sleep))
    
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    elif args.output:
        export_results(results, args.output)
    
    cprint(f"\n[bold green]✓[/] Scan complete! ({len(results)} results)")

if __name__ == "__main__":
    main()

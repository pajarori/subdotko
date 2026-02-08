import sys, asyncio, argparse, httpx
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from .utils import console, ensure_data_files, VERSION
from .resolver import ResolverManager
from .scanner import Subdotko

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

    banner = f"""[bold cyan]
    ▌  ▌  ▗ ▌   
▛▘▌▌▛▌▛▌▛▌▜▘▙▘▛▌
▄▌▙▌▙▌▙▌▙▌▐▖▛▖▙▌ [/bold cyan][dim]v{VERSION}[/dim]
[white][dim]pajarori[/dim][/white]
    """
    console.print(banner)

    ensure_data_files()
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

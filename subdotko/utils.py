import os, json, shutil, random, hashlib
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

RESOLVER_CACHE_TTL_HOURS = 24
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
VERSION = "1.4.3"


def backoff_delay(attempt, base=0.1, cap=5.0):
    delay = min(base * (2 ** attempt), cap)
    return delay + random.uniform(0, delay * 0.5)


def get_package_dir():
    return Path(__file__).parent


def get_data_dir():
    data_dir = Path.home() / ".local" / "pajarori" / "subdotko"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_cache_dir():
    cache_dir = get_data_dir() / ".cache"
    cache_dir.mkdir(exist_ok=True)
    return cache_dir


def ensure_data_files():
    pkg_dir = get_package_dir()
    data_dir = get_data_dir()

    src_fingerprints = pkg_dir / "fingerprints"
    dst_fingerprints = data_dir / "fingerprints"
    dst_has_files = dst_fingerprints.exists() and any(dst_fingerprints.glob("*.yml"))
    if not dst_has_files and src_fingerprints.exists():
        if dst_fingerprints.exists():
            shutil.rmtree(dst_fingerprints)
        shutil.copytree(src_fingerprints, dst_fingerprints)

    dst_blacklist = data_dir / "blacklists.txt"
    if not dst_blacklist.exists():
        src_blacklist = pkg_dir / "blacklists.txt"
        if src_blacklist.exists():
            shutil.copy2(src_blacklist, dst_blacklist)


def get_session_dir():
    session_dir = get_data_dir() / "sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


def calculate_session_hash(domains):
    sorted_domains = sorted(domains)
    content = "\n".join(sorted_domains).encode('utf-8')
    return hashlib.sha256(content).hexdigest()[:32]


def clean_old_sessions(days=3):
    session_dir = get_session_dir()
    if not session_dir.exists():
        return

    cutoff = datetime.now() - timedelta(days=days)

    for session_file in session_dir.glob("*.jsonl"):
        try:
            mtime = datetime.fromtimestamp(session_file.stat().st_mtime)
            if mtime < cutoff:
                session_file.unlink()
        except OSError:
            pass

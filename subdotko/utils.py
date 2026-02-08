import os, json, shutil
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

RESOLVER_CACHE_TTL_HOURS = 24
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
VERSION = "1.1.0"

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

#!/usr/bin/env python3
"""
GODS Recon Intelligence Engine -- Common Utilities
"""
import subprocess
import shlex
import sys
import re
import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import os
from datetime import datetime
from config.settings import TOOL_CATEGORIES, RECON_VERSION

# Try to import rich for enhanced UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

class C:
    G = "\033[1;32m"
    R = "\033[1;31m"
    B = "\033[1;34m"
    Y = "\033[1;33m"
    CYAN = "\033[1;36m"
    M = "\033[1;35m"
    W = "\033[1;37m"
    D = "\033[2m"
    X = "\033[0m"

SEV = {
    "CRITICAL": (C.R, 4),
    "HIGH":     (C.M, 3),
    "MEDIUM":   (C.Y, 2),
    "LOW":      (C.CYAN, 1),
    "INFO":     (C.D, 0),
}

def banner():
    art = r"""   _____  ____  _____   _____
  / ____|/ __ \|  __ \ / ____|
 | |  __| |  | | |  | | (___
 | | |_ | |  | | |  | |\___ \
 | |__| | |__| | |__| |____) |
  \_____|\____/|_____/|_____/
"""
    if RICH_AVAILABLE:
        console.print(f"[bold yellow]{art}[/bold yellow]")
        console.print("       [cyan]G H O S T   O S I N T[/cyan]")
        console.print("       & D E T E C T I O N")
        console.print("          S Y S T E M")
        console.print()
        console.print(f"    [bold cyan][ Recon Intelligence Engine {RECON_VERSION} ][/bold cyan]")
        console.print(f"    [dim]Dev: Rabix$  |  Module: recon[/dim]")
        console.print()
    else:
        print(f"{C.Y}{art}{C.X}")
        print("       G H O S T   O S I N T")
        print("       & D E T E C T I O N")
        print("          S Y S T E M")
        print()
        print(f"    {C.CYAN}[ Recon Intelligence Engine {RECON_VERSION} ]{C.X}")
        print(f"    {C.D}Dev: Rabix$  |  Module: recon{C.X}")
        print()

def log(tag, msg, color=C.W):
    ts = datetime.now().strftime("%H:%M:%S")
    if RICH_AVAILABLE:
        color_map = {
            C.G: "green",
            C.R: "red",
            C.B: "blue",
            C.Y: "yellow",
            C.CYAN: "cyan",
            C.M: "magenta",
            C.W: "white",
            C.D: "dim",
        }
        rich_color = color_map.get(color, "white")
        console.print(f"[dim][{ts}][/dim] [{rich_color}]{tag}[/{rich_color}] {msg}")
    else:
        print(f"{C.D}[{ts}]{C.X} {color}[{tag}]{C.X} {msg}")

def run_cmd(cmd, timeout=120, shell=False):
    try:
        if not shell:
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell)
            return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "COMMAND_NOT_FOUND", -1
    except Exception as e:
        return "", str(e), -1

def tool_check(name):
    _, _, rc = run_cmd(f"which {name}")
    return rc == 0

def check_dependencies(tools_dict):
    """Check all tools and return status dict."""
    status = {}
    for name, cmd in tools_dict.items():
        status[name] = tool_check(cmd)
    return status

def print_dep_status(status, modules=None):
    """Print dependency status in a clean list."""
    print()
    print("Dependency Check")
    print()
    if modules:
        needed = set()
        for mod in modules:
            needed.update(TOOL_CATEGORIES.get(mod, []))
        for name, ok in sorted(status.items()):
            if name in needed:
                mark = f"{C.G}[OK]{C.X}" if ok else f"{C.R}[MISS]{C.X}"
                print(f"  {mark:12} {name}")
    else:
        for name, ok in sorted(status.items()):
            mark = f"{C.G}[OK]{C.X}" if ok else f"{C.R}[MISS]{C.X}"
            print(f"  {mark:12} {name}")
    print()

def print_tool_status(status):
    """Print tool status with optional rich formatting."""
    if RICH_AVAILABLE:
        table = Table(title="Available Tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Status")
        
        current_category = None
        for name, ok in sorted(status.items()):
            mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
            table.add_row(name, mark)
        
        console.print(table)
    else:
        for name, ok in sorted(status.items()):
            mark = f"{C.G}✓{C.X}" if ok else f"{C.R}✗{C.X}"
            print(f"  {mark} {name}")

def sev_color(sev):
    """Get color code for severity."""
    colors = {
        "CRITICAL": C.R,
        "HIGH": C.M,
        "MEDIUM": C.Y,
        "LOW": C.CYAN,
        "INFO": C.D,
    }
    return colors.get(sev.upper(), C.W)

def sev_rank(sev):
    """Get severity rank number."""
    ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return ranks.get(sev.upper(), 0)

def safe_filename(name):
    """Make a string safe for use as a filename."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)

def http_get(url, timeout=10, headers=None):
    """Fetch URL and return (content, error)."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode('utf-8', errors='ignore'), None
    except Exception as e:
        return None, str(e)

def is_port_open(host, port, timeout=3):
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def has_os_detect_privs():
    """Check if we have privileges for OS detection (requires root/capabilities)."""
    return os.geteuid() == 0


def validate_target(target):
    """Validate and normalize target (domain/IP). Returns (is_valid, normalized, error)."""
    if not target:
        return False, None, "Empty target"
    
    # Remove protocol prefix
    target = target.strip()
    if target.startswith(('http://', 'https://')):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Remove trailing slash
    target = target.rstrip('/')
    
    if not target:
        return False, None, "Invalid target"
    
    # Basic validation: check for valid chars
    import re
    # Allow domains, IPs, and CIDR (basic)
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(domain_pattern, target) or re.match(ip_pattern, target):
        return True, target, None
    
    return False, None, f"Invalid target format: {target}"

def has_os_detect_privs():
    """Check if we have privileges for OS detection (requires root/capabilities)."""
    return os.geteuid() == 0


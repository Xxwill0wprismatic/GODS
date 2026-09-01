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

class C:
    G = "\033[1;32m"
    R = "\033[1;31m"
    B = "\033[1;34m"
    Y = "\033[1;33m"
    C = "\033[1;36m"
    M = "\033[1;35m"
    W = "\033[1;37m"
    D = "\033[2m"
    X = "\033[0m"

SEV = {
    "CRITICAL": (C.R, 4),
    "HIGH":     (C.M, 3),
    "MEDIUM":   (C.Y, 2),
    "LOW":      (C.C, 1),
    "INFO":     (C.D, 0),
}

def banner():
    art = r"""   _____  ____  _____   _____
  / ____|/ __ \|  __ \ / ____|
 | |  __| |  | | |  | | (___
 | | |_ | |  | | |  | | \___ \
 | |__| | |__| | |__| |____) |
  \_____|\____/|_____/|_____/
"""
    print(f"{C.Y}{art}{C.X}")
    print("       G H O S T   O S I N T")
    print("       & D E T E C T I O N")
    print("          S Y S T E M")
    print()
    print(f"    {C.C}[ Recon Intelligence Engine {RECON_VERSION} ]{C.X}")
    print(f"    {C.D}Dev: Rabix$  |  Module: recon{C.X}")
    print()

def log(tag, msg, color=C.W):
    ts = datetime.now().strftime("%H:%M:%S")
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
    """Print expanded tool status by purpose."""
    from config.settings import TOOL_PURPOSES
    print()
    print("AVAILABLE TOOLS")
    print()
    for purpose, tools in TOOL_PURPOSES.items():
        relevant = [(t, status.get(t, False)) for t in tools if t in status]
        if not relevant:
            continue
        print(f"  {purpose}")
        for t, ok in relevant:
            mark = f"{C.G}✓{C.X}" if ok else f"{C.R}✗{C.X}"
            print(f"    {mark} {t}")
    print()

def validate_target(target):
    """Validate a hostname/IP or a full HTTP(S) URL."""
    raw = str(target or "").strip()
    if not raw:
        return False, None, "Target is empty"
    candidate = raw
    if "://" in candidate:
        try:
            parsed = urllib.parse.urlparse(candidate)
        except Exception:
            return False, None, "Invalid URL"
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False, None, "Invalid HTTP(S) URL"
        candidate = parsed.hostname
    else:
        candidate = candidate.split("/")[0].split(":")[0]

    try:
        socket.inet_aton(candidate)
        return True, candidate, "Valid IP address"
    except socket.error:
        pass
    if not re.match(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$", candidate):
        return False, None, "Invalid domain format"
    try:
        ip = socket.gethostbyname(candidate)
        return True, ip, f"Resolved to {ip}"
    except socket.gaierror:
        return True, None, "Valid domain format; DNS resolution unavailable"

def http_get(url, headers=None, timeout=15, verify_ssl=True, allow_redirects=True):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": f"GODS-Recon/{RECON_VERSION}"})
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    class _RedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if allow_redirects:
                return super().redirect_request(req, fp, code, msg, headers, newurl)
            return None

    opener = urllib.request.build_opener(
        _RedirectHandler(),
        urllib.request.HTTPSHandler(context=ctx)
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore"), dict(resp.headers), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="ignore"), dict(e.headers), e.code
    except Exception as e:
        return str(e), {}, 0

def is_port_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def sev_color(level):
    return SEV.get(level.upper(), (C.W, 0))[0]

def sev_rank(level):
    return SEV.get(level.upper(), (C.W, 0))[1]

def safe_filename(value):
    """Return a filesystem-safe filename component."""
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))
    return value.strip("._")[:120] or "target"

def has_os_detect_privs():
    """Check if current process can perform OS detection (root on Unix)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True

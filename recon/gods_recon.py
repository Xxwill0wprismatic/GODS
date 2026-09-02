#!/usr/bin/env python3
"""
GODS Recon Intelligence Engine v8.51E
Unified CLI for GODS reconnaissance.

Usage:
  python3 gods_recon.py              # Interactive menu
  python3 gods_recon.py recon -t <target>     # Direct recon
  python3 gods_recon.py reset                 # Reset state
  python3 gods_recon.py status                # Check dependencies
  python3 gods_recon.py info                  # Show info
"""
import argparse
import sys
import os
import glob
import shutil
import json
import shlex
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.helpers import (
    C, log, banner, tool_check, check_dependencies,
    print_dep_status, print_tool_status, validate_target, has_os_detect_privs, run_cmd
)
from utils.logger import ReconLogger
from engine.collector import Collector
from engine.parser import Parser
from engine.correlator import Correlator
from engine.reporter import Reporter
from config.settings import TOOLS, TOOL_CATEGORIES, REQUIRED_TOOLS, OPTIONAL_TOOLS, RECON_VERSION
from engine.toolkit import TOOL_LIST, TOOL_INDEX, availability, print_tool_catalog, run_tool, _ask_common

# ── Pre-configured option sets ──
QUICK_MODULES = ["portscan", "webscan", "dns", "headers", "techdetect", "tls"]
QUICK_OPTS = {
    "portscan": {"mode": "common", "timing": "-T4", "udp": False, "service_detect": True, "os_detect": False},
    "webscan": {"preset": "minimal"},
    "dns": {"record_types": ["A", "MX", "NS", "TXT"], "wildcard": True, "zone_xfer": False},
    "headers": {"protocol": "https", "follow_redirects": True},
    "techdetect": {"aggressiveness": "standard", "check_both": True},
    "tls": {"port": 443, "depth": "standard", "check_redirect": True},
}

FULL_MODULES = ["portscan", "webscan", "dns", "tls", "headers", "whois", "subdomain", "techdetect", "wafdetect", "certtransparency", "metasploit"]
FULL_OPTS = {
    "portscan": {"mode": "full", "timing": "-T4", "udp": True, "service_detect": True, "os_detect": True},
    "webscan": {"preset": "aggressive", "dns_brute": True},
    "dns": {"record_types": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"], "wildcard": True, "zone_xfer": True},
    "tls": {"port": 443, "depth": "deep", "check_redirect": True},
    "headers": {"protocol": "both", "follow_redirects": True},
    "whois": {"confirmed": True},
    "subdomain": {"sources": ["crt.sh", "subfinder", "amass"]},
    "techdetect": {"aggressiveness": "aggressive", "check_both": True},
    "wafdetect": {"method": "aggressive"},
    "certtransparency": {"source": "both", "include_expired": False},
    "metasploit": {"modules": ["http_title", "smb_version", "ftp_version"], "timeout": 60},
}

ALL_MODULES = ["portscan", "webscan", "dns", "tls", "headers", "whois", "subdomain", "techdetect", "wafdetect", "certtransparency"]

# ── Target validation ──
def do_target_validation(target):
    print()
    print(f"Target: {target}")
    print()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.hostname or ""
    ok, ip, msg = validate_target(target)
    if ok:
        print(f"  {C.G}[OK]{C.X}   Valid target")
        if ip and ip != target:
            print(f"  {C.G}[OK]{C.X}   Resolved to {ip}")
        print(f"  {C.G}[OK]{C.X}   Scope accepted")
        print()
        print(f"{C.Y}[!] Only scan systems you are authorized to test.{C.X}")
        print()
        return target
    else:
        print(f"  {C.R}[FAIL]{C.X} {msg}")
        print()
        return False

# ── Dependency manager ──
def cmd_status():
    print()
    print("GODS Status")
    print()
    status = check_dependencies(TOOLS)
    print_tool_status(status)
    missing_req = [name for name in REQUIRED_TOOLS if not status.get(name)]
    missing_opt = [name for name in OPTIONAL_TOOLS if not status.get(name)]
    if missing_req:
        print(f"{C.R}[!] Missing REQUIRED tools: {', '.join(missing_req)}{C.X}")
    if missing_opt:
        print(f"{C.Y}[!] Missing optional tools: {', '.join(missing_opt)}{C.X}")
    if not missing_req and not missing_opt:
        print(f"{C.G}[+] All dependencies installed.{C.X}")
    print()
    return 0

def cmd_install():
    print()
    print("GODS Install")
    print()
    status = check_dependencies(TOOLS)
    missing = [name for name, ok in status.items() if not ok]
    if not missing:
        print(f"{C.G}[+] All dependencies already installed.{C.X}")
        return 0

    print(f"Missing tools: {', '.join(missing)}")
    print()

    pkg = None
    for cmd, name in [("apt-get", "apt"), ("yum", "yum"), ("dnf", "dnf"), ("pacman", "pacman"), ("pkg", "pkg")]:
        if tool_check(cmd):
            pkg = name
            break

    if not pkg:
        print(f"{C.R}[!] No supported package manager found.{C.X}")
        print(f"{C.Y}[!] Install these manually: {', '.join(missing)}{C.X}")
        return 1

    print(f"Detected package manager: {pkg}")
    print()

    confirm = input("[?] Install missing tools? (yes/no): ").strip().lower()
    if confirm != "yes":
        print(f"{C.Y}[*] Installation cancelled.{C.X}")
        return 0

    pkg_map = {
        "nmap": "nmap", "gobuster": "gobuster", "dig": "dnsutils",
        "host": "bind9-host", "openssl": "openssl", "curl": "curl",
        "whois": "whois", "subfinder": "subfinder", "amass": "amass",
        "whatweb": "whatweb", "wafw00f": "wafw00f", "nikto": "nikto",
        "sslscan": "sslscan", "testssl": "testssl.sh",
        "ffuf": "ffuf", "wfuzz": "wfuzz", "gau": "gau",
        "waybackurls": "waybackurls", "unfurl": "unfurl",
        "nuclei": "nuclei", "zap": "zaproxy",
    }

    for tool in missing:
        pkg_name = pkg_map.get(tool, tool)
        print(f"Installing {tool} ({pkg_name})...")
        if pkg == "apt":
            run_cmd(f"apt-get install -y {pkg_name}", shell=True)
        elif pkg == "yum":
            run_cmd(f"yum install -y {pkg_name}", shell=True)
        elif pkg == "dnf":
            run_cmd(f"dnf install -y {pkg_name}", shell=True)
        elif pkg == "pacman":
            run_cmd(f"pacman -S --noconfirm {pkg_name}", shell=True)
        elif pkg == "pkg":
            run_cmd(f"pkg install -y {pkg_name}", shell=True)

    print()
    print(f"{C.G}[+] Install complete. Run 'GODS status' to verify.{C.X}")
    return 0

# ── Reset ──
def cmd_reset():
    print()
    print("GODS Reset")
    print()
    print("This will delete generated reports, logs, and cached data.")
    print(f"{C.R}It will NOT delete source code, modules, or configuration.{C.X}")
    print()
    confirm = input("[?] Type 'yes' to proceed: ").strip().lower()
    if confirm != "yes":
        print(f"{C.Y}[*] Reset cancelled.{C.X}")
        return 0

    base_dir = os.path.dirname(os.path.abspath(__file__))
    deleted = []
    patterns = [
        ("reports/*.json", "report JSON"),
        ("reports/*.txt",  "report TXT"),
        ("reports/*.html", "report HTML"),
    ]
    for pattern, desc in patterns:
        for m in glob.glob(os.path.join(base_dir, pattern)):
            try:
                os.remove(m)
                deleted.append(f"  {desc}: {os.path.basename(m)}")
            except Exception:
                pass
    tmp = "/tmp/gods_wordlists"
    if os.path.exists(tmp):
        try:
            shutil.rmtree(tmp)
            deleted.append("  temp wordlist cache")
        except Exception:
            pass
    for root, dirs, files in os.walk(base_dir):
        for d in list(dirs):
            if d == "__pycache__":
                p = os.path.join(root, d)
                try:
                    shutil.rmtree(p)
                    deleted.append(f"  pycache: {os.path.relpath(p, base_dir)}")
                except Exception:
                    pass

    print()
    if deleted:
        print(f"{C.G}[+] Deleted:{C.X}")
        for d in deleted:
            print(d)
    else:
        print(f"{C.G}[+] Nothing to delete.{C.X}")
    print(f"{C.G}[+] Reset complete.{C.X}")
    print()
    return 0

# ── 30-tool interactive runner ──
def tool_menu(target=None):
    while True:
        print()
        print("GODS Recon Tools")
        print()
        print("[1] List 30 tools")
        print("[2] Run one tool")
        print("[3] Run several tools")
        print("[4] Run all installed tools")
        print("[0] Back")
        print()
        choice = input("[?] Select: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            print_tool_catalog()
            continue
        if choice not in {"2", "3", "4"}:
            print(f"{C.Y}[!] Invalid selection.{C.X}")
            continue
        if not target:
            target = input("[?] Target: ").strip()
        if not target:
            print(f"{C.R}[!] No target specified.{C.X}")
            target = None
            continue

        status = availability()
        if choice == "4":
            selected = [spec for spec in TOOL_LIST if status[spec.name]]
            # One wordlist prompt is enough for all discovery tools.
            wordlist = input("[?] Default wordlist for discovery tools (Enter to skip them): ").strip()
            common = {"wordlist": wordlist, "threads": 10, "extensions": "php,html,txt", "ports": "80,443", "custom_ports": "80,443", "top_n": 100, "service": True, "udp": False, "timing": "-T3", "rate": 10, "severity": "low,medium,high,critical", "depth": 2, "port": 443, "record": "A"}
        else:
            raw = input("[?] Tool number(s), comma-separated: ").strip()
            selected = []
            for item in raw.split(","):
                if item.strip().isdigit():
                    idx = int(item.strip()) - 1
                    if 0 <= idx < len(TOOL_LIST):
                        selected.append(TOOL_LIST[idx])
            common = None

        results = []
        for spec in selected:
            if not status.get(spec.name, False):
                print(f"{C.R}[MISS]{C.X} {spec.name} is not installed")
                results.append({"tool": spec.name, "status": "unavailable", "stdout": "", "stderr": "tool not installed", "returncode": -1, "command": ""})
                continue
            print()
            print(f"Running {spec.name} - {spec.description}")
            if choice == "4":
                options = dict(common or {})
                if spec.name in {"gobuster","ffuf","feroxbuster","dirsearch","wfuzz"} and not options.get("wordlist"):
                    print(f"{C.Y}[SKIP]{C.X} {spec.name}: no default wordlist supplied")
                    results.append({"tool": spec.name, "status": "skipped", "stdout": "", "stderr": "no wordlist", "returncode": -1, "command": ""})
                    continue
            else:
                try:
                    options = _ask_common(spec)
                except (ValueError, KeyboardInterrupt) as e:
                    print(f"{C.Y}[SKIP]{C.X} {spec.name}: {e}{C.X}")
                    continue
            result = run_tool(spec, target, options)
            results.append(result)
            color = C.G if result["status"] == "ok" else C.R
            print(f"{color}[{result['status'].upper()}]{C.X} {spec.name}")
            if result.get("stdout"):
                print(result["stdout"][:4000].rstrip())
            if result.get("stderr") and result["status"] not in {"ok"}:
                print(result["stderr"][:1000].rstrip())
        if results:
            save_tool_results(results, target)
        if choice in {"2","3"}:
            target = None
    return 0

def save_tool_results(results, target):
    base = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(base, "reports")
    os.makedirs(out, exist_ok=True)
    from datetime import datetime
    import html as html_module
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = os.path.join(out, f"{target}_{stamp}_tools")
    ok = [r for r in results if r.get("status") == "ok"]
    skipped = [r for r in results if r.get("status") in {"skipped", "unavailable"}]
    failed = [r for r in results if r.get("status") in {"failed", "timeout", "error"}]

    data = {
        "target": target,
        "version": RECON_VERSION,
        "generated": datetime.now().isoformat(),
        "tool_count": len(results),
        "successful": len(ok),
        "skipped_or_unavailable": len(skipped),
        "failed": len(failed),
        "results": results,
    }
    json_path = stem + ".json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    lines = [
        "GODS RECON TOOL REPORT",
        "-----------------------",
        f"Target  : {target}",
        f"Version : {RECON_VERSION}",
        f"Date    : {data['generated']}",
        f"Tools   : {len(results)}",
        f"Success : {len(ok)}",
        f"Skipped : {len(skipped)}",
        f"Failed  : {len(failed)}",
        "",
        "RESULTS",
    ]
    for r in results:
        lines += [
            f"[{r.get('status','unknown').upper()}] {r.get('tool','unknown')}",
            f"Command: {r.get('command','')}",
            r.get("stdout", "")[:8000].rstrip(),
        ]
        if r.get("stderr"):
            lines.append("Stderr: " + r["stderr"][:2000].rstrip())
        lines.append("")
    txt_path = stem + ".txt"
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    rows=[]
    for r in results:
        rows.append(
            "<tr>"
            f"<td>{html_module.escape(r.get('status','unknown'))}</td>"
            f"<td>{html_module.escape(r.get('tool',''))}</td>"
            f"<td><pre>{html_module.escape(r.get('stdout','')[:8000])}</pre></td>"
            f"<td><pre>{html_module.escape(r.get('stderr','')[:2000])}</pre></td>"
            "</tr>"
        )
    html_path = stem + ".html"
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>GODS Tool Report</title>
<style>body{{font-family:monospace;background:#111;color:#eee;margin:24px}} table{{width:100%;border-collapse:collapse}} td,th{{padding:8px;border-bottom:1px solid #444;text-align:left;vertical-align:top}} pre{{white-space:pre-wrap;max-width:700px}}</style></head><body>
<h1>GODS Recon Tool Report</h1><p>Target: {html_module.escape(target)}<br>Version: {RECON_VERSION}<br>Tools: {len(results)} | Success: {len(ok)} | Skipped: {len(skipped)} | Failed: {len(failed)}</p>
<table><tr><th>Status</th><th>Tool</th><th>Output</th><th>Error</th></tr>{''.join(rows)}</table></body></html>"""
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"{C.G}[+] TXT report:  {txt_path}{C.X}")
    print(f"{C.G}[+] JSON report: {json_path}{C.X}")
    print(f"{C.G}[+] HTML report: {html_path}{C.X}")
    return {"txt": txt_path, "json": json_path, "html": html_path}

# ── Info ──
def cmd_info():
    print()
    print("GODS Recon Intelligence Engine")
    print(f"Version: {RECON_VERSION}")
    print("Developer: Rabix$")
    print()
    print("A reconnaissance framework for authorized security testing.")
    print("Modules: portscan, webscan, dns, tls, headers, whois,")
    print("         subdomain, techdetect, wafdetect, certtransparency")
    print()
    return 0

# ── Config ──
def cmd_config():
    print()
    print("GODS Config")
    print()
    print("Current settings:")
    print(f"  Reports dir: reports/")
    print(f"  Wordlists:   /usr/share/wordlists/ (system)")
    print(f"  Timeout:     60-900s depending on module")
    print()
    print("Edit config/settings.py to change defaults.")
    print()
    return 0

# ── Update ──
def cmd_update():
    print()
    print("GODS Update")
    print()
    print("Check the project repository for the latest version.")
    print("Manual update: git pull or re-download the release.")
    print()
    return 0

# ── View Reports ──
def view_reports():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(base_dir, "reports")
    files = sorted(glob.glob(os.path.join(reports_dir, "*")))
    if not files:
        print()
        print("No reports found.")
        print()
        return
    print()
    print("Available Reports")
    print()
    for i, f in enumerate(files, 1):
        size = os.path.getsize(f)
        size_str = f"{size/1024:.1f} KB" if size > 1024 else f"{size} B"
        print(f"  [{i}] {os.path.basename(f):50} {size_str}")
    print()
    choice = input("[?] Enter number to view (or Enter to skip): ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            with open(files[idx], "r", encoding="utf-8") as f:
                content = f.read()
                print()
                print(content[:3000])
                if len(content) > 3000:
                    print(f"\n... ({len(content)} chars total)")
    print()

# ── Recon engine ──
def run_recon(target, modules, opts_dict, outdir="reports", no_report=False):
    target = do_target_validation(target)
    if not target:
        return 1

    logger = ReconLogger(target, outdir=outdir)
    status = check_dependencies(TOOLS)
    print_dep_status(status, modules)

    collector = Collector(
        target, logger,
        modules=modules,
        portscan_opts=opts_dict.get("portscan"),
        webscan_opts=opts_dict.get("webscan"),
        dns_opts=opts_dict.get("dns"),
        tls_opts=opts_dict.get("tls"),
        headers_opts=opts_dict.get("headers"),
        whois_opts=opts_dict.get("whois"),
        subdomain_opts=opts_dict.get("subdomain"),
        techdetect_opts=opts_dict.get("techdetect"),
        wafdetect_opts=opts_dict.get("wafdetect"),
        certtransparency_opts=opts_dict.get("certtransparency"),
    )
    scan_results = collector.run()

    parser = Parser(scan_results, logger)
    parsed = parser.run()

    correlator = Correlator(logger.findings, logger)
    correlated = correlator.run()

    raw_path = logger.save_raw()
    findings_path = logger.save_findings()
    log("ENGINE", f"Raw data saved: {raw_path}", C.G)
    log("ENGINE", f"Findings saved: {findings_path}", C.G)

    if not no_report:
        # Extract HTML source from webscan results if available
        html_source = None
        if "webscan" in scan_results:
            webscan_result = scan_results.get("webscan", {})
            if isinstance(webscan_result, dict):
                html_source = webscan_result.get("html_source", "")
        
        reporter = Reporter(target, correlated, [raw_path, findings_path], outdir=outdir,
                            tools_used=logger.tools_used, tools_skipped=logger.tools_skipped,
                            session=logger.session_id, module_status=logger.module_status,
                            modules_run=logger.modules_run, html_source=html_source)
        reports = reporter.run()
        print()
        log("DONE", "Recon complete.", C.G)
        log("DONE", f"Reports directory: {logger.outdir}", C.CYAN)
        log("DONE", f"TXT:  {reports['txt']}", C.CYAN)
        log("DONE", f"JSON: {reports['json']}", C.CYAN)
        log("DONE", f"HTML: {reports['html']}", C.CYAN)
        if reports.get('html_source'):
            log("DONE", f"SOURCE: {reports['html_source']}", C.CYAN)
    else:
        print()
        log("DONE", "Recon complete (reports skipped).", C.G)
    return 0

# ── Recon submenu ──
def recon_menu():
    while True:
        print()
        print("GODS Recon")
        print()
        print("[1] Quick Recon")
        print("[2] Custom Recon")
        print("[3] Full Recon")
        print("[4] Select Modules")
        print("[5] Tools (30)")
        print("[6] View Reports")
        print("[0] Back")
        print()
        choice = input("[?] Select: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            target = input("[?] Target: ").strip()
            if target:
                run_recon(target, QUICK_MODULES, QUICK_OPTS)
        elif choice == "2":
            target = input("[?] Target: ").strip()
            if target:
                run_recon(target, ALL_MODULES, {})
        elif choice == "3":
            target = input("[?] Target: ").strip()
            if target:
                run_recon(target, FULL_MODULES, FULL_OPTS)
        elif choice == "4":
            print()
            print("Select modules (comma-separated numbers):")
            for i, mod in enumerate(ALL_MODULES, 1):
                print(f"  [{i}] {mod}")
            print("  [0] All modules")
            print()
            sel = input("[?] Modules: ").strip()
            if sel == "0":
                selected = ALL_MODULES[:]
            else:
                selected = []
                for s in sel.split(","):
                    s = s.strip()
                    if s.isdigit():
                        idx = int(s) - 1
                        if 0 <= idx < len(ALL_MODULES):
                            selected.append(ALL_MODULES[idx])
            if not selected:
                print("No modules selected.")
                continue
            custom = input("[?] Custom options for each module? (y/N): ").strip().lower() == "y"
            target = input("[?] Target: ").strip()
            if target:
                if custom:
                    run_recon(target, selected, {})
                else:
                    opts = {k: v for k, v in QUICK_OPTS.items() if k in selected}
                    run_recon(target, selected, opts)
        elif choice == "5":
            tool_menu()
        elif choice == "6":
            view_reports()
        else:
            print(f"{C.Y}[!] Invalid selection.{C.X}")

# ── Main menu ──
def main_menu():
    while True:
        print()
        print("GODS")
        print()
        print("[1] Recon")
        print("[2] Install")
        print("[3] Update")
        print("[4] Status")
        print("[5] Info")
        print("[6] Config")
        print("[7] Reset")
        print("[0] Exit")
        print()
        choice = input("[?] Select: ").strip()

        if choice == "0":
            print()
            print("Exiting.")
            break
        elif choice == "1":
            recon_menu()
        elif choice == "2":
            cmd_install()
        elif choice == "3":
            cmd_update()
        elif choice == "4":
            cmd_status()
        elif choice == "5":
            cmd_info()
        elif choice == "6":
            cmd_config()
        elif choice == "7":
            cmd_reset()
        else:
            print(f"{C.Y}[!] Invalid selection.{C.X}")

# ── CLI entry point ──
def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="GODS Recon Intelligence Engine",
        add_help=False
    )
    parser.add_argument("command", nargs="?", default=None,
                        choices=["recon", "tools", "reset", "status", "info", "install", "update", "config", "help", "search"],
                        help="Command to run")
    parser.add_argument("--target", "-t", default=None, help="Target domain or IP")
    parser.add_argument("--modules", "-m", default="all", help="Comma-separated modules")
    parser.add_argument("--outdir", "-o", default="reports", help="Output directory")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick recon mode")
    parser.add_argument("--full", "-f", action="store_true", help="Full recon mode")
    parser.add_argument("--help", "-h", action="store_true", help="Show help")
    # Search options
    parser.add_argument("--search", "-s", default=None, help="Search Metasploit payloads")
    parser.add_argument("--os", default=None, help="Filter by OS (linux, windows, macos, php, python, etc.)")
    parser.add_argument("--arch", default=None, help="Filter by architecture (x64, x86, arm)")
    parser.add_argument("--type", default=None, help="Filter by type (meterpreter, shell, exec)")

    return parser


def cli_help():
    print(f"""
GODS Recon Intelligence Engine {RECON_VERSION}

Usage:
  python3 gods_recon.py              # Mode selector
  python3 gods_recon.py <command>    # Direct CLI mode

Commands:
  recon    Run reconnaissance scan
  tools    Open the 30-tool runner
  reset    Reset GODS state
  status   Check tool dependencies
  info     Show tool info
  install  Install missing dependencies
  update   Check for updates
  config   Show configuration
  search   Search Metasploit payloads

Options:
  -t, --target <host>     Target domain or IP
  -m, --modules <list>    Comma-separated modules
  -o, --outdir <path>     Output directory (default: reports)
  -q, --quick             Quick recon mode
  -f, --full              Full recon mode
  --no-report             Skip report generation
  -h, --help              Show this help

Search Options:
  -s, --search <query>   Search Metasploit payloads
  --os <os>               Filter by OS (linux, windows, macos, php, python, android)
  --arch <arch>           Filter by architecture (x64, x86, arm)
  --type <type>           Filter by type (meterpreter, shell, exec)

Examples:
  python3 gods_recon.py recon -t example.com -q
  python3 gods_recon.py recon -t example.com -f
  python3 gods_recon.py recon -t example.com -m portscan,dns,headers
  python3 gods_recon.py tools
  python3 gods_recon.py status
  python3 gods_recon.py search -s "reverse_tcp"
  python3 gods_recon.py search -s "meterpreter" --os linux
  python3 gods_recon.py search --os windows --type shell
  python3 gods_recon.py reset
""")


def cli_repl():
    """Plain terminal CLI mode. The normal command syntax remains available."""
    print()
    print(f"GODS Recon CLI {RECON_VERSION}")
    print("Type 'help' for commands or 'exit' to return.")
    while True:
        try:
            line = input("gods-recon> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line.lower() in {"exit", "quit", "back", "0"}:
            return 0
        if line.lower() in {"help", "--help", "-h"}:
            cli_help()
            continue
        try:
            argv = shlex.split(line)
        except ValueError as e:
            print(f"{C.R}[!] Invalid command: {e}{C.X}")
            continue
        try:
            rc = execute_cli(argv)
        except SystemExit:
            rc = 0
        if rc is not None and rc != 0:
            print(f"{C.R}[!] Command exited with status {rc}.{C.X}")


def execute_cli(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.help:
        cli_help()
        return 0

    if args.command == "tools":
        return tool_menu(args.target)

    if args.command == "recon" and not args.target and not args.quick and not args.full and args.modules == "all":
        recon_menu()
        return 0

    if args.command == "recon" or args.target:
        target = args.target
        if not target:
            target = input("[?] Target: ").strip()
        if not target:
            print(f"{C.R}[!] No target specified.{C.X}")
            return 1

        if args.full:
            return run_recon(target, FULL_MODULES, FULL_OPTS, outdir=args.outdir, no_report=args.no_report)
        elif args.quick:
            return run_recon(target, QUICK_MODULES, QUICK_OPTS, outdir=args.outdir, no_report=args.no_report)
        elif args.modules and args.modules != "all":
            mods = [m.strip() for m in args.modules.split(",") if m.strip()]
            invalid = [m for m in mods if m not in ALL_MODULES]
            if invalid:
                print(f"{C.R}[!] Unknown module(s): {', '.join(invalid)}{C.X}")
                return 2
            return run_recon(target, mods, {}, outdir=args.outdir, no_report=args.no_report)
        else:
            return run_recon(target, ALL_MODULES, {}, outdir=args.outdir, no_report=args.no_report)

    if args.command == "reset":
        return cmd_reset()
    if args.command == "status":
        return cmd_status()
    if args.command == "info":
        return cmd_info()
    if args.command == "install":
        return cmd_install()
    if args.command == "update":
        return cmd_update()
    if args.command == "config":
        return cmd_config()
    if args.command == "help":
        cli_help()
        return 0

    if args.command == "search":
        from engine.toolkit import print_payload_search, print_payloads_by_os
        if args.search or args.os or args.arch or args.type:
            print_payload_search(args.search or "", args.os, args.arch, args.type)
        else:
            print_payloads_by_os()
        return 0

    return 0

def main():
    # Direct CLI arguments keep the old behavior; no arguments show the mode selector.
    if len(sys.argv) > 1:
        return execute_cli(sys.argv[1:])

    banner()
    print("Choose how to use GODS Recon")
    print()
    print("[1] Interactive UI")
    print("[2] CLI")
    print("[0] Exit")
    print()
    while True:
        choice = input("[?] Select: ").strip()
        if choice == "1":
            return recon_menu()
        if choice == "2":
            return cli_repl()
        if choice == "0":
            return 0
        print(f"{C.Y}[!] Invalid selection.{C.X}")

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] Interrupted{C.X}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.R}[!] Error: {e}{C.X}")
        sys.exit(1)

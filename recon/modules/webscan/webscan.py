#!/usr/bin/env python3
"""
GODS Module: webscan
Tools: gobuster dir, gobuster dns, python fallback
Fetches and saves actual HTML source code of target website
"""
import os
import re
from utils.helpers import run_cmd, tool_check, http_get, C, log
from config.settings import TOOLS, TIMEOUTS, WORDLISTS, WEBSCAN_PRESETS

class WebScan:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}
        self.findings_list = []
        self.html_source = ""  # Store actual HTML source code

    def _prompt_options(self):
        print()
        print(f"{C.B}[ Web Path Scan Options ]{C.X}")
        print(f"{C.D}Choose scan intensity:{C.X}")
        print(f"  {C.G}1{C.X} Common dirs/files    (standard wordlist)")
        print(f"  {C.G}2{C.X} Aggressive           (with extensions, fast)")
        print(f"  {C.G}3{C.X} Minimal              (slow, quiet)")
        print(f"  {C.G}4{C.X} Custom wordlist      (you provide path)")
        print()
        choice = input(f"{C.Y}[?] Select intensity (1-4, default=1): {C.X}").strip() or "1"

        preset = "common"
        if choice == "2": preset = "aggressive"
        elif choice == "3": preset = "minimal"
        elif choice == "4": preset = "custom"

        wordlist = None
        if preset == "custom":
            wl = input(f"{C.Y}[?] Enter wordlist path: {C.X}").strip()
            if os.path.isfile(wl):
                wordlist = wl
            else:
                log("webscan", "Wordlist not found, using default", C.R)
                preset = "common"

        ext = ""
        if preset == "aggressive":
            ext = "php,html,txt,bak,zip,sql"
        elif preset in ("common", "minimal"):
            add_ext = input(f"{C.Y}[?] Add file extensions? (e.g. php,html,txt or n): {C.X}").strip().lower()
            if add_ext and add_ext != "n":
                ext = add_ext

        threads = WEBSCAN_PRESETS[preset]["threads"]
        t_in = input(f"{C.Y}[?] Threads (default={threads}): {C.X}").strip()
        if t_in:
            try:
                t = int(t_in)
                if t < 1 or t > 200:
                    log("webscan", "Threads must be 1-200, using default", C.Y)
                else:
                    threads = t
            except ValueError:
                log("webscan", "Invalid thread count, using default", C.Y)

        dns_brute = input(f"{C.Y}[?] Also run DNS subdomain brute? (y/N): {C.X}").strip().lower() == "y"

        self.options = {
            "preset": preset,
            "wordlist": wordlist,
            "extensions": ext,
            "threads": threads,
            "dns_brute": dns_brute,
        }
        print()

    def run(self):
        if not self.options or not self.options.get("preset"):
            self._prompt_options()

        preset = self.options.get("preset", "common")
        wordlist = self.options.get("wordlist") or WEBSCAN_PRESETS[preset]["wordlist"]
        ext = self.options.get("extensions", WEBSCAN_PRESETS[preset]["extensions"])
        threads = self.options.get("threads", WEBSCAN_PRESETS[preset]["threads"])
        dns_brute = self.options.get("dns_brute", False)

        log("webscan", f"Starting web path scan on {self.target} [{preset}]", C.B)
        results = {"dirs": [], "files": [], "subdomains": [], "html_source": None}

        # First, fetch the actual HTML source code of the website
        log("webscan", "=== Fetching HTML Source Code ===", C.B)
        self.fetch_html_source()
        results["html_source"] = self.html_source

        if not os.path.exists(wordlist):
            log("webscan", f"Wordlist not found at {wordlist}", C.R)
            self.logger.finding("webscan", "Wordlist missing", f"Path not found: {wordlist}", "INFO",
                                "", "Provide a valid wordlist or install system wordlists.")
            wordlist = None

        if tool_check(TOOLS["gobuster"]) and wordlist:
            log("webscan", f"Running gobuster dir -w {wordlist} -t {threads}", C.Y)
            url = f"http://{self.target}" if not self.target.startswith("http") else self.target
            cmd = [TOOLS["gobuster"], "dir", "-u", url, "-w", wordlist, "-t", str(threads), "-q"]
            if ext:
                cmd.extend(["-x", ext])
            stdout, stderr, rc = run_cmd(cmd, timeout=TIMEOUTS["gobuster"])
            self.logger.raw("webscan", "gobuster-dir", stdout, stderr, rc)
            dirs, files = self._parse_gobuster(stdout)
            results["dirs"] = dirs
            results["files"] = files
            self.logger.tools_used.append("gobuster")
        else:
            if not tool_check(TOOLS["gobuster"]):
                log("webscan", "gobuster not found, falling back to python dir brute", C.Y)
                self.logger.tools_skipped.append("gobuster (not installed)")
            results["dirs"], results["files"] = self._fallback_dir_brute()

        if dns_brute and tool_check(TOOLS["gobuster"]):
            log("webscan", "Running gobuster dns", C.Y)
            dns_wl = WORDLISTS.get("gobuster_dns", wordlist)
            if dns_wl and os.path.exists(dns_wl):
                stdout2, stderr2, rc2 = run_cmd(
                    [TOOLS["gobuster"], "dns", "-d", self.target, "-w", dns_wl, "-t", str(threads), "-q"],
                    timeout=TIMEOUTS["gobuster"]
                )
                self.logger.raw("webscan", "gobuster-dns", stdout2, stderr2, rc2)
                results["subdomains"] = self._parse_gobuster_dns(stdout2)
            else:
                log("webscan", "DNS wordlist not available, skipping DNS brute", C.Y)

        for code, size, path in results["dirs"]:
            sev = "INFO"
            if any(x in path.lower() for x in ["admin", "panel", "dashboard", "manage", "wp-admin", "phpmyadmin"]):
                sev = "HIGH"
            elif any(x in path.lower() for x in ["backup", ".bak", ".old", ".zip", ".sql", ".tar.gz"]):
                sev = "HIGH"
            elif any(x in path.lower() for x in [".git", ".env", "config", "settings"]):
                sev = "CRITICAL"
            elif code == 200 and ("index of" in path.lower() or "directory listing" in path.lower()):
                sev = "HIGH"
            self.logger.finding(
                "webscan", f"Dir {path} [{code}]",
                f"Size: {size}", sev,
                f"gobuster: {code} {size} {path}",
                "Restrict access or remove exposed directories."
            )

        for code, size, path in results["files"]:
            sev = "INFO"
            if any(ext in path.lower() for ext in [".sql", ".bak", ".zip", ".tar", ".dump"]):
                sev = "HIGH"
            self.logger.finding("webscan", f"File {path} [{code}]", f"Size: {size}", sev)

        for sub in results["subdomains"]:
            self.logger.finding("webscan", f"Subdomain: {sub}", "Discovered via DNS brute", "INFO")

        # Set module status
        if self.html_source:
            self.logger.set_module_status("webscan", "SUCCESS", f"Fetched {len(self.html_source)} bytes of HTML source")
        elif results["dirs"] or results["files"]:
            self.logger.set_module_status("webscan", "SUCCESS", f"Found {len(results['dirs'])} dirs, {len(results['files'])} files")
        else:
            self.logger.set_module_status("webscan", "PARTIAL", "No directories or files found")

        log("webscan", f"Done. Dirs:{len(results['dirs'])} Files:{len(results['files'])} Subs:{len(results['subdomains'])}", C.G)
        return results

    def _parse_gobuster(self, stdout):
        dirs, files = [], []
        for line in stdout.splitlines():
            m = re.search(r"(/[^\s]+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
            if m:
                path, code, size = m.group(1), int(m.group(2)), m.group(3)
                if path.endswith("/"):
                    dirs.append((code, size, path))
                else:
                    files.append((code, size, path))
        return dirs, files

    def _parse_gobuster_dns(self, stdout):
        subs = []
        for line in stdout.splitlines():
            m = re.search(r"Found:\s+([\w\.\-]+)", line)
            if m:
                subs.append(m.group(1))
        return subs

    def _fallback_dir_brute(self):
        log("webscan", "Python fallback: basic dir brute", C.Y)
        common_paths = ["/admin", "/login", "/api", "/backup", "/.env", "/.git", "/robots.txt", "/phpmyadmin"]
        dirs, files = [], []
        url = f"http://{self.target}" if not self.target.startswith("http") else self.target
        for path in common_paths:
            try:
                body, headers, code = http_get(f"{url}{path}", timeout=5)
                if code in [200, 301, 302, 401, 403]:
                    size = len(body)
                    if path.endswith("/"):
                        dirs.append((code, str(size), path))
                    else:
                        files.append((code, str(size), path))
            except Exception:
                pass
        return dirs, files

    def fetch_html_source(self):
        """Fetch and return the actual HTML source code of the target website."""
        log("webscan", f"Fetching HTML source code from {self.target}", C.B)
        
        urls_to_try = [
            f"https://{self.target}",
            f"http://{self.target}",
        ]
        
        for url in urls_to_try:
            try:
                body, headers, code = http_get(url, timeout=10)
                if code == 200 and body:
                    self.html_source = body
                    self.logger.raw("webscan", "html-source", body[:5000], f"URL: {url}, Status: {code}", 0)
                    self.logger.finding(
                        "webscan", "HTML Source Fetched",
                        f"Retrieved {len(body)} bytes from {url}",
                        "INFO",
                        f"First 200 chars: {body[:200]}...",
                        ""
                    )
                    log("webscan", f"Fetched {len(body)} bytes of HTML from {url}", C.G)
                    return True
                else:
                    log("webscan", f"Failed to fetch from {url} (status: {code})", C.Y)
            except Exception as e:
                log("webscan", f"Error fetching from {url}: {str(e)[:100]}", C.Y)
                continue
        
        self.logger.finding("webscan", "HTML Source", "Could not retrieve HTML source", "INFO")
        return False

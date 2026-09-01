#!/usr/bin/env python3
"""
GODS Module: subdomain
Tools: crt.sh, subfinder, amass
"""
import json
import urllib.request
from utils.helpers import run_cmd, tool_check, C, log
from config.settings import TOOLS, TIMEOUTS, SUBDOMAIN_SOURCES

class Subdomain:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("Subdomain Enumeration")
        print()
        print("Sources:", ", ".join(SUBDOMAIN_SOURCES))
        src = input("[?] Sources (comma-separated, default=all): ").strip()
        if src:
            sources = [s.strip().lower() for s in src.split(",")]
            valid = [s for s in sources if s in [x.lower() for x in SUBDOMAIN_SOURCES]]
            if not valid:
                valid = ["crt.sh"]
        else:
            valid = SUBDOMAIN_SOURCES[:]

        self.options = {"sources": valid}
        print()

    def run(self):
        if not self.options or not self.options.get("sources"):
            self._prompt_options()

        sources = self.options.get("sources", SUBDOMAIN_SOURCES[:])
        log("subdomain", f"Enumerating subdomains for {self.target} from {sources}", C.B)
        results = {"subdomains": []}

        if "crt.sh" in sources or "all" in sources:
            log("subdomain", "Querying crt.sh", C.Y)
            try:
                url = f"https://crt.sh/?q=%.{self.target}&output=json"
                req = urllib.request.Request(url, headers={"User-Agent": "GODS-Recon"})
                with urllib.request.urlopen(req, timeout=TIMEOUTS["subdomain"]) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for entry in data:
                        name = entry.get("name_value", "").strip()
                        if name and name not in results["subdomains"]:
                            results["subdomains"].append(name)
                    self.logger.tools_used.append("crt.sh")
            except Exception as e:
                log("subdomain", f"crt.sh error: {e}", C.Y)
                self.logger.tools_skipped.append("crt.sh (API/network error)")

        if "subfinder" in sources:
            if tool_check(TOOLS["subfinder"]):
                log("subdomain", "Running subfinder", C.Y)
                stdout, stderr, rc = run_cmd([TOOLS["subfinder"], "-d", self.target, "-silent"], timeout=TIMEOUTS["subdomain"])
                self.logger.raw("subdomain", "subfinder", stdout, stderr, rc)
                for line in stdout.splitlines():
                    line = line.strip()
                    if line and line not in results["subdomains"]:
                        results["subdomains"].append(line)
                self.logger.tools_used.append("subfinder")
            else:
                log("subdomain", "subfinder not installed, skipping", C.Y)
                self.logger.tools_skipped.append("subfinder (not installed)")

        if "amass" in sources:
            if tool_check(TOOLS["amass"]):
                log("subdomain", "Running amass", C.Y)
                stdout, stderr, rc = run_cmd([TOOLS["amass"], "enum", "-passive", "-d", self.target], timeout=TIMEOUTS["subdomain"])
                self.logger.raw("subdomain", "amass", stdout, stderr, rc)
                for line in stdout.splitlines():
                    line = line.strip()
                    if line and line not in results["subdomains"]:
                        results["subdomains"].append(line)
                self.logger.tools_used.append("amass")
            else:
                log("subdomain", "amass not installed, skipping", C.Y)
                self.logger.tools_skipped.append("amass (not installed)")

        # Deduplicate
        results["subdomains"] = sorted(set(results["subdomains"]))

        for sub in results["subdomains"]:
            self.logger.finding("subdomain", f"Subdomain: {sub}", "Discovered via enumeration", "INFO")

        log("subdomain", f"Done. {len(results['subdomains'])} subdomains found.", C.G)
        return results

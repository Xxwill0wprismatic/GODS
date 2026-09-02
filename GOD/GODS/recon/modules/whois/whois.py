#!/usr/bin/env python3
"""
GODS Module: whois
Tools: whois, python fallback
"""
import re
from utils.helpers import run_cmd, tool_check, C, log
from config.settings import TOOLS, TIMEOUTS

class Whois:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("WHOIS Lookup")
        print()
        self.options = {"confirmed": True}
        print()

    def run(self):
        if not self.options:
            self._prompt_options()

        log("whois", f"Looking up WHOIS for {self.target}", C.B)
        results = {"raw": "", "registrar": None, "expires": None}

        if tool_check(TOOLS["whois"]):
            stdout, stderr, rc = run_cmd([TOOLS["whois"], self.target], timeout=TIMEOUTS["whois"])
            self.logger.raw("whois", "whois", stdout, stderr, rc)
            if rc == 0:
                results["raw"] = stdout
                results["registrar"] = self._extract(stdout, r"Registrar:\s*(.+)")
                results["expires"] = self._extract(stdout, r"Expiry Date:\s*(.+)")
                self.logger.finding("whois", "WHOIS lookup complete", f"Registrar: {results['registrar'] or 'N/A'}", "INFO",
                                    stdout[:500], "")
                self.logger.tools_used.append("whois")
            else:
                log("whois", f"whois failed: {stderr[:100]}", C.Y)
                self.logger.finding("whois", "WHOIS lookup failed", stderr[:200], "INFO")
        else:
            log("whois", "whois not installed, skipping", C.Y)
            self.logger.tools_skipped.append("whois (not installed)")
            self.logger.finding("whois", "WHOIS skipped", "whois command not available", "INFO",
                                "", "Install whois for domain registration data.")

        log("whois", "WHOIS complete.", C.G)
        return results

    def _extract(self, text, pattern):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else None

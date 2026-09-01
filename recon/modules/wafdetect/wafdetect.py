#!/usr/bin/env python3
"""
GODS Module: wafdetect
Tools: wafw00f, python fallback
"""
import re
from utils.helpers import run_cmd, tool_check, http_get, C, log
from config.settings import TOOLS, TIMEOUTS

class WAFDetect:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("WAF Detection")
        print()
        print("[1] Passive   (headers only)")
        print("[2] Standard  (headers + basic probe)")
        print("[3] Aggressive (headers + probe + wafw00f)")
        print()
        choice = input("[?] Mode (1-3, default=2): ").strip() or "2"
        mode_map = {"1": "passive", "2": "standard", "3": "aggressive"}
        mode = mode_map.get(choice, "standard")

        self.options = {"method": mode}
        print()

    def _probe_waf(self, url):
        wafs = []
        try:
            body, headers, code = http_get(url, timeout=10)
            hstr = str(headers).lower()
            if "cloudflare" in hstr:
                wafs.append("Cloudflare")
            if "akamai" in hstr:
                wafs.append("Akamai")
            if "incapsula" in hstr or "x-iinfo" in hstr:
                wafs.append("Incapsula")
            if "sucuri" in hstr:
                wafs.append("Sucuri")
            if "aws" in hstr and "waf" in hstr:
                wafs.append("AWS WAF")
            if code == 403 and any(x in body.lower() for x in ["blocked", "firewall", "waf"]):
                wafs.append("Generic WAF (blocked response)")
        except Exception:
            pass
        return wafs

    def run(self):
        if not self.options or not self.options.get("method"):
            self._prompt_options()

        mode = self.options.get("method", "standard")
        log("wafdetect", f"Detecting WAF on {self.target} [{mode}]", C.B)
        results = {"waf": [], "confidence": "low"}

        url = f"https://{self.target}"
        wafs = self._probe_waf(url)
        for w in wafs:
            if w not in results["waf"]:
                results["waf"].append(w)
                results["confidence"] = "medium"
                self.logger.finding("wafdetect", f"WAF detected: {w}",
                    "Detected via header/response fingerprint", "INFO",
                    "", "Verify WAF rules are properly configured.")

        if mode == "aggressive" and tool_check(TOOLS["wafw00f"]):
            log("wafdetect", "Running wafw00f", C.Y)
            stdout, stderr, rc = run_cmd([TOOLS["wafw00f"], self.target], timeout=TIMEOUTS["wafdetect"])
            self.logger.raw("wafdetect", "wafw00f", stdout, stderr, rc)
            for line in stdout.splitlines():
                m = re.search(r"is behind (.*) WAF", line)
                if m:
                    waf_name = m.group(1).strip()
                    if waf_name and waf_name not in results["waf"]:
                        results["waf"].append(waf_name)
                        results["confidence"] = "high"
                        self.logger.finding("wafdetect", f"WAF confirmed: {waf_name}",
                            "Detected via wafw00f", "INFO", line, "")
            self.logger.tools_used.append("wafw00f")
        elif mode == "aggressive" and not tool_check(TOOLS["wafw00f"]):
            log("wafdetect", "wafw00f not installed, using fallback only", C.Y)
            self.logger.tools_skipped.append("wafw00f (not installed)")

        if not results["waf"]:
            self.logger.finding("wafdetect", "No WAF detected", "No WAF signatures found", "INFO")

        log("wafdetect", f"Done. WAFs: {results['waf']}", C.G)
        return results

#!/usr/bin/env python3
"""
GODS Module: headers
Tools: curl, python urllib
"""
from utils.helpers import run_cmd, tool_check, http_get, C, log
from config.settings import TOOLS, TIMEOUTS

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "Enable HSTS to enforce HTTPS."),
    "Content-Security-Policy": ("MEDIUM", "Define a CSP to mitigate XSS and data injection."),
    "X-Frame-Options": ("LOW", "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."),
    "X-Content-Type-Options": ("LOW", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("LOW", "Set a Referrer-Policy to control referrer leakage."),
    "Permissions-Policy": ("LOW", "Set Permissions-Policy to restrict feature access."),
    "X-XSS-Protection": ("INFO", "X-XSS-Protection is deprecated; use CSP instead."),
}

class Headers:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("Header Security Check")
        print()
        print("[1] HTTPS only")
        print("[2] HTTP only")
        print("[3] Both")
        print()
        choice = input("[?] Protocol (1-3, default=3): ").strip() or "3"
        proto_map = {"1": "https", "2": "http", "3": "both"}
        protocol = proto_map.get(choice, "both")
        follow = input("[?] Follow redirects? (Y/n): ").strip().lower() != "n"

        self.options = {
            "protocol": protocol,
            "follow_redirects": follow,
        }
        print()

    def _check_headers(self, url):
        try:
            body, headers, code = http_get(url, timeout=TIMEOUTS["headers"])
            return headers, code
        except Exception as e:
            return {}, 0

    def run(self):
        if not self.options or not self.options.get("protocol"):
            self._prompt_options()

        protocol = self.options.get("protocol", "both")
        follow_redirects = self.options.get("follow_redirects", True)

        log("headers", f"Checking security headers on {self.target} [{protocol}]", C.B)
        results = {"missing": [], "present": [], "codes": {}}
        connections_failed = 0
        connections_success = 0

        urls = []
        if protocol in ("https", "both"):
            urls.append(f"https://{self.target}")
        if protocol in ("http", "both"):
            urls.append(f"http://{self.target}")

        for url in urls:
            headers, code = self._check_headers(url)
            results["codes"][url] = code

            if code == 0:
                log("headers", f"Failed to connect to {url}", C.Y)
                self.logger.finding("headers", f"Connection failed", f"Could not reach {url}", "INFO")
                connections_failed += 1
                continue

            connections_success += 1
            
            if code >= 400:
                self.logger.finding("headers", f"Error response from {url}", f"HTTP {code}", "INFO")

            # Redirect handling
            if code in [301, 302, 307, 308] and follow_redirects:
                loc = headers.get("Location", "")
                if loc:
                    self.logger.finding("headers", f"Redirect on {url}", f"-> {loc}", "INFO")

            present = []
            missing = []
            for h, (sev, remediation) in SECURITY_HEADERS.items():
                if h in headers:
                    present.append(h)
                    val = headers[h]
                    if h == "X-Frame-Options" and val.lower() not in ["deny", "sameorigin"]:
                        self.logger.finding("headers", f"Weak {h}", f"Value: {val}", "MEDIUM",
                                            val, "Use DENY or SAMEORIGIN.")
                    else:
                        self.logger.finding("headers", f"{h} present", val, "INFO")
                else:
                    missing.append(h)
                    self.logger.finding("headers", f"Missing {h}", "Header not set", sev,
                                        "", remediation)

            results["present"].extend(present)
            results["missing"].extend(missing)

        # Set module status based on results
        if connections_success > 0:
            self.logger.set_module_status("headers", "SUCCESS", f"Analyzed {connections_success} URL(s)")
        elif connections_failed > 0:
            self.logger.set_module_status("headers", "PARTIAL", f"Could not connect to any URLs ({connections_failed} failed)")
        else:
            self.logger.set_module_status("headers", "PARTIAL", "No URLs to check")

        log("headers", "Header check complete.", C.G)
        return results

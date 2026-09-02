#!/usr/bin/env python3
"""
GODS Module: techdetect
Tools: WhatWeb, python fallback
"""
import re
from utils.helpers import run_cmd, tool_check, http_get, C, log
from config.settings import TOOLS, TIMEOUTS

class TechDetect:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("Technology Detection")
        print()
        print("[1] Passive   (headers only)")
        print("[2] Standard  (headers + basic response)")
        print("[3] Aggressive (headers + response + whatweb)")
        print()
        choice = input("[?] Mode (1-3, default=2): ").strip() or "2"
        mode_map = {"1": "passive", "2": "standard", "3": "aggressive"}
        mode = mode_map.get(choice, "standard")
        check_both = input("[?] Check both HTTP and HTTPS? (Y/n): ").strip().lower() != "n"

        self.options = {
            "aggressiveness": mode,
            "check_both": check_both,
        }
        print()

    def _fingerprint(self, url):
        techs = []
        try:
            body, headers, code = http_get(url, timeout=10)
            server = headers.get("Server", "")
            powered = headers.get("X-Powered-By", "")
            if server:
                techs.append(("Server", server))
            if powered:
                techs.append(("X-Powered-By", powered))
            if "wp-content" in body.lower() or "wordpress" in body.lower():
                techs.append(("CMS", "WordPress (fingerprinted)"))
            if "drupal" in body.lower():
                techs.append(("CMS", "Drupal (fingerprinted)"))
            if "joomla" in body.lower():
                techs.append(("CMS", "Joomla (fingerprinted)"))
            if "cloudflare" in str(headers).lower():
                techs.append(("CDN", "Cloudflare"))
            if "nginx" in server.lower():
                techs.append(("Web Server", "nginx"))
            if "apache" in server.lower():
                techs.append(("Web Server", "Apache"))
        except Exception:
            pass
        return techs

    def run(self):
        if not self.options or not self.options.get("aggressiveness"):
            self._prompt_options()

        mode = self.options.get("aggressiveness", "standard")
        check_both = self.options.get("check_both", True)

        log("techdetect", f"Detecting technologies on {self.target} [{mode}]", C.B)
        results = {"technologies": []}

        urls = [f"https://{self.target}"]
        if check_both:
            urls.append(f"http://{self.target}")

        for url in urls:
            techs = self._fingerprint(url)
            for name, val in techs:
                if (name, val) not in results["technologies"]:
                    results["technologies"].append((name, val))
                    confidence = "fingerprinted" if "fingerprinted" in val else "header"
                    self.logger.finding("techdetect", f"{name}: {val}",
                        f"Detected via {confidence} on {url}", "INFO",
                        val, "Verify technology versions and patch levels.")

        if mode == "aggressive" and tool_check(TOOLS["whatweb"]):
            log("techdetect", "Running WhatWeb", C.Y)
            stdout, stderr, rc = run_cmd([TOOLS["whatweb"], "--color=never", self.target], timeout=TIMEOUTS["techdetect"])
            self.logger.raw("techdetect", "whatweb", stdout, stderr, rc)
            for line in stdout.splitlines():
                if self.target in line:
                    for part in line.split(","):
                        part = part.strip()
                        if "[" in part:
                            name = part.split("[")[0].strip()
                            ver = part.split("[")[1].rstrip("]")
                            if (name, ver) not in results["technologies"]:
                                results["technologies"].append((name, ver))
                                self.logger.finding("techdetect", f"{name}: {ver}",
                                    "Detected via WhatWeb", "INFO", part, "")
            self.logger.tools_used.append("whatweb")
        elif mode == "aggressive" and not tool_check(TOOLS["whatweb"]):
            log("techdetect", "whatweb not installed, using python fallback only", C.Y)
            self.logger.tools_skipped.append("whatweb (not installed)")

        # Set module status
        if results["technologies"]:
            self.logger.set_module_status("techdetect", "SUCCESS", f"Detected {len(results['technologies'])} technologies")
        else:
            self.logger.set_module_status("techdetect", "PARTIAL", "No technologies detected")

        log("techdetect", f"Done. {len(results['technologies'])} technologies found.", C.G)
        return results

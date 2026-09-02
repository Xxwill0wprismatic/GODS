#!/usr/bin/env python3
"""
GODS Module: certtransparency
Tools: crt.sh API, CertSpotter API
"""
import json
import urllib.request
from datetime import datetime
from utils.helpers import C, log
from config.settings import TIMEOUTS

class CertTransparency:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("Certificate Transparency")
        print()
        print("[1] crt.sh")
        print("[2] CertSpotter")
        print("[3] Both")
        print()
        choice = input("[?] Source (1-3, default=3): ").strip() or "3"
        source_map = {"1": "crt.sh", "2": "certspotter", "3": "both"}
        source = source_map.get(choice, "both")
        expired = input("[?] Include expired certificates? (y/N): ").strip().lower() == "y"

        self.options = {
            "source": source,
            "include_expired": expired,
        }
        print()

    def _fetch_crtsh(self):
        certs = []
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "GODS-Recon"})
            with urllib.request.urlopen(req, timeout=TIMEOUTS["certtransparency"]) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for entry in data:
                    certs.append({
                        "name": entry.get("name_value", "").strip(),
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    })
        except Exception as e:
            log("certtransparency", f"crt.sh error: {e}", C.Y)
        return certs

    def _fetch_certspotter(self):
        certs = []
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names&expand=issuer"
            req = urllib.request.Request(url, headers={"User-Agent": "GODS-Recon"})
            with urllib.request.urlopen(req, timeout=TIMEOUTS["certtransparency"]) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for entry in data:
                    for name in entry.get("dns_names", []):
                        certs.append({
                            "name": name,
                            "issuer": entry.get("issuer", {}).get("name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                        })
        except Exception as e:
            log("certtransparency", f"CertSpotter error: {e}", C.Y)
        return certs

    def run(self):
        if not self.options or not self.options.get("source"):
            self._prompt_options()

        source = self.options.get("source", "both")
        include_expired = self.options.get("include_expired", False)

        log("certtransparency", f"Querying CT logs for {self.target} [{source}]", C.B)
        results = {"certificates": []}

        all_certs = []
        if source in ("crt.sh", "both"):
            all_certs.extend(self._fetch_crtsh())
        if source in ("certspotter", "both"):
            all_certs.extend(self._fetch_certspotter())

        # Deduplicate by name
        seen = set()
        for c in all_certs:
            key = c["name"]
            if key not in seen:
                seen.add(key)
                if not include_expired and c.get("not_after"):
                    try:
                        expiry = datetime.strptime(c["not_after"], "%Y-%m-%dT%H:%M:%S")
                        if expiry < datetime.utcnow():
                            continue
                    except Exception:
                        pass
                results["certificates"].append(c)
                self.logger.finding("certtransparency", f"CT cert: {c['name']}",
                    f"Issuer: {c.get('issuer', 'N/A')}", "INFO",
                    f"NotAfter: {c.get('not_after', 'N/A')}", "")

        log("certtransparency", f"Done. {len(results['certificates'])} certificates found.", C.G)
        return results

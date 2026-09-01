#!/usr/bin/env python3
"""
GODS Engine: correlator
Cross-references findings between modules and upgrades severity where needed.
"""
from utils.helpers import C, log

class Correlator:
    def __init__(self, findings, logger):
        self.findings = findings
        self.logger = logger

    def run(self):
        log("CORRELATOR", "Cross-referencing findings...", C.B)

        ports = set()
        techs = set()
        headers = set()
        for f in self.findings:
            title = f.get("title", "").lower()
            if "port" in title and "open" in title:
                try:
                    p = int(title.split()[1].split("/")[0])
                    ports.add(p)
                except Exception:
                    pass
            if f.get("module") == "techdetect":
                techs.add(title.lower())
            if f.get("module") == "headers":
                headers.add(title.lower())

        for f in self.findings:
            title = f.get("title", "").lower()
            desc = f.get("description", "").lower()

            if "admin" in title and "waf" not in str(techs):
                for wf in self.findings:
                    if wf.get("module") == "wafdetect" and "no waf" in wf["title"].lower():
                        f["severity"] = "HIGH"
                        f["severity_rank"] = 3
                        f["description"] = f.get("description", "") + " [CORR: Admin panel exposed without WAF]"
                        break

            if any(p in ports for p in [3306, 5432, 1433, 27017, 6379]):
                for tf in self.findings:
                    if tf.get("module") == "tls" and tf.get("severity") == "INFO" and "grade" in tf["title"].lower():
                        if "F" in tf["title"] or "no tls" in tf["description"].lower():
                            for pf in self.findings:
                                if pf.get("module") == "portscan" and any(str(p) in pf["title"] for p in [3306, 5432, 1433, 27017, 6379]):
                                    if pf["severity"] not in ["CRITICAL", "HIGH"]:
                                        pf["severity"] = "HIGH"
                                        pf["severity_rank"] = 3
                                        pf["description"] = f.get("description", "") + " [CORR: Database port open with broken/missing TLS]"

            if "wordpress" in str(techs):
                for hf in self.findings:
                    if hf.get("module") == "headers" and "missing" in hf["title"].lower():
                        if hf["severity"] == "LOW":
                            hf["severity"] = "MEDIUM"
                            hf["severity_rank"] = 2
                            hf["description"] = f.get("description", "") + " [CORR: WordPress site missing basic hardening headers]"

            if "cloudflare" in str(techs):
                for pf in self.findings:
                    if pf.get("module") == "portscan" and pf["severity"] in ["CRITICAL", "HIGH"]:
                        pf["description"] = f.get("description", "") + " [CORR: Port exposed despite Cloudflare proxy]"

        log("CORRELATOR", "Correlation complete.", C.G)
        return self.findings

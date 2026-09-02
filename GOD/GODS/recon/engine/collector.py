#!/usr/bin/env python3
"""
GODS Engine: collector
Orchestrates all recon modules and collects raw output.
"""
import time
from utils.helpers import C, log, banner
from utils.logger import ReconLogger

from modules.portscan.portscan import PortScan
from modules.webscan.webscan import WebScan
from modules.dns.dns import DNS
from modules.tls.tls import TLS
from modules.headers.headers import Headers
from modules.whois.whois import Whois
from modules.subdomain.subdomain import Subdomain
from modules.techdetect.techdetect import TechDetect
from modules.wafdetect.wafdetect import WAFDetect
from modules.certtransparency.certtransparency import CertTransparency
from modules.metasploit.metasploit import Metasploit

# Module execution states
MODULE_SUCCESS = "SUCCESS"
MODULE_PARTIAL = "PARTIAL"
MODULE_SKIPPED = "SKIPPED"
MODULE_FAILED = "FAILED"

class Collector:
    def __init__(self, target, logger, modules=None, wordlist=None, tls_port=443,
                 portscan_opts=None, webscan_opts=None, dns_opts=None,
                 tls_opts=None, headers_opts=None, whois_opts=None,
                 subdomain_opts=None, techdetect_opts=None, wafdetect_opts=None,
                 certtransparency_opts=None, metasploit_opts=None):
        self.target = target
        self.logger = logger
        self.wordlist = wordlist
        self.tls_port = tls_port
        self.portscan_opts = portscan_opts or {}
        self.webscan_opts = webscan_opts or {}
        self.dns_opts = dns_opts or {}
        self.tls_opts = tls_opts or {}
        self.headers_opts = headers_opts or {}
        self.whois_opts = whois_opts or {}
        self.subdomain_opts = subdomain_opts or {}
        self.techdetect_opts = techdetect_opts or {}
        self.wafdetect_opts = wafdetect_opts or {}
        self.certtransparency_opts = certtransparency_opts or {}
        self.metasploit_opts = metasploit_opts or {}
        self.results = {}
        self.modules = modules or [
            "portscan", "webscan", "dns", "tls", "headers",
            "whois", "subdomain", "techdetect", "wafdetect", "certtransparency", "metasploit"
        ]

    def _run_module(self, name, factory):
        """
        Run one module with explicit status tracking.
        
        Status values:
        - SUCCESS: Module completed successfully with valid results
        - PARTIAL: Module ran but some optional component/tool was unavailable  
        - SKIPPED: Required external dependency/tool is unavailable
        - FAILED: Execution/error prevented the module from completing
        """
        try:
            result = factory().run()
            # Modules track their own status based on whether external tools were used
            # Check if module recorded any issues
            module_info = self.logger.module_status.get(name, {})
            status = module_info.get('status', MODULE_SUCCESS)
            
            self.results[name] = result
            # Track that this module actually ran
            self.logger.modules_run.append(name)
            
        except Exception as exc:
            reason = f"{type(exc).__name__}: {exc}"
            self.logger.set_module_status(name, MODULE_FAILED, reason)
            log("ENGINE", f"{name} failed: {reason}", C.R)
            self.results[name] = {"error": reason}

    def run(self):
        banner()
        log("ENGINE", f"Target: {self.target}", C.G)
        log("ENGINE", f"Modules: {', '.join(self.modules)}", C.G)
        print()

        start = time.time()

        if "portscan" in self.modules:
            log("ENGINE", "--- Port Scan ---", C.B)
            self._run_module("portscan", lambda: PortScan(self.target, self.logger, self.portscan_opts))
            print()

        if "dns" in self.modules:
            log("ENGINE", "--- DNS Recon ---", C.B)
            self._run_module("dns", lambda: DNS(self.target, self.logger, self.dns_opts))
            print()

        if "subdomain" in self.modules:
            log("ENGINE", "--- Subdomain Enum ---", C.B)
            self._run_module("subdomain", lambda: Subdomain(self.target, self.logger, self.subdomain_opts))
            print()

        if "certtransparency" in self.modules:
            log("ENGINE", "--- Cert Transparency ---", C.B)
            self._run_module("certtransparency", lambda: CertTransparency(self.target, self.logger, self.certtransparency_opts))
            print()

        if "whois" in self.modules:
            log("ENGINE", "--- WHOIS Lookup ---", C.B)
            self._run_module("whois", lambda: Whois(self.target, self.logger, self.whois_opts))
            print()

        if "webscan" in self.modules:
            log("ENGINE", "--- Web Path Scan ---", C.B)
            self._run_module("webscan", lambda: WebScan(self.target, self.logger, self.webscan_opts))
            print()

        if "techdetect" in self.modules:
            log("ENGINE", "--- Tech Detection ---", C.B)
            self._run_module("techdetect", lambda: TechDetect(self.target, self.logger, self.techdetect_opts))
            print()

        if "wafdetect" in self.modules:
            log("ENGINE", "--- WAF Detection ---", C.B)
            self._run_module("wafdetect", lambda: WAFDetect(self.target, self.logger, self.wafdetect_opts))
            print()

        if "tls" in self.modules:
            log("ENGINE", "--- TLS Analysis ---", C.B)
            self._run_module("tls", lambda: TLS(self.target, self.logger, self.tls_opts))
            print()

        if "headers" in self.modules:
            log("ENGINE", "--- Header Security ---", C.B)
            self._run_module("headers", lambda: Headers(self.target, self.logger, self.headers_opts))
            print()

        if "metasploit" in self.modules:
            log("ENGINE", "--- Metasploit Framework ---", C.B)
            self._run_module("metasploit", lambda: Metasploit(self.target, self.logger, self.metasploit_opts))
            print()

        for name in self.modules:
            # Mark as SKIPPED only if module was requested but never ran
            if name not in self.logger.module_status and name not in self.logger.modules_run:
                self.logger.set_module_status(name, MODULE_SKIPPED, "Module was requested but not executed")

        elapsed = time.time() - start
        log("ENGINE", f"Collection complete in {elapsed:.1f}s", C.G)
        return self.results

#!/usr/bin/env python3
"""
GODS Module: dns
Tools: dig, host, python fallback using socket/dns.resolver
"""
import re
import socket
import dns.resolver
import dns.exception
from utils.helpers import run_cmd, tool_check, C, log
from config.settings import TOOLS, TIMEOUTS, DNS_RECORD_TYPES

# Module status constants
MODULE_SUCCESS = "SUCCESS"
MODULE_PARTIAL = "PARTIAL"
MODULE_SKIPPED = "SKIPPED"
MODULE_FAILED = "FAILED"


class DNS:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("DNS Recon")
        print()
        print("Available record types:", ", ".join(DNS_RECORD_TYPES))
        rt = input("[?] Record types (comma-separated, default=A,MX,NS,TXT): ").strip()
        if rt:
            types = [t.strip().upper() for t in rt.split(",")]
            valid = [t for t in types if t in DNS_RECORD_TYPES]
            invalid = [t for t in types if t not in DNS_RECORD_TYPES]
            if invalid:
                log("dns", f"Invalid record types skipped: {', '.join(invalid)}", C.Y)
            if not valid:
                log("dns", "No valid record types, using default", C.Y)
                valid = ["A", "MX", "NS", "TXT"]
        else:
            valid = ["A", "MX", "NS", "TXT"]

        wildcard = input("[?] Check wildcard DNS? (Y/n): ").strip().lower() != "n"
        zone_xfer = input("[?] Check zone transfer? (y/N): ").strip().lower() == "y"

        self.options = {
            "record_types": valid,
            "wildcard": wildcard,
            "zone_xfer": zone_xfer,
        }
        print()

    def _query_with_dig(self, rtype):
        """Query DNS using dig command."""
        stdout, stderr, rc = run_cmd([TOOLS["dig"], "+short", rtype, self.target], timeout=TIMEOUTS["dns"])
        self.logger.raw("dns", f"dig-{rtype}", stdout, stderr, rc)
        return stdout, stderr, rc

    def _query_with_host(self, rtype):
        """Query DNS using host command."""
        stdout, stderr, rc = run_cmd([TOOLS["host"], "-t", rtype, self.target], timeout=TIMEOUTS["dns"])
        self.logger.raw("dns", f"host-{rtype}", stdout, stderr, rc)
        if rc == 0:
            lines = []
            for line in stdout.splitlines():
                if " has " in line and " pointer " not in line.lower():
                    value = line.split(" has ", 1)[1]
                    if " " in value:
                        value = value.split(" ", 1)[1]
                    lines.append(value.strip().rstrip("."))
            stdout = "\n".join(lines)
        return stdout, stderr, rc

    def _query_with_python(self, rtype):
        """Query DNS using Python's dns.resolver (fallback)."""
        try:
            answers = dns.resolver.resolve(self.target, rtype)
            records = []
            raw_output = []
            for rdata in answers:
                raw_str = rdata.to_text().strip('"')
                raw_output.append(raw_str)
                if rtype == "MX":
                    records.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                else:
                    records.append(str(rdata).rstrip('.'))
            
            self.logger.raw("dns", f"python-dns-{rtype}", "\n".join(raw_output), "", 0)
            return "\n".join(records), "", 0
        except dns.resolver.NoAnswer:
            # Query succeeded but no records of this type exist
            self.logger.raw("dns", f"python-dns-{rtype}", "", "No answer", 0)
            return "", "No answer", 0
        except dns.resolver.NXDOMAIN:
            self.logger.raw("dns", f"python-dns-{rtype}", "", "Domain does not exist", -1)
            return "", "Domain does not exist (NXDOMAIN)", -1
        except dns.resolver.NoNameservers:
            self.logger.raw("dns", f"python-dns-{rtype}", "", "No nameservers available", -1)
            return "", "No nameservers available", -1
        except dns.resolver.Timeout:
            self.logger.raw("dns", f"python-dns-{rtype}", "", "DNS query timeout", -1)
            return "", "DNS query timeout", -1
        except dns.exception.DNSException as e:
            self.logger.raw("dns", f"python-dns-{rtype}", "", str(e), -1)
            return "", str(e), -1
        except Exception as e:
            self.logger.raw("dns", f"python-dns-{rtype}", "", str(e), -1)
            return "", str(e), -1

    def run(self):
        if not self.options or not self.options.get("record_types"):
            self._prompt_options()

        record_types = self.options.get("record_types", ["A", "MX", "NS", "TXT"])
        wildcard = self.options.get("wildcard", True)
        zone_xfer = self.options.get("zone_xfer", False)

        log("dns", f"Querying DNS records for {self.target}", C.B)
        results = {"records": {}, "wildcard": False, "zone_xfer": False}
        
        has_external_tool = False
        has_partial_results = False
        successful_records = []

        has_dig = tool_check(TOOLS["dig"])
        has_host = tool_check(TOOLS["host"])

        if has_dig:
            self.logger.tools_used.append("dig")
            has_external_tool = True
        elif has_host:
            self.logger.tools_used.append("host")
            has_external_tool = True
        else:
            self.logger.tools_skipped.append("dig (not installed)")
            self.logger.tools_skipped.append("host (not installed)")
            log("dns", "Using Python dns.resolver fallback", C.Y)

        for rtype in record_types:
            stdout = stderr = ""
            rc = -1
            source = "unknown"
            
            if has_dig:
                stdout, stderr, rc = self._query_with_dig(rtype)
                source = "dig"
            elif has_host:
                stdout, stderr, rc = self._query_with_host(rtype)
                source = "host"
            else:
                # Use Python fallback
                stdout, stderr, rc = self._query_with_python(rtype)
                source = "python-dns.resolver"
            
            # Parse results
            if rc == 0 and stdout.strip():
                values = [line.strip() for line in stdout.splitlines() if line.strip()]
                results["records"][rtype] = values
                successful_records.append(rtype)
                
                for v in values:
                    self.logger.finding("dns", f"{rtype} record found", v, "INFO",
                                        f"Source: {source}", "")
            elif rc == 0 and not stdout.strip():
                # Query succeeded but returned empty - valid for some record types
                results["records"][rtype] = []
                # Don't report "no record found" for all types - CNAME can exist without A record
                if rtype == "A":
                    self.logger.finding("dns", f"{rtype} record", "No A record (domain may use CNAME)", "INFO",
                                        "Source: " + source, "")
                elif rtype == "AAAA":
                    self.logger.finding("dns", f"{rtype} record", "No AAAA record", "INFO",
                                        "Source: " + source, "")
                # MX, NS, TXT that return empty might be intentional
            else:
                # Error occurred
                results["records"][rtype] = []
                has_partial_results = True
                error_msg = stderr if stderr else "DNS query failed"
                
                if "No answer" in error_msg or "NXDOMAIN" in error_msg:
                    # Domain doesn't exist - this is a valid result
                    self.logger.finding("dns", f"{rtype} record", "Domain does not exist or record not found", "INFO",
                                        f"Source: {source}, Error: {error_msg[:100]}", "")
                else:
                    # Actual error
                    self.logger.finding("dns", f"{rtype} lookup error", error_msg[:200], "INFO",
                                        f"Source: {source}", "Check DNS configuration")

        # Set module status based on results
        if successful_records:
            if has_partial_results and not has_external_tool:
                self.logger.set_module_status("dns", MODULE_PARTIAL, "Some records had errors; using Python fallback")
            elif has_external_tool:
                self.logger.set_module_status("dns", MODULE_SUCCESS, f"Found {len(successful_records)} record types via {source}")
            else:
                self.logger.set_module_status("dns", MODULE_PARTIAL, f"Python fallback: found {len(successful_records)} record types")
        else:
            self.logger.set_module_status("dns", MODULE_FAILED, "No DNS records could be retrieved")

        # Wildcard check
        if wildcard:
            log("dns", "Checking wildcard DNS", C.Y)
            fake = f"wildcard-test-{abs(hash(self.target)) % 100000}.{self.target}"
            try:
                socket.gethostbyname(fake)
                results["wildcard"] = True
                self.logger.finding("dns", "Wildcard DNS detected", f"{fake} resolved", "MEDIUM",
                                    "", "Wildcard DNS can obscure true subdomain enumeration results.")
            except socket.gaierror:
                results["wildcard"] = False
                self.logger.finding("dns", "Wildcard DNS", "Not detected", "INFO")

        # Zone transfer check
        if zone_xfer:
            if has_dig:
                log("dns", "Checking zone transfer", C.Y)
                stdout, stderr, rc = run_cmd([TOOLS["dig"], "AXFR", self.target], timeout=TIMEOUTS["dns"])
                self.logger.raw("dns", "dig-axfr", stdout, stderr, rc)
                if rc == 0 and stdout and "; Transfer failed" not in stdout:
                    results["zone_xfer"] = True
                    self.logger.finding("dns", "Zone transfer allowed", "AXFR succeeded", "CRITICAL",
                                        stdout[:500], "Disable zone transfers on DNS servers.")
                else:
                    results["zone_xfer"] = False
                    self.logger.finding("dns", "Zone transfer", "Not allowed", "INFO")
            else:
                log("dns", "Cannot check zone transfer without dig", C.Y)
                self.logger.finding("dns", "Zone transfer", "Skipped (dig missing)", "INFO")

        log("dns", "DNS recon complete.", C.G)
        return results

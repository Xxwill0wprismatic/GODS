#!/usr/bin/env python3
"""
GODS Module: tls
Tools: openssl, sslscan, testssl.sh, python fallback
"""
import re
import ssl
import socket
from datetime import datetime
from utils.helpers import run_cmd, tool_check, http_get, C, log
from config.settings import TOOLS, TIMEOUTS

class TLS:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _prompt_options(self):
        print()
        print("TLS Analysis")
        print()
        port = input("[?] Port (default=443): ").strip() or "443"
        try:
            port = int(port)
        except ValueError:
            port = 443
        print("[1] Quick   (certificate only)")
        print("[2] Standard (cert + ciphers)")
        print("[3] Deep     (cert + ciphers + sslscan/testssl)")
        depth_choice = input("[?] Depth (1-3, default=2): ").strip() or "2"
        depth_map = {"1": "quick", "2": "standard", "3": "deep"}
        depth = depth_map.get(depth_choice, "standard")
        redirect = input("[?] Check HTTP->HTTPS redirect? (Y/n): ").strip().lower() != "n"

        self.options = {
            "port": port,
            "depth": depth,
            "check_redirect": redirect,
        }
        print()

    def run(self):
        if not self.options or not self.options.get("depth"):
            self._prompt_options()

        port = self.options.get("port", 443)
        depth = self.options.get("depth", "standard")
        check_redirect = self.options.get("check_redirect", True)

        log("tls", f"Analyzing TLS on {self.target}:{port} [{depth}]", C.B)
        results = {"cert": None, "ciphers": [], "redirect": False, "grade": "UNKNOWN"}

        # Check if TLS port is open first
        try:
            with socket.create_connection((self.target, port), timeout=5):
                pass
        except Exception as e:
            log("tls", f"Cannot connect to {self.target}:{port} — TLS not available", C.Y)
            self.logger.finding("tls", "TLS not available", f"Connection to port {port} failed: {e}", "INFO")
            self.logger.set_module_status("tls", "PARTIAL", f"Port {port} not reachable")
            return results

        # 1. Certificate info via openssl
        if tool_check(TOOLS["openssl"]):
            log("tls", "Fetching certificate via openssl", C.Y)
            cmd = [TOOLS["openssl"], "s_client", "-connect", f"{self.target}:{port}", "-servername", self.target, "</dev/null"]
            # Note: shell redirect won't work with list, use shell=True for this specific case or just use python ssl
            # Better: use Python ssl directly for cert parsing
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((self.target, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        results["cert"] = cert
                        results["ciphers"] = [cipher]
                        results["tls_version"] = version

                        if cert:
                            not_after = cert.get("notAfter")
                            if not_after:
                                try:
                                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                    days_left = (expiry - datetime.utcnow()).days
                                    if days_left < 0:
                                        self.logger.finding("tls", "Expired certificate",
                                            f"Expired {abs(days_left)} days ago", "CRITICAL",
                                            f"NotAfter: {not_after}", "Renew the certificate immediately.")
                                    elif days_left < 30:
                                        self.logger.finding("tls", "Certificate expiring soon",
                                            f"Expires in {days_left} days", "HIGH",
                                            f"NotAfter: {not_after}", "Renew the certificate before expiry.")
                                    else:
                                        self.logger.finding("tls", "Certificate valid",
                                            f"Expires in {days_left} days", "INFO",
                                            f"NotAfter: {not_after}", "")
                                except Exception:
                                    pass

                            issuer = cert.get("issuer")
                            subject = cert.get("subject")
                            if issuer and subject:
                                org = dict(subject).get("organizationName", "")
                                issuer_org = dict(issuer).get("organizationName", "")
                                if org and org == issuer_org:
                                    self.logger.finding("tls", "Self-signed certificate",
                                        f"Issuer matches subject: {issuer_org}", "INFO",
                                        str(cert), "Use a publicly trusted CA for production.")
                                else:
                                    self.logger.finding("tls", "Certificate issuer",
                                        f"Issued by: {issuer_org}", "INFO", str(issuer), "")
                        else:
                            self.logger.finding("tls", "No certificate retrieved", "", "INFO")

                        if version in ["TLSv1", "TLSv1.1"]:
                            self.logger.finding("tls", f"Deprecated {version} enabled",
                                "Outdated protocol version", "HIGH",
                                version, "Disable TLS 1.0/1.1 and enforce TLS 1.2+.")
                        elif version == "TLSv1.2":
                            self.logger.finding("tls", "TLS 1.2", "Modern minimum", "INFO", version, "")
                        elif version == "TLSv1.3":
                            self.logger.finding("tls", "TLS 1.3", "Latest version", "INFO", version, "")
            except ssl.SSLError as e:
                log("tls", f"SSL error: {e}", C.Y)
                self.logger.finding("tls", "SSL handshake failed", str(e), "INFO")
            except Exception as e:
                log("tls", f"Cert fetch error: {e}", C.Y)
                self.logger.finding("tls", "Certificate check error", str(e), "INFO")
            self.logger.tools_used.append("openssl")
        else:
            log("tls", "openssl not found, skipping cert details", C.Y)
            self.logger.tools_skipped.append("openssl (not installed)")

        # 2. sslscan (standard/deep)
        if depth in ("standard", "deep") and tool_check(TOOLS["sslscan"]):
            log("tls", "Running sslscan", C.Y)
            stdout, stderr, rc = run_cmd([TOOLS["sslscan"], f"{self.target}:{port}"], timeout=TIMEOUTS["tls"])
            self.logger.raw("tls", "sslscan", stdout, stderr, rc)
            weak = self._parse_sslscan(stdout)
            for cipher, strength in weak:
                sev = "MEDIUM" if "weak" in strength.lower() else "LOW"
                self.logger.finding("tls", f"Weak cipher: {cipher}", strength, sev,
                                    f"sslscan: {cipher}", "Disable weak ciphers in server config.")
            self.logger.tools_used.append("sslscan")
        elif depth in ("standard", "deep") and not tool_check(TOOLS["sslscan"]):
            log("tls", "sslscan not found, skipping cipher scan", C.Y)
            self.logger.tools_skipped.append("sslscan (not installed)")

        # 3. testssl.sh (deep only)
        if depth == "deep" and tool_check(TOOLS["testssl"]):
            log("tls", "Running testssl.sh", C.Y)
            stdout, stderr, rc = run_cmd([TOOLS["testssl"], "--fast", f"{self.target}:{port}"], timeout=TIMEOUTS["tls"])
            self.logger.raw("tls", "testssl", stdout, stderr, rc)
            self.logger.tools_used.append("testssl.sh")
        elif depth == "deep" and not tool_check(TOOLS["testssl"]):
            log("tls", "testssl.sh not found, skipping deep scan", C.Y)
            self.logger.tools_skipped.append("testssl.sh (not installed)")

        # 4. HTTP -> HTTPS redirect check
        if check_redirect:
            log("tls", "Checking HTTP->HTTPS redirect", C.Y)
            try:
                body, headers, code = http_get(f"http://{self.target}", timeout=10, allow_redirects=False)
                if code in [301, 302, 307, 308]:
                    loc = headers.get("Location", "")
                    if loc.startswith("https://"):
                        results["redirect"] = True
                        self.logger.finding("tls", "HTTP redirects to HTTPS", f"Location: {loc}", "INFO")
                    else:
                        results["redirect"] = False
                        self.logger.finding("tls", "HTTP redirect without HTTPS", f"Location: {loc}", "MEDIUM",
                                            "", "Ensure all HTTP traffic redirects to HTTPS.")
                elif code == 200:
                    results["redirect"] = False
                    self.logger.finding("tls", "HTTP serves content without redirect", "No redirect to HTTPS", "MEDIUM",
                                        "", "Implement HTTP->HTTPS redirect.")
                else:
                    self.logger.finding("tls", "HTTP check", f"Status {code}", "INFO")
            except Exception as e:
                self.logger.finding("tls", "HTTP redirect check failed", str(e), "INFO")

        # Set module status
        if results["cert"]:
            self.logger.set_module_status("tls", "SUCCESS", "TLS analysis complete")
        else:
            self.logger.set_module_status("tls", "PARTIAL", "Could not retrieve TLS certificate")

        log("tls", "TLS analysis complete.", C.G)
        return results

    def _parse_sslscan(self, stdout):
        weak = []
        for line in stdout.splitlines():
            if "Accepted" in line and any(x in line.lower() for x in ["rc4", "des", "md5", "null", "export"]):
                parts = line.split()
                if len(parts) >= 3:
                    weak.append((parts[2], "weak"))
        return weak

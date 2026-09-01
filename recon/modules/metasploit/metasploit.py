#!/usr/bin/env python3
"""
GODS Module: metasploit
Integration with Metasploit Framework for exploitation and vulnerability scanning.
Supports msfconsole auxiliary modules and msfvenom payload generation.
"""
import shutil
import os
from utils.helpers import run_cmd, tool_check, C, log
from engine.toolkit import (
    METASPLOIT_MODULES, METASPLOIT_PAYLOADS, run_metasploit_module,
    search_msf_payloads, generate_msf_payload
)
from config.settings import TIMEOUTS


class Metasploit:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}
        self.results = {
            "modules_run": [],
            "vulnerabilities": [],
            "services": [],
            "payloads_generated": []
        }

    def _prompt_options(self):
        print()
        print("Metasploit Options")
        print()
        print("[1] Quick scan (HTTP title, SMB, FTP)")
        print("[2] Web scan (HTTP modules)")
        print("[3] Network scan (common services)")
        print("[4] Custom modules")
        print("[5] Search payloads")
        print("[6] Generate payload")
        print()
        choice = input("[?] Select scan type (1-6, default=1): ").strip() or "1"
        
        if choice == "1":
            self.options["modules"] = ["http_title", "smb_version", "ftp_version"]
        elif choice == "2":
            self.options["modules"] = ["http_title", "http_version", "webdav_scanner"]
        elif choice == "3":
            self.options["modules"] = ["smb_version", "ssh_version", "ftp_version", 
                                      "telnet_version", "mysql_version", "vnc_none_auth"]
        elif choice == "4":
            print("\nAvailable modules:")
            for i, (name, path) in enumerate(sorted(METASPLOIT_MODULES.items()), 1):
                print(f"  {i}. {name:20} - {path}")
            print()
            selected = input("[?] Module names (comma-separated): ").strip()
            if selected:
                self.options["modules"] = [m.strip() for m in selected.split(",")]
        elif choice == "5":
            # Search payloads
            query = input("[?] Search query (or Enter for all): ").strip()
            results = search_msf_payloads(query)
            print(f"\nFound {len(results)} payloads:")
            for p in results[:20]:
                print(f"  {p['name']}")
            if len(results) > 20:
                print(f"  ... and {len(results) - 20} more")
            self.options["modules"] = []  # Don't run modules
        elif choice == "6":
            # Generate payload
            self._prompt_payload_generation()
            self.options["modules"] = []  # Don't run modules
        
        if choice not in ["5", "6"]:
            self.options["timeout"] = int(input("[?] Timeout per module (seconds, default=120): ").strip() or "120")
        print()

    def _prompt_payload_generation(self):
        """Interactive payload generation."""
        print("\nPayload Generation")
        print("=" * 40)
        
        # Search for payloads
        query = input("[?] Search payloads (e.g., linux, meterpreter, reverse_tcp): ").strip()
        results = search_msf_payloads(query) if query else list(METASPLOIT_PAYLOADS.items())
        
        if not results:
            print("No payloads found!")
            return
        
        print(f"\nFound {len(results)} matching payloads:")
        for i, (name, info) in enumerate(list(results.items())[:15], 1):
            print(f"  [{i}] {name} - {info.get('description', '')}")
        
        if len(results) > 15:
            print(f"  ... and {len(results) - 15} more")
        
        choice = input("\n[?] Select payload number (or name directly): ").strip()
        
        payload_name = None
        if choice.isdigit():
            idx = int(choice) - 1
            payload_list = list(results.items())
            if 0 <= idx < len(payload_list):
                payload_name = payload_list[idx][0]
        elif choice in results:
            payload_name = choice
        
        if not payload_name:
            print("Invalid selection.")
            return
        
        # Get options
        lhost = input("[?] LHOST (your IP): ").strip()
        if not lhost:
            lhost = "127.0.0.1"
        
        lport = input("[?] LPORT (default=4444): ").strip() or "4444"
        try:
            lport = int(lport)
        except ValueError:
            lport = 4444
        
        output = input("[?] Output path (default=/tmp/payload.bin): ").strip() or "/tmp/payload.bin"
        
        self.options["payload"] = {
            "name": payload_name,
            "lhost": lhost,
            "lport": lport,
            "output": output
        }

    def run(self):
        if not self.options.get("modules") and not self.options.get("payload"):
            self._prompt_options()
        
        # Handle payload generation if requested
        if self.options.get("payload"):
            return self._run_payload_generation()
        
        if not self.options.get("modules"):
            return self.results
        
        if not tool_check("msfconsole"):
            log("metasploit", "msfconsole not found", C.R)
            self.logger.tools_skipped.append("msfconsole (not installed)")
            self.logger.set_module_status("metasploit", "SKIPPED", "Metasploit not installed")
            self.logger.finding(
                "metasploit", "Metasploit unavailable",
                "Metasploit Framework is not installed", "INFO",
                "", "Install with: apt install metasploit-framework"
            )
            return self.results
        
        self.logger.tools_used.append("msfconsole")
        modules = self.options.get("modules", ["http_title", "smb_version"])
        timeout = self.options.get("timeout", 120)
        
        log("metasploit", f"Running {len(modules)} Metasploit modules on {self.target}", C.B)
        
        for module_name in modules:
            log("metasploit", f"Running: {module_name}", C.Y)
            
            result = run_metasploit_module(
                self.target, 
                module_name, 
                {"timeout": timeout}
            )
            
            self.logger.raw("metasploit", module_name, result.get("stdout", ""), 
                          result.get("stderr", ""), result.get("returncode", -1))
            
            if result["status"] == "ok":
                self.results["modules_run"].append(module_name)
                self._parse_results(module_name, result.get("stdout", ""))
                log("metasploit", f"  OK: {module_name}", C.G)
            else:
                log("metasploit", f"  {result['status'].upper()}: {module_name}", C.Y)
        
        # Set module status
        if self.results["modules_run"]:
            self.logger.set_module_status("metasploit", "SUCCESS", 
                                        f"Ran {len(self.results['modules_run'])} modules")
        else:
            self.logger.set_module_status("metasploit", "PARTIAL", "No modules completed successfully")
        
        log("metasploit", f"Metasploit scan complete. Ran {len(self.results['modules_run'])} modules.", C.G)
        return self.results

    def _run_payload_generation(self):
        """Generate a Metasploit payload using msfvenom."""
        payload_opts = self.options.get("payload", {})
        payload_name = payload_opts.get("name")
        lhost = payload_opts.get("lhost", "127.0.0.1")
        lport = payload_opts.get("lport", 4444)
        output = payload_opts.get("output", "/tmp/payload.bin")
        
        if not payload_name:
            log("metasploit", "No payload specified", C.R)
            return self.results
        
        if not tool_check("msfvenom"):
            log("metasploit", "msfvenom not found", C.R)
            self.logger.tools_skipped.append("msfvenom (not installed)")
            self.logger.set_module_status("metasploit", "SKIPPED", "msfvenom not installed")
            self.logger.finding(
                "metasploit", "msfvenom unavailable",
                "msfvenom is not installed", "INFO",
                "", "Install Metasploit Framework to generate payloads"
            )
            return self.results
        
        self.logger.tools_used.append("msfvenom")
        log("metasploit", f"Generating payload: {payload_name}", C.B)
        log("metasploit", f"LHOST: {lhost}, LPORT: {lport}", C.Y)
        
        result = generate_msf_payload(payload_name, lhost, lport, output)
        
        if result["status"] == "success":
            self.logger.set_module_status("metasploit", "SUCCESS", f"Generated {result.get('file_size', 0)} bytes")
            self.results["payloads_generated"].append({
                "name": payload_name,
                "output": result["output_path"],
                "size": result.get("file_size", 0)
            })
            self.logger.finding(
                "metasploit", "Payload generated",
                f"Generated {result.get('file_size', 0)} bytes at {result['output_path']}", "INFO",
                f"Command: {result.get('command', 'N/A')}",
                f"Payload: {payload_name} LHOST={lhost} LPORT={lport}"
            )
            log("metasploit", f"SUCCESS: Payload saved to {result['output_path']}", C.G)
            log("metasploit", f"Size: {result.get('file_size', 0)} bytes", C.G)
        else:
            self.logger.set_module_status("metasploit", "FAILED", "Payload generation failed")
            self.logger.finding(
                "metasploit", "Payload generation failed",
                result.get("error", "Unknown error"), "HIGH",
                "",
                "Check msfvenom installation and payload name"
            )
            log("metasploit", f"FAILED: {result.get('error', 'Unknown error')}", C.R)
        
        return self.results

    def _parse_results(self, module_name: str, output: str):
        """Parse Metasploit output and create findings."""
        lines = output.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            lower = line.lower()
            
            # Version info
            if "version" in lower and any(x in lower for x in ["smb", "ftp", "ssh", "http"]):
                self.results["services"].append(line)
                self.logger.finding(
                    "metasploit", f"Service detected via {module_name}",
                    line[:200], "INFO",
                    output[:500],
                    "Verify service version and apply updates."
                )
            
            # Vulnerabilities
            elif any(x in lower for x in ["vulnerability", "exploit", "cve", "vuln"]):
                self.logger.finding(
                    "metasploit", f"Vulnerability detected: {module_name}",
                    line[:200], "HIGH",
                    output[:500],
                    "Investigate and patch this vulnerability."
                )
                self.results["vulnerabilities"].append(line)
            
            # Open ports/services
            elif any(x in lower for x in ["open", "listening", "running"]) and "/" in line:
                self.results["services"].append(line)


#!/usr/bin/env python3
"""
GODS Module: portscan
Tools: nmap, python fallback
"""
import re
from utils.helpers import run_cmd, tool_check, is_port_open, C, log, has_os_detect_privs
from config.settings import TOOLS, TIMEOUTS, PORTSCAN_PRESETS, NMAP_TIMING

class PortScan:
    def __init__(self, target, logger, options=None):
        self.target = target
        self.logger = logger
        self.options = options or {}

    def _validate_ports(self, port_str):
        """Validate port input. Returns (ok, cleaned_string, message)."""
        port_str = port_str.strip()
        if not port_str:
            return False, None, "Empty input"

        if '-' in port_str:
            if ',' in port_str:
                return False, None, "Range cannot contain commas"
            parts = port_str.split('-')
            if len(parts) != 2:
                return False, None, "Invalid range format"
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError:
                return False, None, "Range must be numeric"
            if start < 1 or end > 65535:
                return False, None, "Ports must be between 1 and 65535"
            if start > end:
                return False, None, "Range start must be <= end"
            return True, port_str, "Valid range"

        ports = []
        for p in port_str.split(','):
            p = p.strip()
            if not p:
                return False, None, "Empty port in list (double comma)"
            try:
                port = int(p)
                if port < 1 or port > 65535:
                    return False, None, f"Port {port} out of range (1-65535)"
                ports.append(str(port))
            except ValueError:
                return False, None, f"Invalid port: {p}"
        return True, ','.join(ports), "Valid ports"

    def _prompt_options(self):
        print()
        print("Port Scan")
        print()
        print("[1] Common ports    (top 1000 TCP)")
        print("[2] Custom ports    (comma-separated, e.g. 22,80,443)")
        print("[3] Port range      (e.g. 1-1000)")
        print("[4] All TCP ports   (1-65535)")
        print()
        choice = input("[?] Select scan type: ").strip()

        mode = "common"
        custom_ports = None
        if choice == "2":
            mode = "custom"
            inp = input("[?] Enter ports: ").strip()
            ok, val, msg = self._validate_ports(inp)
            if ok:
                custom_ports = val
            else:
                log("portscan", f"Invalid port list ({msg}), using common", C.R)
                mode = "common"
                custom_ports = None
        elif choice == "3":
            mode = "range"
            inp = input("[?] Enter range: ").strip()
            ok, val, msg = self._validate_ports(inp)
            if ok:
                custom_ports = val
            else:
                log("portscan", f"Invalid range ({msg}), using common", C.R)
                mode = "common"
                custom_ports = None
        elif choice == "4":
            mode = "full"
        else:
            mode = "common"

        print()
        print("Additional options:")
        udp = input("[?] Include UDP scan? (y/N): ").strip().lower() == "y"
        sv = input("[?] Service/version detection? (Y/n): ").strip().lower() != "n"
        os_detect = input("[?] OS detection? (requires root) (y/N): ").strip().lower() == "y"

        print()
        print("Timing:")
        for k, v in NMAP_TIMING.items():
            print(f"  [{k}] {v}")
        timing = input("[?] Select timing (0-5, default=4): ").strip() or "4"
        if timing not in NMAP_TIMING:
            log("portscan", "Invalid timing, using T4", C.Y)
            timing = "4"

        self.options = {
            "mode": mode,
            "custom_ports": custom_ports,
            "timing": f"-T{timing}",
            "udp": udp,
            "service_detect": sv,
            "os_detect": os_detect,
        }
        print()

    def run(self):
        if not self.options or not self.options.get("mode"):
            self._prompt_options()

        mode = self.options.get("mode", "common")
        timing = self.options.get("timing", "-T4")
        udp = self.options.get("udp", False)
        sv = self.options.get("service_detect", True)
        os_detect = self.options.get("os_detect", False)
        custom_ports = self.options.get("custom_ports")

        log("portscan", f"Scanning {self.target} [{mode}]", C.B)
        results = {"open_ports": [], "services": [], "os_guess": None, "mode": mode, "method": "unknown"}
        used_external = False
        used_fallback = False

        if tool_check(TOOLS["nmap"]):
            self.logger.tools_used.append("nmap")
            used_external = True
            cmd_parts = [TOOLS["nmap"], timing]
            if sv:
                cmd_parts.append("-sV")

            if mode in PORTSCAN_PRESETS:
                preset = PORTSCAN_PRESETS[mode]
                base_args = preset["nmap_args"].split()
                filtered = []
                skip_next = False
                for i, arg in enumerate(base_args):
                    if skip_next:
                        skip_next = False
                        continue
                    if arg in ("-T0", "-T1", "-T2", "-T3", "-T4", "-T5"):
                        filtered.append(timing)
                    elif arg == "-sV" and not sv:
                        continue
                    else:
                        filtered.append(arg)
                        if arg == "--top-ports":
                            skip_next = True
                cmd_parts.extend(filtered)
            elif mode == "range" and custom_ports:
                cmd_parts.extend(["-p", custom_ports])
            elif mode == "custom" and custom_ports:
                cmd_parts.extend(["-p", custom_ports])
            else:
                cmd_parts.extend(["--top-ports", "1000"])

            cmd_parts.extend(["-oN", "-", self.target])
            timeout = TIMEOUTS.get(PORTSCAN_PRESETS.get(mode, {}).get("timeout_key", "nmap_quick"), TIMEOUTS["nmap_quick"])

            nmap_cmd = " ".join(cmd_parts)
            log("portscan", f"Running: {nmap_cmd}", C.Y)
            stdout, stderr, rc = run_cmd(cmd_parts, timeout=timeout)
            self.logger.raw("portscan", "nmap", stdout, stderr, rc)
            results["method"] = "nmap"
            results["open_ports"] = self._parse_nmap(stdout)
            results["services"] = self._parse_services(stdout)
            if rc != 0 and stderr:
                log("portscan", f"nmap stderr: {stderr[:200]}", C.R)

            if udp:
                log("portscan", "Running UDP scan", C.Y)
                udp_cmd = [TOOLS["nmap"], timing, "-sU", "--top-ports", "100", "-oN", "-", self.target]
                stdout_u, stderr_u, rc_u = run_cmd(udp_cmd, timeout=TIMEOUTS["nmap_quick"])
                self.logger.raw("portscan", "nmap-udp", stdout_u, stderr_u, rc_u)
                udp_results = self._parse_services(stdout_u, proto_default="udp")
                results["services"].extend(udp_results)
                for port, proto, state, service, version in udp_results:
                    results["open_ports"].append(port)

            if os_detect:
                if has_os_detect_privs():
                    log("portscan", "Running OS detection", C.Y)
                    os_cmd = [TOOLS["nmap"], "-O", self.target]
                    stdout2, stderr2, rc2 = run_cmd(os_cmd, timeout=TIMEOUTS["nmap_quick"])
                    self.logger.raw("portscan", "nmap-os", stdout2, stderr2, rc2)
                    results["os_guess"] = self._parse_os(stdout2)
                    if rc2 != 0:
                        log("portscan", "OS detection failed", C.Y)
                else:
                    log("portscan", "OS detection skipped (requires root privileges)", C.Y)
        else:
            log("portscan", "nmap not found, using Python fallback", C.Y)
            self.logger.tools_skipped.append("nmap (not installed)")
            results["method"] = "python-socket"
            results["open_ports"] = self._fallback_scan()
            used_fallback = True

        # Set module status based on results
        if results["services"] or results["open_ports"]:
            if used_external:
                self.logger.set_module_status("portscan", "SUCCESS", f"Found {len(results['open_ports'])} ports via nmap")
            else:
                self.logger.set_module_status("portscan", "PARTIAL", f"Found {len(results['open_ports'])} ports via Python fallback (nmap not available)")
        else:
            if used_external:
                self.logger.set_module_status("portscan", "PARTIAL", "nmap scan completed but no open ports found")
            else:
                self.logger.set_module_status("portscan", "PARTIAL", "Python fallback scan completed but no open ports found")

        for port, proto, state, service, version in results["services"]:
            sev = "INFO"
            if port == 3389:
                sev = "HIGH"
            elif port in [3306, 5432, 1433, 27017, 6379, 9200]:
                sev = "MEDIUM"
            elif port in [21, 23, 25, 110, 143]:
                sev = "LOW"
            evidence_source = "nmap" if used_external else "python-socket"
            self.logger.finding(
                "portscan", f"Port {port}/{proto} {state}",
                f"Service: {service} {version}", sev,
                f"{evidence_source}: {port}/{proto} {state} {service} {version}",
                "Review if this service needs to be exposed to the internet."
            )

        if results["os_guess"]:
            self.logger.finding("portscan", "OS Detection", f"nmap guessed: {results['os_guess']}",
                "INFO", results["os_guess"], "OS info helps attackers target exploits. Keep services patched.")

        log("portscan", f"Done. {len(results['open_ports'])} open ports found.", C.G)
        return results

    def _parse_nmap(self, stdout):
        ports = []
        for line in stdout.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$", line.strip())
            if m:
                ports.append(int(m.group(1)))
        return ports

    def _parse_services(self, stdout, proto_default="tcp"):
        services = []
        for line in stdout.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s+(.*)$", line.strip())
            if m:
                services.append((int(m.group(1)), m.group(2), m.group(3), m.group(4), m.group(5).strip()))
            else:
                m2 = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)$", line.strip())
                if m2:
                    services.append((int(m2.group(1)), m2.group(2), m2.group(3), m2.group(4), ""))
        return services

    def _parse_os(self, stdout):
        for line in stdout.splitlines():
            if "OS details:" in line:
                return line.split(":", 1)[1].strip()
            if "Running:" in line:
                return line.split(":", 1)[1].strip()
        return None

    def _fallback_scan(self):
        """Python fallback using socket-based TCP connect scan."""
        log("portscan", "Python fallback: scanning common ports", C.Y)
        common = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443]
        open_ports = []
        for p in common:
            if is_port_open(self.target, p):
                open_ports.append(p)
        return open_ports

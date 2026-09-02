#!/usr/bin/env python3
"""
GODS Recon Intelligence Engine — Structured Logger
"""
import json
import os
import tempfile
import shutil
from datetime import datetime
from utils.helpers import C, sev_rank, safe_filename, RICH_AVAILABLE, console

# Absolute path to project root (where the recon folder is located)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class ReconLogger:
    def __init__(self, target, outdir="reports"):
        self.target = target
        # Use absolute path based on project root, not current working directory
        self.outdir = os.path.join(PROJECT_ROOT, outdir)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.raw_log = []
        self.findings = []
        self.tools_used = []
        self.tools_skipped = []
        self.module_status = {}
        # Track which modules ran (internal modules)
        self.modules_run = []
        os.makedirs(self.outdir, exist_ok=True)

    def raw(self, module, tool, stdout, stderr="", rc=0):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "tool": tool,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": rc
        }
        self.raw_log.append(entry)

    def set_module_status(self, module, status, reason=""):
        """Record the final status of a requested module."""
        entry = status.upper()
        self.module_status[module] = {"status": entry, "reason": reason}

    def finding(self, module, title, description, severity="INFO", evidence="", remediation=""):
        finding = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "title": title,
            "description": description,
            "severity": severity.upper(),
            "severity_rank": sev_rank(severity),
            "evidence": evidence,
            "remediation": remediation
        }
        # Prevent duplicate observations from being emitted by multiple protocol
        # checks or execution paths. Keep distinct evidence as separate findings.
        duplicate_key = (
            module, finding["title"], finding["description"],
            finding["severity"], finding["evidence"], finding["remediation"]
        )
        for existing in self.findings:
            existing_key = (
                existing.get("module"), existing.get("title"), existing.get("description"),
                existing.get("severity"), existing.get("evidence", ""), existing.get("remediation", "")
            )
            if existing_key == duplicate_key:
                return existing

        self.findings.append(finding)
        
        # Output with rich if available, otherwise use ANSI colors
        if RICH_AVAILABLE:
            color_map = {
                "CRITICAL": "red",
                "HIGH": "magenta",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim",
            }
            rich_color = color_map.get(severity.upper(), "white")
            console.print(f"  [{rich_color}]{severity.upper():8}[/{rich_color}] [cyan]{module:12}[/cyan] -> {title}")
        else:
            color = {
                "CRITICAL": C.R, "HIGH": C.M, "MEDIUM": C.Y,
                "LOW": C.CYAN, "INFO": C.D
            }.get(severity.upper(), C.W)
            print(f"  {color}[{severity.upper():8}]{C.X} {module:12} -> {title}")

    def save_raw(self):
        """Save raw log with atomic write (temp file + rename)."""
        filename = f"{safe_filename(self.target)}_{self.session_id}_raw.json"
        path = os.path.join(self.outdir, filename)
        # Atomic write: write to temp file first, then rename
        fd, tmp_path = tempfile.mkstemp(dir=self.outdir, prefix=f'.{filename}.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.raw_log, f, indent=2)
            shutil.move(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return path

    def save_findings(self):
        """Save findings with atomic write (temp file + rename)."""
        filename = f"{safe_filename(self.target)}_{self.session_id}_findings.json"
        path = os.path.join(self.outdir, filename)
        # Atomic write: write to temp file first, then rename
        fd, tmp_path = tempfile.mkstemp(dir=self.outdir, prefix=f'.{filename}.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.findings, f, indent=2)
            shutil.move(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return path

    def get_summary(self):
        """Return a dict summarizing the scan."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "target": self.target,
            "session": self.session_id,
            "findings": len(self.findings),
            "severity_counts": counts,
            "modules_run": self.modules_run,
            "tools_used": self.tools_used,
            "tools_skipped": self.tools_skipped,
            "module_status": self.module_status,
        }

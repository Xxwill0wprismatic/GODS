#!/usr/bin/env python3
"""
GODS Engine: reporter
Generates plain-text, JSON, and HTML reports.
"""
import os
import json
import html as html_module
import tempfile
import shutil
from datetime import datetime
from utils.helpers import C, log, sev_color, safe_filename
from config.settings import RECON_VERSION

# Absolute path to project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Reporter:
    def __init__(self, target, findings, raw_files, outdir="reports", tools_used=None, tools_skipped=None, session=None, module_status=None, modules_run=None, html_source=None):
        self.target = target
        self.findings = sorted(findings, key=lambda x: (-x.get("severity_rank", 0), x.get("module", "")))
        self.raw_files = raw_files
        # Use absolute path based on project root
        self.outdir = os.path.join(PROJECT_ROOT, outdir)
        self.tools_used = tools_used or []
        self.tools_skipped = tools_skipped or []
        self.module_status = module_status or {}
        self.modules_run = modules_run or []  # Internal modules that ran
        self.html_source = html_source  # Actual HTML source code of target website
        os.makedirs(self.outdir, exist_ok=True)
        self.session = session or datetime.now().strftime("%Y%m%d_%H%M%S")

    def run(self):
        log("REPORTER", "Generating reports...", C.B)
        
        # Save HTML source code if available
        html_source_path = self._save_html_source()
        
        # Generate all three report formats
        txt_path = self._text_report()
        json_path = self._json_report()
        html_path = self._html_report()
        
        # Verify all files exist
        errors = []
        for name, path in [("TXT", txt_path), ("JSON", json_path), ("HTML", html_path)]:
            if not os.path.exists(path):
                errors.append(f"{name} report not found at {path}")
            elif os.path.getsize(path) == 0:
                errors.append(f"{name} report is empty at {path}")
        
        if errors:
            for err in errors:
                log("REPORTER", err, C.R)
            raise RuntimeError(f"Report generation failed: {'; '.join(errors)}")
        
        # Validate consistency
        self._validate_consistency(json_path, html_path)
        
        log("REPORTER", f"TXT:  {txt_path}", C.G)
        log("REPORTER", f"JSON: {json_path}", C.G)
        log("REPORTER", f"HTML: {html_path}", C.G)
        if html_source_path:
            log("REPORTER", f"SOURCE: {html_source_path}", C.G)
        
        return {"txt": txt_path, "json": json_path, "html": html_path, "html_source": html_source_path}

    def _save_html_source(self):
        """Save the actual HTML source code of the target website."""
        if not self.html_source:
            return None
        
        filename = f"{safe_filename(self.target)}_{self.session}_source.html"
        path = os.path.join(self.outdir, filename)
        self._atomic_write(path, self.html_source)
        return path

    def _atomic_write(self, path, content):
        """Atomically write content to a file using temp file + rename."""
        filename = os.path.basename(path)
        # Create temp file in same directory for atomic rename
        fd, tmp_path = tempfile.mkstemp(dir=self.outdir, prefix=f'.{filename}.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            shutil.move(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _validate_consistency(self, json_path, html_path):
        """Validate that JSON and HTML contain consistent data."""
        try:
            with open(json_path, 'r') as f:
                json_data = json.load(f)
            
            # Check severity counts match
            json_counts = json_data.get('severity_counts', {})
            
            # Parse HTML to extract severity counts from findings table only
            with open(html_path, 'r') as f:
                html_content = f.read()
            
            # Count severity labels in the findings table (not in summary boxes)
            # The findings are in <tr> with severity in first <td>
            import re
            # Find all severity labels in table rows
            html_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            # Look for pattern like: <td style="color:#ff4444;font-weight:bold;padding:8px;">CRITICAL</td>
            for sev in html_severity_counts:
                pattern = rf'<td[^>]*color:[^"]*{["#ff4444","#ff8800","#ffcc00","#00aaff","#888888"][["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(sev)]}[^>]*>[{sev[0]}{sev[1:].lower()}][^<]*</td>'
                # Simpler approach: count occurrences in table rows
                html_severity_counts[sev] = html_content.count(f">{sev}</td>")
            
            # Verify counts match
            all_match = True
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                json_count = json_counts.get(sev, 0)
                html_count = html_severity_counts[sev]
                if json_count != html_count:
                    log("REPORTER", f"WARNING: {sev} count mismatch JSON={json_count} HTML={html_count}", C.Y)
                    all_match = False
            
            # Verify findings count matches - count table data rows
            json_findings_count = len(json_data.get('findings', []))
            # Count rows that start with severity colored text (finding rows)
            html_findings_count = html_content.count("<tr style=\"border-bottom:1px solid #333;\">")
            if json_findings_count != html_findings_count:
                log("REPORTER", f"WARNING: Findings count mismatch JSON={json_findings_count} HTML={html_findings_count}", C.Y)
                all_match = False
            
            if all_match:
                log("REPORTER", "Report consistency validation passed", C.G)
            else:
                log("REPORTER", "Report consistency validation complete (see warnings above)", C.Y)
        except Exception as e:
            log("REPORTER", f"Validation warning: {e}", C.Y)

    def _text_report(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

        by_module = {}
        for f in self.findings:
            mod = f.get("module", "unknown")
            by_module.setdefault(mod, []).append(f)

        sections = []
        sections.append("GODS RECON REPORT")
        sections.append("=" * 50)
        sections.append("")
        sections.append("TARGET INFORMATION")
        sections.append(f"  Target  : {self.target}")
        sections.append(f"  Session : {self.session}")
        sections.append(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        sections.append("")
        
        sections.append("SEVERITY SUMMARY")
        sections.append(f"  CRITICAL : {counts['CRITICAL']}")
        sections.append(f"  HIGH     : {counts['HIGH']}")
        sections.append(f"  MEDIUM   : {counts['MEDIUM']}")
        sections.append(f"  LOW      : {counts['LOW']}")
        sections.append(f"  INFO     : {counts['INFO']}")
        sections.append("")
        
        sections.append("ENGINE/INTERNAL MODULES RUN")
        if self.modules_run:
            for m in sorted(self.modules_run):
                status_info = self.module_status.get(m, {})
                status = status_info.get('status', 'UNKNOWN')
                sections.append(f"  + {m}: {status}")
        else:
            sections.append("  (none)")
        sections.append("")
        
        sections.append("EXTERNAL TOOLS USED")
        if self.tools_used:
            for t in self.tools_used:
                sections.append(f"  + {t}")
        else:
            sections.append("  (none)")
        sections.append("")
        
        sections.append("MODULE STATUS")
        for mod in sorted(self.module_status):
            info = self.module_status[mod]
            line = f"  {mod:18} {info.get('status','UNKNOWN')}"
            if info.get("reason"):
                line += f" — {info['reason']}"
            sections.append(line)
        sections.append("")
        
        sections.append("TOOLS SKIPPED")
        if self.tools_skipped:
            for t in self.tools_skipped:
                sections.append(f"  - {t}")
        else:
            sections.append("  (none)")
        sections.append("")
        
        sections.append("SECURITY FINDINGS")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in self.findings if f.get("severity") == sev]
            if sev_findings:
                sections.append(f"  [{sev}]")
                for f in sev_findings:
                    sections.append(f"    {f.get('module','unknown'):12} {f.get('title','')}")
                    desc = f.get('description', '')
                    if desc:
                        sections.append(f"      Desc: {desc}")
                    ev = f.get('evidence', '')
                    if ev:
                        sections.append(f"      Evidence: {ev}")
                    if f.get("remediation"):
                        sections.append(f"      Fix:  {f.get('remediation','')}")
                    sections.append("")
        
        sections.append("RECOMMENDATIONS")
        seen_recs = set()
        for f in self.findings:
            rec = f.get("remediation", "")
            if rec and rec not in seen_recs and f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                seen_recs.add(rec)
                sections.append(f"  [{f['severity']}] {rec}")
        
        sections.append("")
        sections.append("RAW DATA FILES")
        for rf in self.raw_files:
            sections.append(f"  {os.path.basename(rf)}")
        sections.append("")
        
        sections.append("=" * 50)
        sections.append(f"Generated by GODS Recon Intelligence Engine {RECON_VERSION}")
        
        report_body = "\n".join(sections)
        
        filename = f"{safe_filename(self.target)}_{self.session}_report.txt"
        path = os.path.join(self.outdir, filename)
        self._atomic_write(path, report_body)
        return path

    def _json_report(self):
        filename = f"{safe_filename(self.target)}_{self.session}_report.json"
        path = os.path.join(self.outdir, filename)
        data = {
            "target": self.target,
            "session": self.session,
            "date": datetime.now().isoformat(),
            "version": RECON_VERSION,
            "findings": self.findings,
            "raw_files": [os.path.basename(rf) for rf in self.raw_files],
            "internal_modules_run": self.modules_run,
            "external_tools_used": self.tools_used,
            "tools_skipped": self.tools_skipped,
            "severity_counts": {sev: 0 for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "modules": sorted(set(f.get("module", "unknown") for f in self.findings)),
            "module_status": self.module_status,
            "html_source_file": f"{safe_filename(self.target)}_{self.session}_source.html" if self.html_source else None,
            "html_source_size": len(self.html_source) if self.html_source else 0,
        }
        for f in self.findings:
            sev = f.get("severity", "INFO")
            data["severity_counts"][sev] = data["severity_counts"].get(sev, 0) + 1
        
        content = json.dumps(data, indent=2)
        self._atomic_write(path, content)
        return path

    def _html_report(self):
        filename = f"{safe_filename(self.target)}_{self.session}_report.html"
        path = os.path.join(self.outdir, filename)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

        colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#00aaff", "INFO": "#888888"}

        rows = ""
        for f in self.findings:
            sev = f.get("severity", "INFO")
            title = html_module.escape(f.get('title', ''))
            module = html_module.escape(f.get('module', ''))
            description = html_module.escape(f.get('description', ''))
            evidence = html_module.escape(str(f.get('evidence', '')))
            remediation = html_module.escape(str(f.get('remediation', '')))
            
            # Handle empty evidence with placeholder
            if not evidence or evidence == 'None':
                evidence = "<em style='color:#666'>No evidence available</em>"
            
            # Handle empty remediation with placeholder
            if not remediation or remediation == 'None':
                remediation = "<em style='color:#666'>No recommendation</em>"
            
            rows += f"""<tr style="border-bottom:1px solid #333;">
<td style="color:{colors.get(sev,'#fff')};font-weight:bold;padding:8px;">{sev}</td>
<td style="padding:8px;">{module}</td>
<td style="padding:8px;">{title}</td>
<td style="padding:8px;max-width:300px;word-wrap:break-word;">{description}</td>
<td style="padding:8px;max-width:250px;word-wrap:break-word;font-size:0.85em;color:#aaa;">{evidence}</td>
<td style="padding:8px;max-width:250px;word-wrap:break-word;color:#66ff66;font-size:0.85em;">{remediation}</td>
</tr>"""

        # Internal modules
        modules_run_html = ""
        if self.modules_run:
            for m in sorted(self.modules_run):
                status_info = self.module_status.get(m, {})
                status = status_info.get('status', 'UNKNOWN')
                modules_run_html += f"<li><b>{html_module.escape(m)}</b>: {html_module.escape(status)}</li>"
        else:
            modules_run_html = "<li>(none)</li>"
        
        # External tools used
        tools_used_html = ""
        if self.tools_used:
            for t in self.tools_used:
                tools_used_html += f"<li>{html_module.escape(t)}</li>"
        else:
            tools_used_html = "<li>(none)</li>"
        
        # Tools skipped
        tools_skipped_html = ""
        if self.tools_skipped:
            for t in self.tools_skipped:
                tools_skipped_html += f"<li>{html_module.escape(t)}</li>"
        else:
            tools_skipped_html = "<li>(none)</li>"
        
        # Module status rows
        module_status_rows = ""
        for m, v in sorted(self.module_status.items()):
            status = v.get('status', 'UNKNOWN')
            reason = html_module.escape(v.get('reason', ''))
            # Color code status
            status_color = "#4CAF50" if status == "SUCCESS" else "#FFC107" if status == "PARTIAL" else "#F44336" if status == "FAILED" else "#888888"
            module_status_rows += f"<tr><td>{html_module.escape(m)}</td><td style='color:{status_color}'>{html_module.escape(status)}</td><td>{reason}</td></tr>"
        
        # Raw files
        raw_files_html = ""
        for rf in self.raw_files:
            raw_files_html += f"<li>{html_module.escape(os.path.basename(rf))}</li>"
        
        # HTML Source Code section
        html_source_section = ""
        if self.html_source:
            # Escape the HTML source for display
            escaped_source = html_module.escape(self.html_source)
            source_file = f"{safe_filename(self.target)}_{self.session}_source.html"
            html_source_section = f"""
<h2>🌐 Target Website HTML Source Code</h2>
<div style="background:#161b22;padding:10px;border-radius:6px;margin:10px 0;">
<p><b>Source File:</b> <a href="{source_file}" style="color:#58a6ff;">{source_file}</a></p>
<p><b>Size:</b> {len(self.html_source):,} bytes</p>
</div>
<h3>HTML Source Preview (first 5000 chars):</h3>
<pre style="background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:15px;overflow-x:auto;max-height:400px;font-family:monospace;font-size:12px;white-space:pre-wrap;word-wrap:break-word;color:#e6edf3;">{escaped_source[:5000]}</pre>
"""
        
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        target_escaped = html_module.escape(self.target)
        session_escaped = html_module.escape(self.session)
        modules_str = html_module.escape(', '.join(sorted(set(f.get('module','unknown') for f in self.findings))))

        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>GODS Report - {target_escaped}</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;margin:0;padding:20px;}}
.container{{max-width:1400px;margin:0 auto;}}
h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px;}}
h2{{color:#8b949e;border-bottom:1px solid #30363d;padding-bottom:5px;margin-top:25px;}}
h3{{color:#c9d1d9;margin-top:20px;}}
.summary{{background:#161b22;padding:15px;border-radius:6px;border-left:4px solid #58a6ff;margin:15px 0;}}
.summary b{{color:#58a6ff;}}
table{{width:100%;border-collapse:collapse;margin:10px 0;}}
th{{background:#21262d;padding:12px;text-align:left;border-bottom:2px solid #30363d;color:#c9d1d9;}}
td{{padding:10px;border-bottom:1px solid #30363d;vertical-align:top;}}
tr:hover{{background:#161b22;}}
ul{{list-style:none;padding-left:10px;}}
ul li{{padding:3px 0;}}
ul li::before{{content:"•";color:#58a6ff;margin-right:8px;}}
.severity-box{{display:inline-block;padding:8px 16px;margin:5px;border-radius:4px;text-align:center;min-width:80px;}}
.critical{{background:#ff444433;color:#ff4444;}}
.high{{background:#ff880033;color:#ff8800;}}
.medium{{background:#ffcc0033;color:#ffcc00;}}
.low{{background:#00aaff33;color:#00aaff;}}
.info{{background:#88888833;color:#888888;}}
.footer{{margin-top:40px;padding-top:20px;border-top:1px solid #30363d;color:#8b949e;text-align:center;}}
.scroll-cell{{max-width:300px;max-height:150px;overflow:auto;word-wrap:break-word;}}
.scroll-cell::-webkit-scrollbar{{width:6px;height:6px;}}
.scroll-cell::-webkit-scrollbar-track{{background:#21262d;}}
.scroll-cell::-webkit-scrollbar-thumb{{background:#484f58;border-radius:3px;}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.8em;}}
.badge-success{{background:#238636;color:#fff;}}
.badge-warning{{background:#9e6a03;color:#fff;}}
.badge-danger{{background:#da3633;color:#fff;}}
.badge-info{{background:#1f6feb;color:#fff;}}
pre{{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:15px;overflow-x:auto;}}
</style>
</head><body>
<div class="container">
<h1>🔍 GODS Recon Report</h1>
<div class="summary">
<b>Target:</b> {target_escaped}<br>
<b>Session:</b> {session_escaped}<br>
<b>Date:</b> {report_date}<br>
<b>Engine Version:</b> {RECON_VERSION}
</div>

<h2>📊 Severity Summary</h2>
<div>
<span class="severity-box critical">CRITICAL<br><b>{counts['CRITICAL']}</b></span>
<span class="severity-box high">HIGH<br><b>{counts['HIGH']}</b></span>
<span class="severity-box medium">MEDIUM<br><b>{counts['MEDIUM']}</b></span>
<span class="severity-box low">LOW<br><b>{counts['LOW']}</b></span>
<span class="severity-box info">INFO<br><b>{counts['INFO']}</b></span>
</div>

<h2>⚙️ Engine/Internal Modules</h2>
<ul>{modules_run_html}</ul>

<h2>🔧 External Tools Used</h2>
<ul>{tools_used_html}</ul>

<h2>⏭️ Tools Skipped</h2>
<ul>{tools_skipped_html}</ul>

<h2>📋 Module Status</h2>
<table>
<tr><th style="width:150px;">Module</th><th style="width:100px;">Status</th><th>Reason</th></tr>
{module_status_rows if module_status_rows else '<tr><td colspan="3">(no modules run)</td></tr>'}
</table>

<h2>🔍 Security Findings ({len(self.findings)})</h2>
<table>
<tr><th style="width:80px;">Severity</th><th style="width:100px;">Module</th><th style="width:180px;">Title</th><th>Description</th><th style="width:200px;">Evidence</th><th style="width:180px;">Remediation</th></tr>
{rows if rows else '<tr><td colspan="6" style="text-align:center;color:#888;">No findings</td></tr>'}
</table>

<h2>📁 Raw Data Files</h2>
<ul>{raw_files_html if raw_files_html else '<li>(none)</li>'}</ul>

{html_source_section}

<div class="footer">
Generated by GODS Recon Intelligence Engine {RECON_VERSION}
</div>
</div>
</body></html>"""

        self._atomic_write(path, html)
        return path

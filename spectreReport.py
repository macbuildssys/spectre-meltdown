#!/usr/bin/env python3
"""
spectre-report: Parse spectre-meltdown-checker output and generate an HTML report.

Usage:
    sudo spectre-meltdown-checker --no-color > checker_output.txt
    python3 spectreReport.py --input checker_output.txt --output spectreReport.html

    # Pipe directly:
    sudo spectre-meltdown-checker --no-color | python3 spectreReport.py --output spectreReport.html

    # Run the checker from the script (requires root):
    sudo python3 spectreReport.py --run --output spectreReport.html
"""

import re
import sys
import argparse
import subprocess
import socket
import platform
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


STATUS_VULNERABLE   = "VULNERABLE"
STATUS_OK           = "OK"
STATUS_NOT_AFFECTED = "NOT AFFECTED"
STATUS_UNKNOWN      = "UNKNOWN"

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# CVE header:  CVE-2017-5753 aka 'Spectre Variant 1, bounds check bypass'
CVE_HEADER_RE = re.compile(r"^(CVE-\d{4}-\d{4,7})\s+aka\s+'(.+)'")

# Status line: > STATUS: NOT VULNERABLE (reason) or > STATUS: VULNERABLE (reason)
STATUS_LINE_RE = re.compile(r"^>?\s*STATUS:\s*(.*)", re.IGNORECASE)

# Compact summary: > SUMMARY: CVE-XXXX:OK CVE-YYYY:VULNERABLE ...
SUMMARY_LINE_RE = re.compile(r"^>?\s*SUMMARY:\s*(.*)", re.IGNORECASE)
SUMMARY_PAIR_RE = re.compile(r"(CVE-\d{4}-\d{4,7}):(\S+)")

GOOD_KEYWORDS = re.compile(
    r"\b(mitigat|not affected|not vulnerable|protected|retpoline|ibrs|ibpb"
    r"|stibp|ssbd|enabled|patched|sanitization|prctl|flush)\b",
    re.IGNORECASE,
)
BAD_KEYWORDS = re.compile(
    r"\b(vulnerable|exploit|no\s+microcode|missing|disabled|weak|insufficient)\b",
    re.IGNORECASE,
)


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


@dataclass
class MitigationLine:
    text: str
    is_good: bool
    is_bad: bool
    is_info: bool


@dataclass
class CVEEntry:
    cve_id: str
    alias: str
    status: str
    status_reason: str
    mitigations: list[MitigationLine] = field(default_factory=list)


@dataclass
class ParsedReport:
    cves: list[CVEEntry] = field(default_factory=list)
    system_info: list[str] = field(default_factory=list)
    hardware_lines: list[str] = field(default_factory=list)
    summary_lines: list[str] = field(default_factory=list)
    hostname: str = ""
    scan_time: str = ""
    checker_version: str = ""
    kernel: str = ""
    cpu: str = ""


def classify_mitigation(line: str) -> MitigationLine:
    is_good = bool(GOOD_KEYWORDS.search(line))
    is_bad  = bool(BAD_KEYWORDS.search(line))
    is_info = not is_good and not is_bad
    return MitigationLine(text=line, is_good=is_good, is_bad=is_bad, is_info=is_info)


def resolve_status(status_text: str) -> tuple[str, str]:
    """Parse "> STATUS: NOT VULNERABLE (reason)" into (STATUS_*, reason)."""
    upper = status_text.upper()
    if "NOT VULNERABLE" in upper:
        reason = re.sub(r"NOT VULNERABLE\s*", "", status_text, flags=re.IGNORECASE).strip("() ")
        return STATUS_OK, reason
    if "NOT AFFECTED" in upper:
        reason = re.sub(r"NOT AFFECTED\s*", "", status_text, flags=re.IGNORECASE).strip("() ")
        return STATUS_NOT_AFFECTED, reason
    if "VULNERABLE" in upper:
        reason = re.sub(r"VULNERABLE\s*", "", status_text, flags=re.IGNORECASE).strip("() ")
        return STATUS_VULNERABLE, reason
    return STATUS_UNKNOWN, status_text.strip()


def parse_output(raw: str) -> ParsedReport:
    report = ParsedReport(
        hostname=socket.gethostname(),
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    lines = [strip_ansi(l) for l in raw.splitlines()]

    current_cve: Optional[CVEEntry] = None
    in_hardware = False

    for line in lines:
        stripped = line.strip()
        # Strip leading "> " prompt used by the checker on status/summary lines
        clean = stripped.lstrip(">").strip()

        # Compact summary line — parse CVE:STATUS pairs
        sm = SUMMARY_LINE_RE.match(stripped)
        if sm:
            for pair in SUMMARY_PAIR_RE.finditer(sm.group(1)):
                report.summary_lines.append(f"{pair.group(1)} [{pair.group(2)}]")
            continue

        # Checker version
        if "spectre-meltdown-checker" in clean.lower() and "tool" in clean.lower():
            report.checker_version = clean
            continue

        # Kernel line
        if clean.startswith("Kernel is Linux") or clean.startswith("Kernel is "):
            report.kernel = clean.replace("Kernel is ", "").strip()
            continue

        # CPU line
        if clean.startswith("CPU is "):
            report.cpu = clean.replace("CPU is ", "").strip()
            continue

        # Hardware check section boundary
        if clean == "Hardware check":
            in_hardware = True
            current_cve = None
            continue

        # CVE header line: "CVE-XXXX-XXXXX aka 'description'"
        m = CVE_HEADER_RE.match(clean)
        if m:
            in_hardware = False
            current_cve = CVEEntry(
                cve_id=m.group(1),
                alias=m.group(2),
                status=STATUS_UNKNOWN,
                status_reason="",
            )
            report.cves.append(current_cve)
            continue

        # Status line belonging to the current CVE: "> STATUS: NOT VULNERABLE (...)"
        sm2 = STATUS_LINE_RE.match(clean)
        if sm2 and current_cve is not None:
            status, reason = resolve_status(sm2.group(1))
            current_cve.status = status
            current_cve.status_reason = reason
            continue

        # Hardware section detail lines
        if in_hardware and clean.startswith("*"):
            detail = clean.lstrip("* ").strip()
            report.hardware_lines.append(detail)
            continue

        # Mitigation/detail lines inside a CVE block
        if current_cve is not None and (clean.startswith("*") or clean.startswith(">")):
            detail = clean.lstrip("*> ").strip()
            if detail and not STATUS_LINE_RE.match(clean):
                mit = classify_mitigation(detail)
                current_cve.mitigations.append(mit)
            continue

    return report


def status_badge(status: str) -> tuple[str, str]:
    return {
        STATUS_VULNERABLE:   ("badge-vuln",        "VULNERABLE"),
        STATUS_OK:           ("badge-ok",           "OK"),
        STATUS_NOT_AFFECTED: ("badge-not-affected", "NOT AFFECTED"),
        STATUS_UNKNOWN:      ("badge-unknown",      "UNKNOWN"),
    }.get(status, ("badge-unknown", status))


def counts(report: ParsedReport) -> dict[str, int]:
    c = {STATUS_VULNERABLE: 0, STATUS_OK: 0, STATUS_NOT_AFFECTED: 0, STATUS_UNKNOWN: 0}
    for cve in report.cves:
        c[cve.status] = c.get(cve.status, 0) + 1
    return c


def render_html(report: ParsedReport) -> str:
    c = counts(report)
    total      = sum(c.values())
    vuln_count = c[STATUS_VULNERABLE]

    overall_class = "status-critical" if vuln_count > 0 else "status-clean"
    overall_label = f"{vuln_count} VULNERABLE" if vuln_count > 0 else "FULLY PATCHED"

    cve_cards = ""
    for cve in report.cves:
        css_class, label = status_badge(cve.status)

        mit_html = ""
        if cve.mitigations:
            rows = ""
            for mit in cve.mitigations:
                mit_cls = "mit-good" if mit.is_good else ("mit-bad" if mit.is_bad else "mit-info")
                icon    = "✓" if mit.is_good else ("✗" if mit.is_bad else "·")
                rows += (
                    f'<div class="mit-row {mit_cls}">'
                    f'<span class="mit-icon">{icon}</span>'
                    f'<span>{mit.text}</span></div>\n'
                )
            mit_html = f'<div class="mitigations">{rows}</div>'

        reason_html = (
            f'<p class="cve-reason">{cve.status_reason}</p>'
            if cve.status_reason else ""
        )

        cve_cards += f"""
<div class="cve-card {css_class}">
  <div class="cve-header">
    <span class="cve-id">{cve.cve_id}</span>
    <span class="badge {css_class}">{label}</span>
    <span class="cve-alias">{cve.alias}</span>
  </div>
  {reason_html}
  {mit_html}
</div>"""

    hw_html = ""
    if report.hardware_lines:
        items = "".join(f"<li>{l}</li>" for l in report.hardware_lines)
        hw_html = f"""
<details class="hw-section">
  <summary>Hardware Check Details</summary>
  <ul class="hw-list">{items}</ul>
</details>"""

    summary_html = ""
    if report.summary_lines:
        rows = ""
        for line in report.summary_lines:
            m = re.match(r"^(CVE-\d{4}-\d{4,7})\s+\[([^\]]+)\]", line)
            if m:
                cid, st = m.group(1), m.group(2)
                cls = "sum-vuln" if "VULNERABLE" in st.upper() else "sum-ok"
                rows += f'<tr class="{cls}"><td>{cid}</td><td>[{st}]</td></tr>'
        if rows:
            summary_html = f"""
<section class="summary-section">
  <h2>Summary</h2>
  <table class="summary-table">
    <thead><tr><th>CVE</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""

    checker_span = f'<span>{report.checker_version}</span>' if report.checker_version else ""
    kernel_span  = f'<span>Kernel: {report.kernel}</span>' if report.kernel else f'<span>Kernel: {platform.release()}</span>'
    cpu_span     = f'<span>CPU: {report.cpu}</span>' if report.cpu else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Spectre/Meltdown Report — {report.hostname}</title>
<style>
:root {{
  --bg:        #0d0f14;
  --bg2:       #131720;
  --bg3:       #1b2030;
  --border:    #2a3148;
  --accent:    #4f8ef7;
  --text:      #c8d0e8;
  --muted:     #5a6485;
  --vuln:      #e05252;
  --vuln-bg:   #2a1414;
  --vuln-dim:  #5a2020;
  --ok:        #3fcf6e;
  --ok-bg:     #0f2a1a;
  --ok-dim:    #1a4a2a;
  --na:        #4fa8e0;
  --na-bg:     #0f1e2a;
  --na-dim:    #1a3a5a;
  --unk:       #c8a040;
  --unk-bg:    #2a2010;
  --unk-dim:   #4a3a10;
  --font-mono: 'IBM Plex Mono', 'JetBrains Mono', 'Fira Code', monospace;
  --font-ui:   'Inter', 'DM Sans', system-ui, sans-serif;
  --radius:    6px;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-ui);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}}

.page-header {{
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 32px 48px 24px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}}
.page-header h1 {{
  font-family: var(--font-mono);
  font-size: 22px;
  font-weight: 600;
  color: #fff;
  letter-spacing: -0.5px;
}}
.page-header .meta {{
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted);
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}}

.overall-banner {{
  margin: 32px 48px 0;
  padding: 20px 28px;
  border-radius: var(--radius);
  display: flex;
  align-items: center;
  gap: 16px;
  font-family: var(--font-mono);
}}
.status-critical {{ background: var(--vuln-bg); border: 1px solid var(--vuln-dim); }}
.status-critical .overall-label {{ color: var(--vuln); font-size: 18px; font-weight: 700; letter-spacing: 1px; }}
.status-clean    {{ background: var(--ok-bg);   border: 1px solid var(--ok-dim);   }}
.status-clean .overall-label    {{ color: var(--ok);   font-size: 18px; font-weight: 700; letter-spacing: 1px; }}

.overall-dot {{
  width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0;
}}
.status-critical .overall-dot {{ background: var(--vuln); box-shadow: 0 0 8px var(--vuln); animation: pulse 2s infinite; }}
.status-clean .overall-dot    {{ background: var(--ok);   box-shadow: 0 0 8px var(--ok); }}

@keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.4; }} }}

.stats-bar {{
  display: flex; gap: 16px; padding: 24px 48px; flex-wrap: wrap;
}}
.stat-chip {{
  padding: 10px 20px; border-radius: var(--radius);
  font-family: var(--font-mono); font-size: 13px;
  display: flex; flex-direction: column; gap: 2px;
  border: 1px solid transparent; min-width: 120px;
}}
.stat-chip .stat-num   {{ font-size: 28px; font-weight: 700; line-height: 1; }}
.stat-chip .stat-label {{ font-size: 11px; letter-spacing: 0.5px; opacity: 0.75; }}
.chip-vuln  {{ background: var(--vuln-bg); border-color: var(--vuln-dim); color: var(--vuln); }}
.chip-ok    {{ background: var(--ok-bg);   border-color: var(--ok-dim);   color: var(--ok);   }}
.chip-na    {{ background: var(--na-bg);   border-color: var(--na-dim);   color: var(--na);   }}
.chip-unk   {{ background: var(--unk-bg);  border-color: var(--unk-dim);  color: var(--unk);  }}
.chip-total {{ background: var(--bg3);     border-color: var(--border);   color: var(--text); }}

main {{ padding: 0 48px 64px; }}

.cve-grid {{ display: flex; flex-direction: column; gap: 10px; margin-bottom: 40px; }}

.cve-card {{
  border-radius: var(--radius);
  border: 1px solid var(--border);
  overflow: hidden;
  transition: border-color 0.15s;
}}
.cve-card:hover {{ border-color: var(--accent); }}

.badge-vuln         {{ background: var(--vuln-bg); border-color: var(--vuln-dim); }}
.badge-ok           {{ background: var(--ok-bg);   border-color: var(--ok-dim);   }}
.badge-not-affected {{ background: var(--na-bg);   border-color: var(--na-dim);   }}
.badge-unknown      {{ background: var(--unk-bg);  border-color: var(--unk-dim);  }}

.cve-header {{
  display: flex; align-items: center; gap: 12px;
  padding: 12px 16px; background: rgba(255,255,255,0.02);
  flex-wrap: wrap;
}}
.cve-id {{
  font-family: var(--font-mono); font-weight: 600;
  font-size: 13px; color: #fff; flex: 0 0 auto;
}}
.cve-alias {{
  font-family: var(--font-mono); font-size: 11px;
  color: var(--muted); flex: 1;
}}
.badge {{
  font-family: var(--font-mono); font-size: 10px; font-weight: 700;
  letter-spacing: 1px; padding: 3px 8px; border-radius: 3px;
  border: 1px solid transparent; flex-shrink: 0;
}}
.badge.badge-vuln         {{ background: var(--vuln-dim); color: var(--vuln); border-color: var(--vuln); }}
.badge.badge-ok           {{ background: var(--ok-dim);   color: var(--ok);   border-color: var(--ok);   }}
.badge.badge-not-affected {{ background: var(--na-dim);   color: var(--na);   border-color: var(--na);   }}
.badge.badge-unknown      {{ background: var(--unk-dim);  color: var(--unk);  border-color: var(--unk);  }}

.cve-reason {{
  font-family: var(--font-mono); font-size: 11.5px;
  color: var(--muted); padding: 4px 16px 8px;
}}

.mitigations {{
  border-top: 1px solid var(--border);
  padding: 10px 16px;
  display: flex; flex-direction: column; gap: 3px;
}}
.mit-row {{
  display: flex; align-items: flex-start; gap: 8px;
  font-family: var(--font-mono); font-size: 11.5px; padding: 2px 0;
}}
.mit-icon {{ flex: 0 0 14px; font-weight: 700; }}
.mit-good {{ color: var(--ok);   }}
.mit-bad  {{ color: var(--vuln); }}
.mit-info {{ color: var(--muted); }}

.hw-section {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0; margin-bottom: 32px;
}}
.hw-section summary {{
  font-family: var(--font-mono); font-size: 12px; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1px;
  padding: 14px 20px; cursor: pointer; list-style: none;
}}
.hw-section summary::-webkit-details-marker {{ display: none; }}
.hw-section summary::before {{ content: '▶ '; font-size: 10px; }}
.hw-section[open] summary::before {{ content: '▼ '; }}
.hw-list {{
  list-style: none; font-family: var(--font-mono); font-size: 11.5px;
  color: var(--muted); padding: 0 20px 16px; display: flex;
  flex-direction: column; gap: 3px;
}}

.summary-section {{
  margin-top: 40px; padding-top: 32px;
  border-top: 1px solid var(--border);
}}
.summary-section h2 {{
  font-family: var(--font-mono); font-size: 13px; text-transform: uppercase;
  letter-spacing: 1.5px; color: var(--accent); margin-bottom: 16px;
}}
.summary-table {{
  width: 100%; border-collapse: collapse;
  font-family: var(--font-mono); font-size: 12px;
}}
.summary-table th {{
  text-align: left; padding: 8px 12px;
  background: var(--bg2); border: 1px solid var(--border);
  color: var(--muted); font-weight: 600; letter-spacing: 0.5px;
}}
.summary-table td {{ padding: 8px 12px; border: 1px solid var(--border); }}
.sum-vuln td {{ background: var(--vuln-bg); color: var(--vuln); }}
.sum-ok   td {{ background: var(--ok-bg);   color: var(--ok);   }}

footer {{
  text-align: center; font-family: var(--font-mono); font-size: 11px;
  color: var(--muted); padding: 32px; border-top: 1px solid var(--border);
}}
</style>
</head>
<body>

<header class="page-header">
  <h1>spectre-meltdown Vulnerability Report</h1>
  <div class="meta">
    <span>Host: {report.hostname}</span>
    <span>Scanned: {report.scan_time}</span>
    {kernel_span}
    {cpu_span}
    {checker_span}
  </div>
</header>

<div class="overall-banner {overall_class}">
  <div class="overall-dot"></div>
  <div class="overall-label">{overall_label}</div>
</div>

<div class="stats-bar">
  <div class="stat-chip chip-total">
    <span class="stat-num">{total}</span>
    <span class="stat-label">TOTAL CVEs</span>
  </div>
  <div class="stat-chip chip-vuln">
    <span class="stat-num">{c[STATUS_VULNERABLE]}</span>
    <span class="stat-label">VULNERABLE</span>
  </div>
  <div class="stat-chip chip-ok">
    <span class="stat-num">{c[STATUS_OK]}</span>
    <span class="stat-label">OK / PATCHED</span>
  </div>
  <div class="stat-chip chip-na">
    <span class="stat-num">{c[STATUS_NOT_AFFECTED]}</span>
    <span class="stat-label">NOT AFFECTED</span>
  </div>
  <div class="stat-chip chip-unk">
    <span class="stat-num">{c[STATUS_UNKNOWN]}</span>
    <span class="stat-label">UNKNOWN</span>
  </div>
</div>

<main>
  {hw_html}
  <div class="cve-grid">{cve_cards}</div>
  {summary_html}
</main>

<footer>
  spectre-report &nbsp;·&nbsp; generated {report.scan_time} &nbsp;·&nbsp; {report.hostname}
</footer>

</body>
</html>"""


def run_checker() -> str:
    for cmd in ["spectre-meltdown-checker.sh", "spectre-meltdown-checker"]:
        try:
            result = subprocess.run([cmd, "--no-color"], capture_output=True, text=True)
            return result.stdout + result.stderr
        except FileNotFoundError:
            continue
    print("Error: spectre-meltdown-checker not found in PATH.", file=sys.stderr)
    print("Install: sudo apt install spectre-meltdown-checker", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an HTML report from spectre-meltdown-checker output."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--input", "-i", metavar="FILE",
                       help="Path to checker output file")
    group.add_argument("--run", action="store_true",
                       help="Run spectre-meltdown-checker directly (requires root)")
    parser.add_argument("--output", "-o", metavar="FILE", default="spectreReport.html",
                        help="Output HTML file (default: spectreReport.html)")
    args = parser.parse_args()

    if args.run:
        raw = run_checker()
    elif args.input:
        raw = Path(args.input).read_text(encoding="utf-8", errors="replace")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(1)

    report = parse_output(raw)
    html   = render_html(report)

    out_path = Path(args.output)
    out_path.write_text(html, encoding="utf-8")
    print(f"Report written to: {out_path.resolve()}")

    c = counts(report)
    print(f"  Total CVEs  : {sum(c.values())}")
    print(f"  Vulnerable  : {c[STATUS_VULNERABLE]}")
    print(f"  OK/Patched  : {c[STATUS_OK]}")
    print(f"  Not Affected: {c[STATUS_NOT_AFFECTED]}")
    print(f"  Unknown     : {c[STATUS_UNKNOWN]}")


if __name__ == "__main__":
    main()
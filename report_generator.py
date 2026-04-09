"""HTML report generator for WAF Bypass Lab."""
import os
from dataclasses import asdict
from html import escape


def generate_html(summary, results, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    verdict_color = {
        "BLOCKED": "#34c759",
        "ALLOWED": "#ff3b30",
        "ERROR": "#ff9500",
        "DRY_RUN": "#60a5fa",
        "UNKNOWN": "#64748b",
    }
    sev_color = {
        "CRITICAL": "#ff3b30",
        "HIGH": "#ff9500",
        "MEDIUM": "#ffcc00",
        "LOW": "#34c759",
    }

    # Group findings by category for the sidebar
    by_cat = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)

    # Sort categories: worst coverage first
    def cat_coverage(items):
        tot = len(items)
        blk = sum(1 for i in items if i.verdict == "BLOCKED")
        return blk / tot if tot else 1.0

    sorted_cats = sorted(by_cat.items(), key=lambda kv: cat_coverage(kv[1]))

    cat_sections = []
    for cat_name, items in sorted_cats:
        tot = len(items)
        blk = sum(1 for i in items if i.verdict == "BLOCKED")
        pct = round(blk / tot * 100, 1) if tot else 0
        pct_color = "#34c759" if pct >= 90 else "#ff9500" if pct >= 60 else "#ff3b30"

        rows = []
        for i, r in enumerate(sorted(items, key=lambda x: x.verdict != "ALLOWED")):
            v_color = verdict_color.get(r.verdict, "#888")
            s_color = sev_color.get(r.severity, "#888")
            body_preview = escape(r.actual_body_snippet[:200]) if r.actual_body_snippet else "<i style=\"color:#475569\">(empty)</i>"
            error_block = f'<div class="err">Error: {escape(r.error)}</div>' if r.error else ""
            rows.append(f"""
            <tr class="r" data-verdict="{r.verdict}">
              <td><span class="verdict" style="background:{v_color}">{r.verdict}</span></td>
              <td><span class="sev" style="background:{s_color}">{r.severity}</span></td>
              <td class="pid">{r.id}</td>
              <td class="pname">{escape(r.name)}</td>
              <td class="mth">{r.method}</td>
              <td class="sts">{r.actual_status or '—'}</td>
              <td class="lat">{r.latency_ms}ms</td>
            </tr>
            <tr class="detail"><td colspan="7">
              <div class="url"><b>URL:</b> <code>{escape(r.url[:300])}</code></div>
              <div class="url"><b>CWE:</b> {r.cwe} &nbsp;&nbsp; <b>Expected:</b> {r.expected}</div>
              <pre class="body">{body_preview}</pre>
              {error_block}
            </td></tr>
            """)

        cat_sections.append(f"""
        <section class="cat">
          <div class="chead">
            <h2>{escape(cat_name)}</h2>
            <div class="cbar"><div class="cbar-fill" style="width:{pct}%;background:{pct_color}"></div></div>
            <div class="cstats"><b style="color:{pct_color}">{pct}%</b> &nbsp; {blk}/{tot} blocked</div>
          </div>
          <table>
            <thead>
              <tr><th>Verdict</th><th>Sev</th><th>ID</th><th>Name</th><th>Method</th><th>Status</th><th>Latency</th></tr>
            </thead>
            <tbody>
              {''.join(rows)}
            </tbody>
          </table>
        </section>
        """)

    coverage = summary.coverage_percent
    cov_color = "#34c759" if coverage >= 90 else "#ff9500" if coverage >= 60 else "#ff3b30"
    grade = "A" if coverage >= 95 else "B" if coverage >= 85 else "C" if coverage >= 70 else "D" if coverage >= 50 else "F"

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WAF Bypass Lab — Coverage Report</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;color:#cbd5e1;margin:0;padding:24px;max-width:1200px;margin:auto}}
  h1{{color:#60a5fa;margin:0 0 4px;font-size:28px}}
  .sub{{color:#64748b;font-size:13px;margin-bottom:24px}}
  .hero{{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:26px;margin-bottom:20px;display:flex;gap:24px;align-items:center;flex-wrap:wrap}}
  .grade{{font-size:84px;font-weight:900;line-height:1;color:{cov_color};font-family:'Georgia',serif}}
  .gwrap{{text-align:center}}
  .gwrap .gl{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-top:-4px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;flex:1;min-width:400px}}
  .s{{background:#020617;border:1px solid #1e293b;border-radius:10px;padding:14px 18px}}
  .s .n{{font-size:24px;font-weight:800}}
  .s .l{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}}
  .cat{{background:#0f172a;border:1px solid #1e293b;border-radius:12px;margin-bottom:14px;overflow:hidden}}
  .chead{{padding:16px 20px;display:flex;gap:16px;align-items:center;border-bottom:1px solid #1e293b}}
  .chead h2{{margin:0;font-size:16px;color:#e2e8f0;flex-shrink:0}}
  .cbar{{flex:1;background:#020617;height:10px;border-radius:5px;overflow:hidden}}
  .cbar-fill{{height:100%;transition:width .5s}}
  .cstats{{color:#94a3b8;font-size:12px}}
  table{{width:100%;border-collapse:collapse}}
  th{{text-align:left;padding:10px 14px;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.5px;background:#0b111e;border-bottom:1px solid #1e293b}}
  td{{padding:8px 14px;border-bottom:1px solid #131e35;font-size:12px;vertical-align:middle}}
  tr.r{{cursor:pointer}}
  tr.r:hover{{background:#131e35}}
  tr.detail td{{background:#020617;padding:12px 20px;font-size:11px;color:#94a3b8;border-bottom:1px solid #1e293b}}
  .verdict,.sev{{color:#000;font-weight:800;font-size:10px;padding:2px 8px;border-radius:10px}}
  .pid{{color:#fbbf24;font-family:monospace;font-size:11px}}
  .pname{{color:#e2e8f0}}
  .mth{{color:#60a5fa;font-family:monospace;font-size:11px;font-weight:600}}
  .sts{{color:#94a3b8;font-family:monospace}}
  .lat{{color:#475569;font-family:monospace;font-size:10px}}
  .url{{margin:6px 0}}
  code{{background:#0b111e;padding:2px 6px;border-radius:4px;color:#fbbf24;font-size:11px}}
  pre.body{{background:#0b111e;padding:10px 14px;border-radius:6px;border-left:3px solid #475569;overflow-x:auto;color:#94a3b8;font-size:10px;max-height:120px;margin:8px 0}}
  .err{{background:rgba(255,59,48,.1);border-left:3px solid #ff3b30;padding:8px 14px;border-radius:4px;color:#ff6b6b;font-size:11px;margin-top:6px}}
  .footer{{margin-top:30px;color:#334155;font-size:11px;text-align:center}}
  .notice{{background:rgba(255,149,0,.08);border:1px solid rgba(255,149,0,.3);border-radius:8px;padding:14px 18px;margin-bottom:20px;font-size:12px;color:#fbbf24}}
</style>
</head>
<body>
  <h1>&#x1F6E1; WAF Bypass Lab &mdash; Coverage Report</h1>
  <div class="sub">Target: <code>{escape(summary.target)}</code> &middot; Generated {summary.started_at}</div>

  <div class="notice"><b>Authorized testing only.</b> This report was generated against a target for which the operator confirmed written authorization to test.</div>

  <div class="hero">
    <div class="gwrap">
      <div class="grade">{grade}</div>
      <div class="gl">WAF GRADE</div>
    </div>
    <div class="stats">
      <div class="s"><div class="n" style="color:{cov_color}">{coverage}%</div><div class="l">Coverage</div></div>
      <div class="s"><div class="n">{summary.total_tests}</div><div class="l">Tests Run</div></div>
      <div class="s"><div class="n" style="color:#34c759">{summary.blocked}</div><div class="l">Blocked</div></div>
      <div class="s"><div class="n" style="color:#ff3b30">{summary.allowed}</div><div class="l">Gaps (Allowed)</div></div>
      <div class="s"><div class="n" style="color:#ff9500">{summary.errors}</div><div class="l">Errors</div></div>
    </div>
  </div>

  {''.join(cat_sections)}

  <div class="footer">WAF Bypass Lab &middot; github.com/CyberEnthusiastic/waf-bypass-lab &middot; Licensed under MIT</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html)

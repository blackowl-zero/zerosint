"""
Report generator.

- JSON export (all findings, for other tools to consume).
- Self-contained HTML report: summary, findings table by tier, and a
  relationship graph (seed -> finding). With pyvis installed the graph is
  interactive; otherwise it falls back to a plain adjacency list, so the
  report is always produced.
"""
from __future__ import annotations

import contextlib
import html
import json
import logging
import os
import re
import tempfile
from urllib.parse import urlparse

from core.models import EntityType, Finding

log = logging.getLogger("osint")

TIER_COLOR = {"high": "#4ade80", "medium": "#fbbf24", "low": "#94a3b8"}
TYPE_COLOR = {
    EntityType.EMAIL: "#60a5fa", EntityType.USERNAME: "#c084fc",
    EntityType.DOMAIN: "#34d399", EntityType.IP: "#f87171",
    EntityType.PROFILE_URL: "#f472b6", EntityType.BREACH: "#fb7185",
    EntityType.SUBDOMAIN: "#2dd4bf", EntityType.NAME: "#fcd34d",
}


@contextlib.contextmanager
def _atomic_open(path: str):
    """Write to a temp file next to `path`, then swap it in. A crash or Ctrl+C
    mid-write leaves the previous file intact instead of a truncated one."""
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yield fh
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def export_json(results: dict[str, Finding], path: str) -> None:
    data = [f.to_dict() for f in results.values()]
    with _atomic_open(path) as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    log.info("JSON written: %s", path)


def _safe_href(url: str) -> str | None:
    """Only http(s) URLs become links; anything else (javascript:, data:...) stays text."""
    try:
        scheme = urlparse(str(url).strip()).scheme.lower()
    except ValueError:
        return None
    return url if scheme in ("http", "https") else None


# pyvis always adds an HTML comment pointing at ../node_modules and loads
# Bootstrap from a CDN (only used for a card border). Strip both so the
# report is one file that works offline.
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_BOOTSTRAP_RE = re.compile(
    r"<link\b[^>]*bootstrap[^>]*>|<script\b[^>]*bootstrap[^>]*>\s*</script>", re.I | re.S)


def _build_graph_html(results: dict[str, Finding],
                      edges: list[tuple[str, str]]) -> str:
    """Full HTML document for the graph (embedded later in an iframe)."""
    try:
        from pyvis.network import Network
    except ImportError:
        log.info("pyvis not installed, graph fallback to text.")
        names = {f.node_id: f.value for f in results.values()}
        lines = [f"{names.get(p, p)} -> {names.get(c, c)}" for p, c in edges]
        return "<pre>" + html.escape("\n".join(lines)) + "</pre>"

    # in_line: vis-network JS/CSS go inside the file, no lib/ folder needed
    net = Network(height="600px", width="100%", bgcolor="#0f172a",
                  font_color="#e2e8f0", directed=True, cdn_resources="in_line")
    net.barnes_hut()
    for f in results.values():
        color = TYPE_COLOR.get(f.type, "#94a3b8")
        label = f.value if len(f.value) <= 30 else f.value[:27] + "..."
        title = f"{f.type} | conf={f.confidence} | src={f.meta.get('all_sources')}"
        net.add_node(f.node_id, label=label, color=color, title=title)
    nodes = {f.node_id for f in results.values()}
    for p, c in edges:
        if p in nodes and c in nodes:
            net.add_edge(p, c)
    try:
        doc = net.generate_html(notebook=False)
        doc = _HTML_COMMENT_RE.sub("", doc)
        doc = _BOOTSTRAP_RE.sub("", doc)
        # inside the iframe: no default white margin, no extra border/scrollbar
        frame_css = ("<style>html, body { margin: 0; background: #0f172a; overflow: hidden; }"
                     " #mynetwork { border: 0 !important; }</style>")
        return doc.replace("</head>", frame_css + "</head>", 1)
    except Exception as e:  # noqa: BLE001
        log.warning("graph gen failed: %s", e)
        return "<p>graph unavailable</p>"


def _rows(results: dict[str, Finding]) -> str:
    out = []
    ordered = sorted(
        (f for f in results.values() if f.source != "input"),
        key=lambda f: (-f.confidence, f.type),
    )
    for f in ordered:
        tier = f.meta.get("tier", "low")
        val = html.escape(f.value)
        if f.type == EntityType.PROFILE_URL and _safe_href(f.value):
            val = f'<a href="{val}" target="_blank" rel="noopener">{val}</a>'
        extra = ""
        if f.type == EntityType.BREACH:
            dc = f.meta.get("data_classes", [])
            extra = html.escape(", ".join(dc[:4]))
        out.append(f"""
        <tr>
          <td><span class="pill" style="background:{TYPE_COLOR.get(f.type,'#334155')}">{html.escape(f.type)}</span></td>
          <td>{val}</td>
          <td>{html.escape(', '.join(f.meta.get('all_sources', [f.source])))}</td>
          <td><span class="tier" style="color:{TIER_COLOR[tier]}">{f.confidence} ({tier})</span></td>
          <td>{html.escape(str(f.parent or ''))}</td>
          <td>{extra}</td>
        </tr>""")
    return "\n".join(out)


def _phone_section(results: dict[str, Finding]) -> str:
    """PhoneInfoga: phone info + dork links (after dead-link filtering). Empty if there is none."""
    phones = [f for f in results.values()
              if f.type == EntityType.PHONE and isinstance(f.meta.get("dorks"), dict)]
    if not phones:
        return ""
    out = ["<h2>Phone intelligence (PhoneInfoga)</h2>"]
    for f in phones:
        m = f.meta
        info = " | ".join(
            f"{k}: <b>{html.escape(str(m.get(k)))}</b>"
            for k in ("e164", "international", "country_code", "country", "carrier", "line_type")
            if m.get(k) not in (None, "")
        )
        flt = m.get("dork_filter", {})
        note = f"dead-link filter: {html.escape(str(flt.get('status', '?')))}"
        if flt.get("dead_domains"):
            note += " | dropped: " + html.escape(", ".join(flt["dead_domains"]))
        if flt.get("reason"):
            note += " | " + html.escape(flt["reason"])
        out.append(f'<div class="sub" style="margin:8px 0">{info}</div>')
        for k, why in (m.get("unavailable") or {}).items():
            out.append(f'<div class="sub">{html.escape(k)}: {html.escape(why)}</div>')
        out.append(f'<div class="sub" style="margin-bottom:8px">{note}</div>')
        out.append("<table><thead><tr><th>Category</th><th>Google dork (open manually)</th></tr></thead><tbody>")
        for cat, items in m["dorks"].items():
            for it in items:
                url = html.escape(it.get("url", ""))
                label = html.escape(it.get("dork") or it.get("url", ""))
                cell = (f'<a href="{url}" target="_blank" rel="noopener noreferrer">{label}</a>'
                        if _safe_href(it.get("url", "")) else label)
                out.append(f'<tr><td>{html.escape(cat)}</td><td>{cell}</td></tr>')
        out.append("</tbody></table>")
    return "\n".join(out)


def export_html(results: dict[str, Finding], edges: list[tuple[str, str]],
                summary: dict, target_label: str, path: str,
                interrupted: bool = False) -> None:
    graph_html = _build_graph_html(results, edges)
    title_suffix = " (partial)" if interrupted else ""
    banner = ('<div class="banner">Scan interrupted (Ctrl+C): partial results.</div>'
              if interrupted else "")
    if graph_html.lstrip().lower().startswith("<html"):
        # pyvis gives a whole document; nest it in an iframe, not in our <body>.
        # sandbox: the graph may run its own scripts and nothing else (opaque
        # origin: no access to the report, no forms, popups or navigation)
        graph_html = ('<iframe class="graph" title="Relationship graph" sandbox="allow-scripts" '
                      'style="width:100%;height:600px;border:0;display:block" '
                      f'srcdoc="{html.escape(graph_html, quote=True)}"></iframe>')

    by_type = ", ".join(f"{k}: {v}" for k, v in summary["by_type"].items()) or "none"
    t = summary["by_tier"]

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZeroSint Report: {html.escape(target_label)}{title_suffix}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
         background:#0b1120; color:#e2e8f0; }}
  header {{ padding:24px 32px; border-bottom:1px solid #1e293b;
            background:linear-gradient(180deg,#111827,#0b1120); }}
  h1 {{ margin:0 0 4px; font-size:20px; }}
  .sub {{ color:#64748b; font-size:13px; }}
  main {{ padding:24px 32px; max-width:1200px; margin:0 auto; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:#111827; border:1px solid #1e293b; border-radius:10px;
           padding:14px 18px; min-width:120px; }}
  .card .n {{ font-size:26px; font-weight:700; }}
  .card .l {{ font-size:11px; color:#64748b; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1e293b;
           vertical-align:top; }}
  th {{ color:#64748b; text-transform:uppercase; font-size:11px; }}
  .pill {{ padding:2px 8px; border-radius:999px; color:#0b1120;
           font-size:11px; font-weight:700; }}
  .tier {{ font-weight:700; }}
  a {{ color:#60a5fa; word-break:break-all; }}
  h2 {{ margin-top:36px; font-size:15px; color:#94a3b8;
        border-left:3px solid #3b82f6; padding-left:10px; }}
  .banner {{ margin:16px 32px 0; padding:12px 16px; border:1px solid #f59e0b;
             border-radius:8px; color:#fbbf24; background:#1f1405; font-weight:700; }}
  .disclaimer {{ margin-top:40px; padding:14px; border:1px dashed #334155;
                 border-radius:8px; color:#64748b; font-size:12px; }}
</style></head>
<body>
<header>
  <h1>ZeroSint Report</h1>
  <div class="sub">Target: <b>{html.escape(target_label)}</b> | {summary['total']} findings | passive recon only</div>
</header>
{banner}
<main>
  <div class="cards">
    <div class="card"><div class="n">{summary['total']}</div><div class="l">findings</div></div>
    <div class="card"><div class="n" style="color:{TIER_COLOR['high']}">{t['high']}</div><div class="l">high conf</div></div>
    <div class="card"><div class="n" style="color:{TIER_COLOR['medium']}">{t['medium']}</div><div class="l">medium</div></div>
    <div class="card"><div class="n" style="color:{TIER_COLOR['low']}">{t['low']}</div><div class="l">low</div></div>
  </div>
  <div class="sub">By type: {by_type}</div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Type</th><th>Value</th><th>Sources</th><th>Confidence</th><th>From seed</th><th>Notes</th></tr></thead>
    <tbody>{_rows(results)}</tbody>
  </table>

  {_phone_section(results)}

  <h2>Relationship graph</h2>
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;overflow:hidden">
    {graph_html}
  </div>

  <div class="disclaimer">
    For authorized security research & educational use only. All data gathered
    via passive OSINT from public sources. No active intrusion, no credential testing.
  </div>
</main>
</body></html>"""

    with _atomic_open(path) as fh:
        fh.write(doc)
    log.info("HTML written: %s", path)

#!/usr/bin/env python3
"""ClawHub skill security scan scraper.

Generates a markdown report for the skills found under --skills-dir.

Strategy:
- Determine slug from SKILL.md frontmatter name:
- Visit https://clawhub.ai/<owner>/<slug>
- Expand any collapsed "Details" controls
- Extract Security Scan + Runtime requirements + Comments

Note: ClawHub renders this section client-side; we use Playwright.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LocalSkill:
    path: Path
    slug: str
    local_version: str | None


def _read_frontmatter(path: Path) -> dict[str, Any]:
    """Very small YAML frontmatter reader (only key: value lines)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    block = text[4:end]
    out: dict[str, Any] = {}
    for line in block.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        # Strip simple quotes
        v = v.strip('"').strip("'")
        out[k] = v
    return out


def _find_local_skills(skills_dir: Path) -> list[LocalSkill]:
    skills: list[LocalSkill] = []
    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("_") or child.name.startswith("."):
            continue
        skill_md = child / "SKILL.md"
        if not skill_md.exists():
            continue
        fm = _read_frontmatter(skill_md)
        slug = (fm.get("name") or "").strip()
        if not slug:
            continue
        local_version = (fm.get("version") or "").strip() or None
        skills.append(LocalSkill(path=child, slug=slug, local_version=local_version))
    return skills


def _load_slug_map(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise SystemExit(f"slug-map not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").strip()


def _parse_page_text(text: str) -> dict[str, Any]:
    """Parse the main text blob into sections.

    Kept as a fallback because some parts of the page are easier to capture as text,
    but security scan details should prefer DOM scraping.
    """
    t = (text or "").replace("\r", "")
    lines = [ln.strip() for ln in t.split("\n") if ln.strip()]

    # Current version
    version = None
    for i, ln in enumerate(lines):
        if ln.lower() == "current version" and i + 1 < len(lines):
            version = lines[i + 1]
            break

    # Security scan raw block
    sec_raw = None
    if "SECURITY SCAN" in t:
        sec_raw = t.split("SECURITY SCAN", 1)[1]
        # page footer marker seen on ClawHub
        if "Like a lobster shell" in sec_raw:
            sec_raw = sec_raw.split("Like a lobster shell", 1)[0]
        sec_raw = sec_raw.strip()

    sec_lines = [ln.strip() for ln in (sec_raw or "").split("\n") if ln.strip()]
    vt_status = None
    oc_status = None
    oc_conf = None
    oc_reason = None

    def _idx(label: str) -> int:
        try:
            return sec_lines.index(label)
        except ValueError:
            return -1

    vt_i = _idx("VirusTotal")
    if vt_i >= 0 and vt_i + 1 < len(sec_lines):
        vt_status = sec_lines[vt_i + 1]

    oc_i = _idx("OpenClaw")
    if oc_i >= 0 and oc_i + 1 < len(sec_lines):
        oc_status = sec_lines[oc_i + 1]
    if oc_i >= 0 and oc_i + 2 < len(sec_lines):
        oc_conf = sec_lines[oc_i + 2]
    if oc_i >= 0:
        # find the long reason sentence
        for ln in sec_lines[oc_i : oc_i + 100]:
            if ln.startswith("The skill") or ln.startswith("The tool"):
                oc_reason = ln
                break

    # Runtime requirements section
    runtime = None
    rr_idx = next((i for i, ln in enumerate(lines) if ln == "Runtime requirements"), -1)
    if rr_idx >= 0:
        runtime = []
        for j in range(rr_idx, len(lines)):
            if j > rr_idx and lines[j] == "Files":
                break
            runtime.append(lines[j])

    # Comments section
    comments = None
    c_idx = next((i for i, ln in enumerate(lines) if ln == "Comments"), -1)
    if c_idx >= 0:
        comments = lines[c_idx : min(len(lines), c_idx + 200)]

    return {
        "version": version,
        "security": {
            "vtStatus": vt_status,
            "vtLink": None,
            "ocStatus": oc_status,
            "ocConf": oc_conf,
            "ocReason": oc_reason,
            "summary": None,
            "dimensions": None,
            "guidance": None,
            "raw": sec_raw,
        },
        "runtime": runtime,
        "comments": comments,
    }


def _extract_security_dom(page: Any) -> dict[str, Any] | None:
    """Extract security scan data from the rendered DOM.

    Returns None if the scan panel isn't present (e.g. page layout changed or gated).
    """

    js = r"""
() => {
  const panel = document.querySelector('.scan-results-panel');
  if (!panel) return null;

  const rows = Array.from(panel.querySelectorAll('.scan-result-row'));

  function pickRow(name) {
    for (const r of rows) {
      const n = r.querySelector('.scan-result-scanner-name')?.innerText?.trim();
      if (n === name) return r;
    }
    return null;
  }

  const vtRow = pickRow('VirusTotal');
  const ocRow = pickRow('OpenClaw');

  const vtStatus = vtRow?.querySelector('.scan-result-status')?.innerText?.trim() || null;
  const vtLink = vtRow?.querySelector('a.scan-result-link')?.href || null;

  const ocStatus = ocRow?.querySelector('.scan-result-status')?.innerText?.trim() || null;
  const ocConf = ocRow?.querySelector('.scan-result-confidence')?.innerText?.trim() || null;

  const detail = panel.querySelector('.analysis-detail');
  const summary = detail?.querySelector('.analysis-summary-text')?.innerText?.trim() || null;

  // Expand details if collapsed
  const header = detail?.querySelector('.analysis-detail-header');
  if (header) {
    try { header.click(); } catch (e) {}
  }

  const dims = [];
  const dimRows = Array.from(detail?.querySelectorAll('.dimension-row') || []);
  for (const r of dimRows) {
    const label = r.querySelector('.dimension-label')?.innerText?.trim() || null;
    const body = r.querySelector('.dimension-detail')?.innerText?.trim() || null;
    if (label || body) dims.push({ label, detail: body });
  }

  const guidance = detail?.querySelector('.analysis-guidance')?.innerText?.trim() || null;

  return { vtStatus, vtLink, ocStatus, ocConf, summary, dimensions: dims, guidance };
}
"""

    try:
        return page.evaluate(js)
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Scrape ClawHub Security Scan for local skills")
    ap.add_argument("--owner", default="odrobnik", help="ClawHub owner/handle")
    ap.add_argument("--skills-dir", default=str(Path.home() / "Developer" / "Skills"), help="Folder containing local skills")
    ap.add_argument("--out", default=None, help="Output markdown path (default: /tmp/clawhub-skill-review-YYYY-MM-DD.md)")
    ap.add_argument("--slug-map", default=None, help="Optional JSON mapping of local slug->ClawHub slug")
    ap.add_argument("--only", default=None, help="Only scrape a single slug (after slug-map), e.g. tesla-fleet-api")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of skills (0=all)")
    ap.add_argument("--headful", action="store_true", help="Run browser non-headless")

    args = ap.parse_args()

    skills_dir = Path(args.skills_dir).expanduser().resolve()
    if not skills_dir.exists():
        raise SystemExit(f"skills-dir not found: {skills_dir}")

    out_path = Path(args.out) if args.out else Path(f"/tmp/clawhub-skill-review-{dt.date.today().isoformat()}.md")

    slug_map = _load_slug_map(args.slug_map)

    local_skills = _find_local_skills(skills_dir)

    # Apply slug map early so --only matches what we'll scrape.
    mapped_skills: list[LocalSkill] = []
    for s in local_skills:
        mapped_skills.append(LocalSkill(path=s.path, slug=slug_map.get(s.slug, s.slug), local_version=s.local_version))
    local_skills = mapped_skills

    if args.only:
        local_skills = [s for s in local_skills if s.slug == args.only]

    if args.limit and args.limit > 0:
        local_skills = local_skills[: args.limit]

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        raise SystemExit(
            "Playwright not installed. Run:\n"
            "  python3 -m pip install playwright\n"
            "  python3 -m playwright install chromium\n"
        )

    rows: list[dict[str, Any]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headful)
        page = browser.new_page()

        for s in local_skills:
            slug = s.slug
            url = f"https://clawhub.ai/{args.owner}/{slug}"
            sys.stderr.write(f"Scraping {slug}…\n")
            sys.stderr.flush()

            try:
                # ClawHub renders the scan panel client-side; wait for JS to finish.
                page.goto(url, wait_until="networkidle", timeout=60000)
                page.wait_for_selector("main", timeout=20000)
                # Prefer to wait for the scan panel; if it's missing, we'll fall back to text parsing.
                try:
                    page.wait_for_selector(".scan-results-panel", timeout=20000)
                except Exception:
                    pass

                # Expand any Details dropdowns.
                try:
                    page.evaluate(
                        """() => {
                            const btns = Array.from(document.querySelectorAll('button'));
                            for (const b of btns) {
                              const t = (b.innerText || '').trim();
                              if (t.includes('Details') && t.includes('▾')) {
                                try { b.click(); } catch (e) {}
                              }
                            }
                        }"""
                    )
                except Exception:
                    pass

                time.sleep(0.15)

                main_el = page.query_selector("main")
                text = main_el.inner_text() if main_el else page.content()

                parsed = _parse_page_text(text)
                sec = parsed.get("security") or {}

                # Prefer DOM extraction (more reliable than parsing text blobs)
                dom_sec = _extract_security_dom(page)
                if dom_sec:
                    sec["domOk"] = True
                    sec.update(
                        {
                            "vtStatus": dom_sec.get("vtStatus") or sec.get("vtStatus"),
                            "vtLink": dom_sec.get("vtLink") or sec.get("vtLink"),
                            "ocStatus": dom_sec.get("ocStatus") or sec.get("ocStatus"),
                            "ocConf": dom_sec.get("ocConf") or sec.get("ocConf"),
                            "summary": dom_sec.get("summary"),
                            "dimensions": dom_sec.get("dimensions"),
                            "guidance": dom_sec.get("guidance"),
                        }
                    )
                else:
                    sec["domOk"] = False
                    # Fallback: try to locate VT report link
                    try:
                        a = page.query_selector("a[href*='virustotal.com/gui/file/']")
                        if a:
                            sec["vtLink"] = a.get_attribute("href")
                    except Exception:
                        pass

                rows.append(
                    {
                        "slug": slug,
                        "url": url,
                        "localVersion": s.local_version,
                        "pageVersion": parsed.get("version"),
                        "security": sec,
                        "runtime": parsed.get("runtime"),
                        "comments": parsed.get("comments"),
                    }
                )
            except Exception as e:
                rows.append({"slug": slug, "url": url, "error": str(e)})

        browser.close()

    # Write markdown
    lines: list[str] = []
    lines.append(f"# ClawHub Skill Review — {args.owner}")
    lines.append("")
    lines.append(f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}")
    lines.append("")

    lines.append("## Index")
    lines.append("")
    lines.append("| Slug | Local | ClawHub | VirusTotal | OpenClaw | Confidence | VT link |")
    lines.append("|---|---:|---:|---|---|---|---|")

    for r in rows:
        if r.get("error"):
            lines.append(f"| {_md_escape(r['slug'])} |  |  | ERROR |  |  |  |");
            continue
        sec = r.get("security") or {}
        lines.append(
            "| "
            + " | ".join(
                [
                    _md_escape(r.get("slug", "")),
                    _md_escape(r.get("localVersion") or ""),
                    _md_escape(r.get("pageVersion") or ""),
                    _md_escape(sec.get("vtStatus") or ""),
                    _md_escape(sec.get("ocStatus") or ""),
                    _md_escape(sec.get("ocConf") or ""),
                    sec.get("vtLink") or "",
                ]
            )
            + " |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Details")
    lines.append("")

    for r in rows:
        lines.append(f"### {r.get('slug')}")
        lines.append(f"URL: {r.get('url')}")
        if r.get("error"):
            lines.append("")
            lines.append(f"**Error:** `{r['error']}`")
            lines.append("")
            lines.append("---")
            lines.append("")
            continue

        lines.append("")
        lines.append(f"Local version: `{r.get('localVersion')}`")
        lines.append(f"ClawHub version: `{r.get('pageVersion')}`")
        lines.append("")

        sec = r.get("security") or {}
        lines.append("**Security Scan:**")
        lines.append("")
        lines.append(f"- VirusTotal: {sec.get('vtStatus') or '—'}")
        if sec.get("vtLink"):
            lines.append(f"  - {sec.get('vtLink')}")
        lines.append(f"- OpenClaw: {sec.get('ocStatus') or '—'} ({sec.get('ocConf') or '—'})")
        if sec.get("summary"):
            lines.append(f"- Summary: {sec.get('summary')}")

        if sec.get("dimensions"):
            lines.append("")
            lines.append("**OpenClaw analysis dimensions:**")
            for d in sec.get("dimensions") or []:
                label = d.get("label") or "(unknown)"
                detail = d.get("detail") or ""
                lines.append(f"- {label}: {detail}")

        if sec.get("guidance"):
            lines.append("")
            lines.append("**OpenClaw guidance:**")
            lines.append("```text")
            lines.append(str(sec.get("guidance")).strip())
            lines.append("```")

        # Only include raw text fallback when DOM extraction failed (avoids duplicate content).
        if not sec.get("domOk"):
            lines.append("")
            lines.append("**Security Scan (raw text fallback):**")
            lines.append("```text")
            lines.append((sec.get("raw") or "(missing)").strip())
            lines.append("```")

        lines.append("")
        lines.append("**Runtime requirements (as shown):**")
        lines.append("```text")
        rt = r.get("runtime")
        lines.append("\n".join(rt) if rt else "(none shown)")
        lines.append("```")

        lines.append("")
        lines.append("**Comments (as shown):**")
        lines.append("```text")
        c = r.get("comments")
        lines.append("\n".join(c) if c else "(none shown)")
        lines.append("```")

        lines.append("")
        lines.append("---")
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()

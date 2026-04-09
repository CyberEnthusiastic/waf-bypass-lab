"""
WAF Bypass Lab — defensive WAF assessment tool.

Replays a curated library of OWASP Top 10 attack payloads against a target
URL to measure how effectively the WAF in front of it blocks known attacks.

This is a DEFENSIVE tool. It is designed to answer one question for the
security team that owns the target:

  "How well does our WAF block the attacks every attacker will eventually try?"

Authorized use only. You MUST pass --i-am-authorized-to-test on every run,
acknowledging that you have explicit written permission to test the target.

Inspired by the Akamai/Fastly Hurl test patterns used by large-scale
e-commerce security teams to validate WAF coverage in production.

Author: Adithya Vasamsetti (CyberEnthusiastic)
License: MIT
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import ssl
import socket
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional


BANNER = r"""
============================================================
   WAF BYPASS LAB  v1.0
   Defensive WAF coverage assessment
   github.com/CyberEnthusiastic
============================================================
"""

AUTHORIZATION_NOTICE = """
AUTHORIZED USE ONLY

By running this tool against any target, you confirm that you have explicit
written authorization from the target's owner to conduct security testing.

This tool replays known-malicious payloads that will be logged by any decent
WAF, SIEM, or intrusion detection system. Running it against a system you do
not own is illegal in most jurisdictions and may be a violation of the
Computer Fraud and Abuse Act (CFAA), Article 8 of the EU Cybercrime
Convention, or equivalent local laws.

The author disclaims all liability for misuse.
"""


@dataclass
class PayloadResult:
    id: str
    name: str
    category: str
    cwe: str
    method: str
    url: str
    severity: str
    expected: str
    actual_status: Optional[int] = None
    actual_body_snippet: str = ""
    latency_ms: float = 0.0
    verdict: str = "UNKNOWN"   # BLOCKED / ALLOWED / ERROR
    waf_hit: bool = False      # True if WAF appeared to block (403/406/429/503)
    error: str = ""


@dataclass
class Summary:
    target: str
    started_at: str
    total_tests: int = 0
    blocked: int = 0
    allowed: int = 0
    errors: int = 0
    coverage_percent: float = 0.0
    by_category: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_severity: Dict[str, Dict[str, int]] = field(default_factory=dict)


# --- Detection: did the WAF block? ------------------------------------------
# A "block" is any 4xx in 400-499 range (except 404 if the test already expects
# a block via the 404 pattern), 5xx if it's an anti-bot / rate-limit page, or
# any response whose body contains known WAF block signatures.
WAF_BLOCK_SIGNATURES = [
    "access denied",
    "ak_reference_id",
    "x-sigsci-agentresponse",
    "your request has been blocked",
    "request unsuccessful",
    "you have been blocked",
    "cloudflare ray id",
    "waf_originally_attempted",
    "request is blocked",
    "security rule violation",
    "incapsula incident",
    "403 forbidden",
]

BLOCK_STATUS_CODES = {403, 406, 409, 418, 429, 451, 503}


def is_waf_block(status: int, body_snippet: str) -> bool:
    if status in BLOCK_STATUS_CODES:
        return True
    low = body_snippet.lower()
    return any(sig in low for sig in WAF_BLOCK_SIGNATURES)


# --- HTTP request helper ----------------------------------------------------
def build_url(target: str, path: str, query: Optional[str]) -> str:
    base = target.rstrip("/")
    url = base + path
    if query:
        # URL-encode each value in the query string so urllib doesn't choke
        # on special chars like <, >, ', space. We keep any pre-encoded %XX
        # bytes as-is so double-encoding tests still work.
        encoded_pairs = []
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                v = urllib.parse.quote(v, safe="%")
                encoded_pairs.append(f"{k}={v}")
            else:
                encoded_pairs.append(urllib.parse.quote(pair, safe="%"))
        encoded_query = "&".join(encoded_pairs)
        sep = "&" if "?" in path else "?"
        url = url + sep + encoded_query
    return url


def send_request(method: str, url: str, headers: Dict[str, str],
                 body: Optional[bytes], timeout: int = 10,
                 verify_ssl: bool = True) -> (int, str, float):
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)

    ctx = None
    if url.startswith("https://") and not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            elapsed = (time.perf_counter() - start) * 1000
            body_text = resp.read(4096).decode("utf-8", errors="replace")
            return resp.status, body_text[:800], elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        body_text = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body_text[:800], elapsed
    except urllib.error.URLError as e:
        elapsed = (time.perf_counter() - start) * 1000
        raise RuntimeError(f"URLError: {e.reason}") from e
    except (socket.timeout, TimeoutError):
        elapsed = (time.perf_counter() - start) * 1000
        raise RuntimeError("Connection timeout") from None


# --- Payload runner ---------------------------------------------------------
class WafBypassLab:
    DEFAULT_UA = "WAF-Bypass-Lab/1.0 (defensive-security-testing; https://github.com/CyberEnthusiastic/waf-bypass-lab)"

    def __init__(self, target: str, payloads_dir: str = "payloads",
                 delay_ms: int = 200, timeout: int = 10, verify_ssl: bool = True,
                 custom_headers: Optional[Dict[str, str]] = None,
                 dry_run: bool = False):
        self.target = target.rstrip("/")
        self.payloads_dir = Path(payloads_dir)
        self.delay_ms = delay_ms
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.custom_headers = custom_headers or {}
        self.dry_run = dry_run
        self.results: List[PayloadResult] = []

    def load_payloads(self, categories_filter: Optional[List[str]] = None) -> List[Dict]:
        all_files = sorted(self.payloads_dir.glob("*.json"))
        loaded = []
        for f in all_files:
            data = json.loads(f.read_text(encoding="utf-8"))
            if categories_filter and data["category"] not in categories_filter:
                continue
            for p in data["payloads"]:
                p["_category"] = data["category"]
                p["_cwe"] = data.get("cwe", "")
                loaded.append(p)
        return loaded

    def run(self, categories_filter: Optional[List[str]] = None,
            max_tests: Optional[int] = None) -> List[PayloadResult]:
        payloads = self.load_payloads(categories_filter)
        if max_tests:
            payloads = payloads[:max_tests]

        print(f"[*] Loaded {len(payloads)} payloads")
        print(f"[*] Target : {self.target}")
        print(f"[*] Delay  : {self.delay_ms}ms between requests")
        print(f"[*] Timeout: {self.timeout}s")
        if self.dry_run:
            print("[!] DRY RUN — no network requests will be sent")
        print()

        for i, p in enumerate(payloads, 1):
            result = self._run_single(p)
            self.results.append(result)

            verdict_color = {
                "BLOCKED": "\033[92m",  # green - good, WAF worked
                "ALLOWED": "\033[91m",  # red - bad, WAF missed
                "ERROR":   "\033[93m",  # yellow
            }.get(result.verdict, "\033[0m")
            reset = "\033[0m"
            status_display = result.actual_status if result.actual_status else "---"
            print(f"  [{i:3}/{len(payloads)}] {verdict_color}{result.verdict:<8}{reset} "
                  f"{status_display:<5} {result.id:<10} {result.name[:55]}")

            if self.delay_ms and not self.dry_run:
                time.sleep(self.delay_ms / 1000.0)

        return self.results

    def _run_single(self, payload: Dict) -> PayloadResult:
        method = payload["method"]
        path = payload["path"]
        query = payload.get("query")
        body_obj = payload.get("body")
        content_type = payload.get("content_type", "")
        extra_headers = payload.get("headers", {})
        url = build_url(self.target, path, query)

        headers = {
            "User-Agent": self.DEFAULT_UA,
            "Accept": "*/*",
        }
        headers.update(self.custom_headers)
        headers.update(extra_headers)

        body_bytes = None
        if body_obj is not None:
            if isinstance(body_obj, (dict, list)):
                body_bytes = json.dumps(body_obj).encode("utf-8")
                headers.setdefault("Content-Type", content_type or "application/json")
            else:
                body_bytes = str(body_obj).encode("utf-8")
                headers.setdefault("Content-Type", content_type or "text/plain")

        result = PayloadResult(
            id=payload["id"],
            name=payload["name"],
            category=payload["_category"],
            cwe=payload.get("_cwe", ""),
            method=method,
            url=url,
            severity=payload.get("severity", "MEDIUM"),
            expected=payload.get("expected", "block"),
        )

        if self.dry_run:
            result.verdict = "DRY_RUN"
            return result

        try:
            status, body_snippet, elapsed = send_request(
                method, url, headers, body_bytes,
                timeout=self.timeout, verify_ssl=self.verify_ssl
            )
            result.actual_status = status
            result.actual_body_snippet = body_snippet
            result.latency_ms = round(elapsed, 1)
            result.waf_hit = is_waf_block(status, body_snippet)
            if result.waf_hit:
                result.verdict = "BLOCKED"
            else:
                result.verdict = "ALLOWED"
        except Exception as e:
            result.verdict = "ERROR"
            result.error = str(e)[:200]
        return result

    def summary(self) -> Summary:
        s = Summary(
            target=self.target,
            started_at=datetime.utcnow().isoformat() + "Z",
            total_tests=len(self.results),
        )
        for r in self.results:
            if r.verdict == "BLOCKED":
                s.blocked += 1
            elif r.verdict == "ALLOWED":
                s.allowed += 1
            elif r.verdict == "ERROR":
                s.errors += 1

            cat = r.category
            s.by_category.setdefault(cat, {"blocked": 0, "allowed": 0, "errors": 0})
            s.by_category[cat][r.verdict.lower() if r.verdict != "UNKNOWN" else "errors"] = \
                s.by_category[cat].get(r.verdict.lower() if r.verdict != "UNKNOWN" else "errors", 0) + 1

            sev = r.severity
            s.by_severity.setdefault(sev, {"blocked": 0, "allowed": 0, "errors": 0})
            s.by_severity[sev][r.verdict.lower() if r.verdict != "UNKNOWN" else "errors"] = \
                s.by_severity[sev].get(r.verdict.lower() if r.verdict != "UNKNOWN" else "errors", 0) + 1

        if s.total_tests:
            s.coverage_percent = round(s.blocked / s.total_tests * 100, 1)
        return s


# --- CLI --------------------------------------------------------------------
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="WAF Bypass Lab — defensive WAF coverage assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AUTHORIZATION_NOTICE,
    )
    parser.add_argument("target", nargs="?", help="Target URL (e.g. https://staging.myapp.com)")
    parser.add_argument("--i-am-authorized-to-test", action="store_true",
                        help="REQUIRED: confirm you have written authorization to test the target")
    parser.add_argument("-p", "--payloads", default="payloads",
                        help="Path to payloads directory (default: payloads/)")
    parser.add_argument("-c", "--category", action="append",
                        help="Only run this category (repeat for multiple)")
    parser.add_argument("-n", "--max-tests", type=int, default=None,
                        help="Cap total tests (useful for smoke tests)")
    parser.add_argument("--delay-ms", type=int, default=200,
                        help="Delay between requests in ms (default: 200)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header to add to every request (e.g. -H 'X-Test: 1')")
    parser.add_argument("--dry-run", action="store_true",
                        help="Load payloads and print plan without sending any requests")
    parser.add_argument("-o", "--output", default="reports/waf_report.json")
    parser.add_argument("--html", default="reports/waf_report.html")
    parser.add_argument("--list-categories", action="store_true",
                        help="List available payload categories and exit")
    args = parser.parse_args()

    print(BANNER)

    if args.list_categories:
        for f in sorted(Path(args.payloads).glob("*.json")):
            data = json.loads(f.read_text(encoding="utf-8"))
            print(f"  - {data['category']:<35} ({len(data['payloads'])} payloads)  [{f.name}]")
        return

    if not args.target:
        parser.print_help()
        sys.exit(2)

    if not args.dry_run and not args.i_am_authorized_to_test:
        print(AUTHORIZATION_NOTICE)
        print("ERROR: --i-am-authorized-to-test flag is required.")
        print("       Pass this flag to confirm you have written authorization.")
        sys.exit(2)

    custom_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    lab = WafBypassLab(
        target=args.target,
        payloads_dir=args.payloads,
        delay_ms=args.delay_ms,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        custom_headers=custom_headers,
        dry_run=args.dry_run,
    )

    results = lab.run(categories_filter=args.category, max_tests=args.max_tests)
    summary = lab.summary()

    print()
    print("=" * 60)
    print(f"  Target coverage : {summary.coverage_percent}%  ({summary.blocked}/{summary.total_tests} blocked)")
    print(f"  Blocked         : {summary.blocked}")
    print(f"  Allowed         : {summary.allowed}  <-- GAPS, investigate these")
    print(f"  Errors          : {summary.errors}")
    print("=" * 60)
    print()
    print("Coverage by category:")
    for cat, counts in summary.by_category.items():
        total = sum(counts.values())
        blocked = counts.get("blocked", 0)
        pct = round(blocked / total * 100, 1) if total else 0
        print(f"  {cat:<35} {blocked:>3}/{total:<3}  {pct}%")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fp:
        json.dump({
            "summary": asdict(summary),
            "results": [asdict(r) for r in results]
        }, fp, indent=2)
    print()
    print(f"[+] JSON report: {args.output}")

    from report_generator import generate_html
    generate_html(summary, results, args.html)
    print(f"[+] HTML report: {args.html}")


if __name__ == "__main__":
    main()

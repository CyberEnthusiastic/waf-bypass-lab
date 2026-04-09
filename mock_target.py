"""
Mock WAF target for offline testing of waf_lab.py.

Simulates a basic WAF by blocking known attack signatures with HTTP 403.
Run this first, then point waf_lab.py at http://127.0.0.1:8088 for an
end-to-end demo without touching any real infrastructure.
"""
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

BLOCK_PATTERNS = [
    # SQLi
    r"union\s+select",
    r"' or '1'='1",
    r"information_schema",
    r"waitfor\s+delay",
    r"load_file",
    r"into\s+outfile",
    r"xp_cmdshell",
    r"benchmark\s*\(",
    r"@@version",
    r"is_srvrolemember",
    r"sys\.(databases|objects)|sysobjects",
    r"0x[0-9a-f]{10,}",
    r"having\s+\d+=\d+",
    r"\$ne\b|\$regex\b|\$where\b",
    r"';?\s*(drop|delete|insert|select)\s",
    r"cast\s*\(\s*\(",
    r"'\s*and\s*\d+=",
    r"'\s*\)\s*(union|and|or)\s",
    r"substring\s*\(",
    # XSS
    r"<script",
    r"<svg\s+onload",
    r"<svg/onload",
    r"<img\s+[^>]*onerror",
    r"javascript:",
    r"xss:expression",
    r"<body\s+onload",
    r"<iframe\s+srcdoc",
    r"document\.cookie",
    r"alert\s*\(",
    r"&lt;script",
    # Log4j
    r"\$\{jndi:",
    r"\$\{.*jndi",
    r"%24%7bjndi",
    r"%2524%257b",
    # LFI / Traversal
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"%252e%252e",
    r"%5c\.\.",
    r"%c0%af",
    r"file://",
    r"/etc/(passwd|shadow|group)",
    r"windows/system32",
    r"/proc/(self|version|cpuinfo)",
    r"etc\\passwd",
    # RFI
    r"php://filter",
    r"php://input",
    r"data://text",
    r"data:.*base64,",
    r"ftp://[^\"]*\.(txt|php)",
    r"https?://[^\"]*shell",
    r"https?://[^\"]*r57",
    r"https?://[^\"]*c\d+\.php",
    r"https?://[^\"]*exploit",
    # Cmd injection
    r"(?:;|\|)\s*(cat|ls|id|whoami|dir|uname)",
    r"`(id|whoami|ls|cat)`",
    r"\$\((whoami|id|ls|cat)",
    r"\$\$\(whoami",
    r"&&\s*(cat|ls|whoami|dir|echo)",
    r"\|\|\s*(ls|cat|whoami)",
    r"echo\s+\$\(",
    r"invoke-expression|downloadstring",
    r"curl\s+http.*\|\s*bash",
    r"Y2F0IC9ldGMvcGFzc3dk",
    r"\bdir\s+c:\\",
    # SSRF
    r"169\.254\.169\.254",
    r"169\.254\.170\.2",
    r"metadata\.google\.internal",
    r"127\.0\.0\.1:9001",
    r"localhost:\d+/admin",
    r"x-aws-ec2-metadata-token",
    # Scanners
    r"sqlmap", r"nikto", r"\bnmap\b", r"nessus", r"dirbuster", r"wpscan",
    r"arachni", r"gobuster", r"metasploit", r"owasp[\s-]?zap", r"burp",
    r"havij", r"w3af", r"w00tw00t", r"acunetix",
    r"dirb-", r"appscan", r"nessus_is_probing", r"netsparker",
    # WPA
    r"%0d%0aset-cookie",
    r"\\r\\nset-cookie",
    r"transfer-encoding.*chunked.*identity",
    r"%EF%BC%9C",
    r"bytes=0-9{20,}",
    r"connection:.*keep-alive.*x-forwarded-for",
    r"proxy-connection",
    r"content-encoding.*gzip.*deflate",
    r"expect:.*100-continue.*malicious",
]
BLOCK_RE = re.compile("|".join(BLOCK_PATTERNS), re.IGNORECASE)


class MockWafHandler(BaseHTTPRequestHandler):
    def do_GET(self):     self._handle()
    def do_POST(self):    self._handle()
    def do_PUT(self):     self._handle()
    def do_DELETE(self):  self._handle()
    def do_HEAD(self):    self._handle()

    def log_message(self, format, *args):
        pass  # silent

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def _handle(self):
        body = self._read_body() if self.command in ("POST", "PUT", "DELETE") else ""
        # Decode the path TWICE to catch both single and double URL encoding
        decoded_once = urllib.parse.unquote(self.path)
        decoded_twice = urllib.parse.unquote(decoded_once)
        headers_blob = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        # Combine raw + decoded URL + headers + body for inspection
        inspect = f"{self.path}\n{decoded_once}\n{decoded_twice}\n{headers_blob}\n{body}"
        if BLOCK_RE.search(inspect):
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Access Denied</h1><p>Request blocked by mock WAF.</p></body></html>")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK - mock WAF allowed this request through")


def main():
    host = "127.0.0.1"
    port = 8088
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    print(f"[*] Mock WAF target listening on http://{host}:{port}")
    print("[*] All attack-like requests will be blocked with HTTP 403")
    print("[*] Benign requests return HTTP 200")
    print("[*] Press Ctrl+C to stop")
    try:
        HTTPServer((host, port), MockWafHandler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")


if __name__ == "__main__":
    main()

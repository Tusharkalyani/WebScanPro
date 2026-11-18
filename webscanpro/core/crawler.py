import time
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup

class CrawledResource:
    def __init__(self, url: str, path: str, method: str = "GET", status_code: int = 200,
                 content_type: str = "", forms: list = None, params: list = None,
                 headers: dict = None, body_sample: str = ""):
        self.url = url
        self.path = path
        self.method = method
        self.status_code = status_code
        self.content_type = content_type
        self.forms = forms or []
        self.params = params or []
        self.headers = headers or {}
        self.body_sample = body_sample

    def to_dict(self):
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "forms": self.forms,
            "params": self.params,
        }


class SafeCrawler:
    """
    Polite, controlled web crawler engineered for local security assessments.
    Enforces strict origin boundaries, page budgets, crawl depth limits,
    media filtering, and session preservation (avoids auto-logging out).
    """

    EXCLUDED_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".mp3", ".webm", ".avi",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx"
    }

    LOGOUT_KEYWORDS = {"logout", "signout", "log-out", "sign-out", "exit", "disconnect"}

    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 30,
                 timeout: int = 5, rate_limit_delay: float = 0.05,
                 session_cookies: dict = None, custom_headers: dict = None,
                 logger_callback=None):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.target_origin = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"
        
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.logger = logger_callback or (lambda level, msg: None)

        # HTTP Session setup
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebScanPro-Security-Audit/1.0 (Authorized Security Evaluation)",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
        })
        if session_cookies:
            self.session.cookies.update(session_cookies)
        if custom_headers:
            self.session.headers.update(custom_headers)

        self.visited_urls = set()
        self.resources = []
        self.request_count = 0

    def is_same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        return (parsed.scheme == self.parsed_base.scheme and
                parsed.netloc.lower() == self.parsed_base.netloc.lower())

    def should_skip_path(self, url: str) -> bool:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        # Check file extensions
        for ext in self.EXCLUDED_EXTENSIONS:
            if path_lower.endswith(ext):
                return True

        # Avoid unintentional logout during authenticated crawls
        for kw in self.LOGOUT_KEYWORDS:
            if kw in path_lower or kw in (parsed.query or "").lower():
                self.logger("WARNING", f"Skipping logout URL to preserve session: {url}")
                return True

        return False

    def canonicalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # Sort query params for consistent deduplication
        qs = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted([(k, v[0]) for k, v in qs.items() if v]))
        
        norm_path = parsed.path if parsed.path else "/"
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            norm_path,
            "",
            sorted_query,
            ""  # Strip fragment
        ))

    def extract_forms(self, soup: BeautifulSoup, current_url: str) -> list:
        forms_data = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = urljoin(current_url, action) if action else current_url

            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                input_type = tag.get("type", "text") if tag.name == "input" else tag.name
                val = tag.get("value", "")
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "default_value": val
                })

            forms_data.append({
                "action": action_url,
                "method": method,
                "inputs": inputs,
                "raw_html": str(form)[:300]
            })
        return forms_data

    def extract_params(self, url: str) -> list:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return [{"name": k, "value": v[0] if v else "", "location": "query"} for k, v in qs.items()]

    def crawl(self) -> list:
        """
        Executes bounded breadth-first crawl starting from base_url.
        Returns list of CrawledResource objects.
        """
        queue = [(self.base_url, 0)]
        self.visited_urls.add(self.canonicalize_url(self.base_url))

        self.logger("INFO", f"Starting safe crawl of target: {self.base_url} (Max Depth: {self.max_depth}, Max Pages: {self.max_pages})")

        while queue and len(self.resources) < self.max_pages:
            current_url, depth = queue.pop(0)

            if depth > self.max_depth:
                continue

            try:
                time.sleep(self.rate_limit_delay)
                self.request_count += 1
                
                resp = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )

                content_type = resp.headers.get("Content-Type", "")
                is_html = "text/html" in content_type or "application/xhtml" in content_type
                
                forms = []
                body_sample = resp.text[:1000] if resp.text else ""
                
                if is_html and resp.text:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    forms = self.extract_forms(soup, resp.url)

                    # Extract new links if within depth limit
                    if depth < self.max_depth:
                        for a in soup.find_all("a", href=True):
                            raw_href = a["href"].strip()
                            if not raw_href or raw_href.startswith("#") or raw_href.startswith("javascript:"):
                                continue

                            abs_link = urljoin(resp.url, raw_href)
                            if self.is_same_origin(abs_link) and not self.should_skip_path(abs_link):
                                canon = self.canonicalize_url(abs_link)
                                if canon not in self.visited_urls and len(self.visited_urls) < self.max_pages * 2:
                                    self.visited_urls.add(canon)
                                    queue.append((abs_link, depth + 1))

                params = self.extract_params(resp.url)
                
                resource = CrawledResource(
                    url=resp.url,
                    path=urlparse(resp.url).path or "/",
                    method="GET",
                    status_code=resp.status_code,
                    content_type=content_type,
                    forms=forms,
                    params=params,
                    headers=dict(resp.headers),
                    body_sample=body_sample
                )
                self.resources.append(resource)
                self.logger("INFO", f"Crawled [{resp.status_code}] {resp.url} (Forms: {len(forms)}, Params: {len(params)})")

            except requests.exceptions.RequestException as e:
                self.logger("WARNING", f"Request failed for {current_url}: {str(e)}")

        self.logger("SUCCESS", f"Crawl complete. Discovered {len(self.resources)} endpoints across {self.request_count} requests.")
        return self.resources

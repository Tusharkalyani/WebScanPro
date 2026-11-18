import ipaddress
import socket
from urllib.parse import urlparse, urlunparse
import requests
from config import Config

class TargetValidationError(Exception):
    pass

class TargetValidator:
    """
    Strict security boundary validator ensuring scans are exclusively conducted
    against authorized local labs, private test networks, and loopback addresses.
    """

    ALLOWED_SCHEMES = ("http", "https")
    
    @staticmethod
    def normalize_url(url: str) -> str:
        if not url or not url.strip():
            raise TargetValidationError("URL cannot be empty.")
        
        url = url.strip()
        if "://" in url:
            scheme = url.split("://", 1)[0].lower()
            if scheme not in TargetValidator.ALLOWED_SCHEMES:
                raise TargetValidationError(f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
        else:
            url = "http://" + url

        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme.lower() not in TargetValidator.ALLOWED_SCHEMES:
            raise TargetValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        if not parsed.netloc:
            raise TargetValidationError("Invalid URL format: missing host/domain.")

        # Reconstruct canonical base (scheme + netloc + normalized path, remove query/fragment for base)
        normalized_path = parsed.path if parsed.path else "/"
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path

        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            "", "", ""
        ))
        return normalized.rstrip("/") if normalized_path == "/" else normalized

    @staticmethod
    def is_loopback_or_private(host: str) -> bool:
        # Strip port if present
        hostname = host.split(":")[0].strip("[]")
        
        # Check standard loopback aliases
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver"):
            return True

        try:
            # Try parsing as IP address directly
            ip_obj = ipaddress.ip_address(hostname)
            return ip_obj.is_loopback or ip_obj.is_private
        except ValueError:
            pass

        # Try resolving host to IP to prevent DNS rebinding or public redirects
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
            return ip_obj.is_loopback or ip_obj.is_private
        except Exception:
            return False

    @staticmethod
    def validate_target(url: str, is_explicitly_authorized: bool = False, custom_allowed_hosts=None) -> dict:
        """
        Validates the target URL and verifies authorization status.
        Returns dict with status, normalized_url, host, and port.
        """
        if not is_explicitly_authorized:
            raise TargetValidationError(
                "Target scan rejected: Explicit target authorization confirmation is required. "
                "Only scan targets you own or are legally authorized to test."
            )

        normalized = TargetValidator.normalize_url(url)
        parsed = urlparse(normalized)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        allowed_hosts = list(Config.ALLOWED_TARGET_HOSTS)
        if custom_allowed_hosts:
            allowed_hosts.extend(custom_allowed_hosts)

        # Check if explicitly in allowed hosts
        is_allowed = host.lower() in [h.lower() for h in allowed_hosts]

        # Or if private / loopback IP is enabled
        if not is_allowed and Config.ALLOW_PRIVATE_IPS:
            is_allowed = TargetValidator.is_loopback_or_private(host)

        if not is_allowed:
            raise TargetValidationError(
                f"Security Boundary Enforcement: Host '{host}' is not on the authorized target allowlist. "
                "By default, WebScanPro only permits local lab environments (localhost, 127.0.0.1, private lab subnets)."
            )

        return {
            "valid": True,
            "normalized_url": normalized,
            "scheme": parsed.scheme,
            "host": host,
            "port": port,
        }

    @staticmethod
    def check_target_connectivity(url: str, timeout: int = 4) -> dict:
        """
        Quick connectivity probe before starting crawl/scan.
        """
        try:
            normalized = TargetValidator.normalize_url(url)
            resp = requests.get(normalized, timeout=timeout, allow_redirects=True, verify=False)
            return {
                "alive": True,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", "Unknown"),
                "content_type": resp.headers.get("Content-Type", ""),
                "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                "error": None,
            }
        except requests.exceptions.RequestException as e:
            return {
                "alive": False,
                "status_code": None,
                "server": None,
                "content_type": None,
                "response_time_ms": None,
                "error": str(e),
            }

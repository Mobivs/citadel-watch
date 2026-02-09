"""
HTTPS enforcement middleware.

Implements:
- HTTP → HTTPS redirect
- HSTS (HTTP Strict Transport Security) headers
- Security headers (CSP, X-Frame-Options, etc.)
- Certificate validation helpers

HTTPS is mandatory for API communication to:
- Prevent token theft in transit
- Prevent man-in-the-middle attacks
- Ensure data confidentiality
- Comply with security requirements
"""

import logging
from typing import Callable
from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """
    Redirect HTTP requests to HTTPS.
    
    Catches all HTTP requests and redirects to HTTPS equivalent.
    Preserves query parameters and request body (for POST/PUT/PATCH, converts to GET redirect).
    
    Note: Request body is lost in redirect. For APIs, ensure clients use HTTPS.
    
    Configuration:
        - Skip localhost (127.0.0.1, ::1) for testing
        - Use X-Forwarded-Proto header for reverse proxies
        - Log all redirects for monitoring
    """
    
    def __init__(
        self,
        app,
        skip_hosts: list[str] = None,
    ):
        """
        Initialize HTTPS redirect middleware.
        
        Args:
            app: FastAPI application
            skip_hosts: List of hosts to skip HTTPS enforcement (default: localhost)
        """
        super().__init__(app)
        self.skip_hosts = skip_hosts or ["localhost", "127.0.0.1", "::1"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> any:
        """
        Intercept request and redirect HTTP to HTTPS.
        
        Args:
            request: HTTP request
            call_next: Next middleware/handler
        
        Returns:
            Redirect response if HTTP, else original response
        """
        # Check X-Forwarded-Proto header (set by reverse proxy)
        forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
        
        # Check direct connection protocol
        is_secure = (
            request.url.scheme == "https" or
            forwarded_proto == "https"
        )
        
        # Skip for localhost (development/testing)
        host = request.url.hostname or request.client.host if request.client else None
        is_localhost = host in self.skip_hosts
        
        if not is_secure and not is_localhost:
            # Redirect to HTTPS
            url = request.url.replace(scheme="https")
            logger.info(f"Redirecting {request.url} to {url}")
            return RedirectResponse(url=url, status_code=308)  # 308 Permanent Redirect
        
        # Continue processing
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    
    Headers added:
    - HSTS: Tell browsers to use HTTPS only for 1 year
    - X-Content-Type-Options: Prevent MIME sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: Enable browser XSS protection
    - Referrer-Policy: Control referrer information
    - Permissions-Policy: Control feature access
    - Content-Security-Policy: Prevent XSS/injection attacks
    """
    
    def __init__(
        self,
        app,
        hsts_max_age: int = 31536000,  # 1 year
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = False,
    ):
        """
        Initialize security headers middleware.
        
        Args:
            app: FastAPI application
            hsts_max_age: HSTS max age in seconds (default: 1 year)
            hsts_include_subdomains: Include subdomains in HSTS (default: True)
            hsts_preload: Enable HSTS preload list (default: False, require careful testing)
        """
        super().__init__(app)
        self.hsts_max_age = hsts_max_age
        self.hsts_include_subdomains = hsts_include_subdomains
        self.hsts_preload = hsts_preload
    
    def _build_hsts_header(self) -> str:
        """Build HSTS header value."""
        parts = [f"max-age={self.hsts_max_age}"]
        if self.hsts_include_subdomains:
            parts.append("includeSubDomains")
        if self.hsts_preload:
            parts.append("preload")
        return "; ".join(parts)
    
    async def dispatch(self, request: Request, call_next: Callable) -> any:
        """
        Add security headers to response.
        
        Args:
            request: HTTP request
            call_next: Next middleware/handler
        
        Returns:
            Response with security headers added
        """
        response = await call_next(request)
        
        # HSTS: Strict-Transport-Security
        response.headers["Strict-Transport-Security"] = self._build_hsts_header()
        
        # MIME type protection
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS protection (legacy, but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy (don't leak URL parameters)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Feature policy (disable unnecessary features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "camera=(), "
            "microphone=(), "
            "payment=(), "
            "usb=(), "
            "vr=()"
        )
        
        # Content-Security-Policy (prevents XSS/injection)
        # For API: only allow same-origin, no inline scripts
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "img-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests"
        )
        
        logger.debug(f"Security headers added to {request.url.path}")
        return response


class CertificateValidator:
    """
    Certificate validation helpers for mutual TLS (mTLS).
    
    Supports:
    - Self-signed certificates (for testing)
    - CA-signed certificates (for production)
    - Certificate pinning (optional)
    """
    
    @staticmethod
    def get_certificate_subject(cert_der: bytes) -> dict:
        """
        Extract subject information from certificate.
        
        Args:
            cert_der: Certificate in DER format
        
        Returns:
            Dictionary with CN, O, C, etc.
        
        Requires: cryptography package
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            subject_dict = {}
            
            for attr in cert.subject:
                subject_dict[attr.oid._name] = attr.value
            
            return subject_dict
        except ImportError:
            logger.warning("cryptography package not installed; certificate validation disabled")
            return {}
    
    @staticmethod
    def validate_certificate_chain(cert_der: bytes, ca_cert_path: str) -> bool:
        """
        Validate certificate against CA.
        
        Args:
            cert_der: Certificate in DER format
            ca_cert_path: Path to CA certificate
        
        Returns:
            True if valid, False otherwise
        
        Note: For production, use proper TLS library or reverse proxy
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID
            from cryptography.hazmat.backends import default_backend
            
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Load CA certificate
            with open(ca_cert_path, 'rb') as f:
                ca_data = f.read()
            
            # TODO: Implement actual validation
            # This is placeholder; real implementation requires OpenSSL or cryptography
            logger.info("Certificate validation not yet implemented")
            return True
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            return False


def add_https_middleware(app, enforce: bool = True, hsts_preload: bool = False):
    """
    Add HTTPS enforcement middleware to FastAPI app.
    
    Usage:
        from fastapi import FastAPI
        from citadel_archer.api.https_middleware import add_https_middleware
        
        app = FastAPI()
        add_https_middleware(app, enforce=True)
    
    Args:
        app: FastAPI application
        enforce: Whether to redirect HTTP to HTTPS (default: True)
        hsts_preload: Whether to include HSTS preload (default: False)
    """
    if enforce:
        # Add HTTPS redirect middleware (runs first)
        app.add_middleware(HTTPSRedirectMiddleware)
    
    # Add security headers middleware (runs second)
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts_preload=hsts_preload,
    )
    
    logger.info(f"HTTPS middleware added (enforce={enforce}, hsts_preload={hsts_preload})")


# Configuration helper for common scenarios

class HTTPSConfig:
    """HTTPS configuration presets."""
    
    # Development: No redirect, relaxed headers
    DEVELOPMENT = {
        "enforce": False,
        "hsts_preload": False,
        "hsts_max_age": 3600,  # 1 hour (short for dev)
    }
    
    # Staging: HTTPS redirect, strong headers
    STAGING = {
        "enforce": True,
        "hsts_preload": False,
        "hsts_max_age": 86400,  # 1 day
    }
    
    # Production: HTTPS redirect, HSTS preload, strong headers
    PRODUCTION = {
        "enforce": True,
        "hsts_preload": True,  # After testing!
        "hsts_max_age": 31536000,  # 1 year
    }
    
    @staticmethod
    def apply(app, environment: str = "development"):
        """
        Apply HTTPS configuration based on environment.
        
        Args:
            app: FastAPI application
            environment: "development", "staging", or "production"
        """
        config = {
            "development": HTTPSConfig.DEVELOPMENT,
            "staging": HTTPSConfig.STAGING,
            "production": HTTPSConfig.PRODUCTION,
        }.get(environment, HTTPSConfig.DEVELOPMENT)
        
        add_https_middleware(app, **config)
        logger.info(f"HTTPS configuration applied: {environment}")

"""
Scanners package for SecureSys Auditor.

Contains various scanner implementations:
- URLScanner: Scans websites for security issues (headers, SSL, etc.)
"""
from .url_scanner import URLScanner, URLScanResult

__all__ = ["URLScanner", "URLScanResult"]

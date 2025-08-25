"""Simple rule‑based engine inspired by the OWASP CRS.

The functions in this module implement a first‑pass signature checker for
incoming HTTP requests.  It scans request lines, bodies, cookies and a
selected subset of headers for patterns that often indicate attacks.  Only
very common patterns are included here; the rule set can be extended by
adding additional regular expressions to the ``SIGNATURES`` dictionary.

If a request matches any signature the engine returns a dictionary mapping
the detected threat type (e.g. ``'sqli'``) to the part of the request in
which it was found (e.g. ``'Request'``).  When no pattern matches an empty
dictionary is returned.
"""

from __future__ import annotations
import re
import urllib.parse
import json
from typing import Dict, List
from .request import Request

# Precompile a handful of regular expressions for common attack categories.
# These patterns are derived from the OWASP CRS but drastically simplified
# for demonstration purposes.  They are case insensitive and will catch
# obvious attempts; however, they are neither complete nor tuned to avoid
# false positives.
SIGNATURES: Dict[str, List[re.Pattern]] = {
    # SQL injection patterns
    'sqli': [
        re.compile(r"(?:\bunion\b\s+select|\bselect\b.+\bfrom\b)", re.I),
        re.compile(r"(?:\bdrop\b\s+table|\binsert\b\s+into|\bupdate\b\s+\w+\s+set)", re.I),
        re.compile(r"(?:'\s*or\s*'\d+'='\d+'|'\s*or\s*1=1|\bor\b\s+1=1)", re.I),
        # detect semicolon or double dash comments which are typical in SQL injection.
        # The original pattern had an extra double quote which broke the string literal.
        re.compile(r"(?:;\s*--|--\s*)", re.I),
        re.compile(r"\b(benchmark|sleep|information_schema)\b", re.I),
    ],
    # Cross‑site scripting patterns
    'xss': [
        re.compile(r"<\s*script", re.I),
        re.compile(r"<\s*img\b[^>]*\bonerror\b", re.I),
        re.compile(r"javascript:\s*", re.I),
        re.compile(r"onload\s*=", re.I),
        re.compile(r"alert\s*\(", re.I),
    ],
    # Command injection patterns
    'cmdi': [
        re.compile(r"(?:;|&&|\|\||\|)\s*\w+", re.I),
        re.compile(r"`[^`]+`", re.I),
        re.compile(r"\b(cat|ls|rm|wget|curl|whoami|powershell|cmd\.exe|sh)\b", re.I),
    ],
    # Path traversal patterns
    'path-traversal': [
        re.compile(r"\.\.\s*/", re.I),
        re.compile(r"\.\.\\", re.I),
        re.compile(r"(?:/|\\)etc(?:/|\\)passwd", re.I),
        re.compile(r"web-inf|boot\.ini", re.I),
    ],
}

def _unquote(text: str) -> str:
    """Repeatedly decode percent‑encoded text until it stops changing."""
    k = 0
    prev = text
    while k < 5:  # limit recursion depth to avoid pathological cases
        decoded = urllib.parse.unquote_plus(prev)
        if decoded == prev:
            break
        prev = decoded
        k += 1
    return prev


def _clean(text: str) -> str:
    """Normalise a piece of text for signature matching."""
    if text is None:
        return ''
    # unquote and lower‑case
    t = _unquote(text)
    t = ' '.join(t.strip().split())  # collapse whitespace
    return t.lower()


def scan_request(req: Request) -> Dict[str, str]:
    """Scan the given request for signature matches.

    Returns a dict mapping detected threat types to the location in the
    request where the match occurred.  The function examines the request
    line, the body, the Cookie header and several other headers.  If a
    parameter value is longer than 100 characters a ``parameter‑tampering``
    threat is recorded.
    """
    threats: Dict[str, str] = {}
    # Prepare list of (text, location) tuples to scan
    to_scan: List[tuple] = []
    if req.request:
        to_scan.append((_clean(req.request), 'Request'))
    if req.body:
        to_scan.append((_clean(req.body), 'Body'))
    # Inspect cookies and user‑agent / encoding headers
    for header in ['Cookie', 'User_Agent', 'Accept_Encoding', 'Accept_Language']:
        value = req.headers.get(header)
        if value:
            to_scan.append((_clean(value), header.replace('_', ' ')))
    # Signature matching
    for text, location in to_scan:
        for threat, patterns in SIGNATURES.items():
            if threat in threats:
                continue  # already recorded
            for pat in patterns:
                if pat.search(text):
                    threats[threat] = location
                    break
    # Parameter tampering: parse query and body parameters; if any value > 100
    try:
        query_params = urllib.parse.parse_qs(_clean(req.request or ''))
    except Exception:
        query_params = {}
    body_params: Dict[str, List[str]] = {}
    if req.body:
        # attempt URL decoding first
        bclean = _clean(req.body)
        body_params = urllib.parse.parse_qs(bclean)
        if not body_params:
            # try json
            try:
                obj = json.loads(req.body)
                for k, v in obj.items():
                    body_params[k] = [str(v)]
            except Exception:
                pass
    # check lengths
    for vlist in list(query_params.values()) + list(body_params.values()):
        for v in vlist:
            if len(str(v)) > 100:
                threats['parameter-tampering'] = 'Body' if body_params else 'Request'
                break
        if 'parameter-tampering' in threats:
            break
    return threats
"""
Audit web minimal : effectue requête HTTP/HTTPS avec timeout et vérifie
présence des headers de sécurité demandés.
"""
from typing import Dict, Any
import requests
import logging

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    'X-Frame-Options',
    'Content-Security-Policy',
    'Strict-Transport-Security'
]


def audit_web(host: str, port: int = 80, timeout: float = 3.0) -> Dict[str, Any]:
    """Fait une requête GET vers l'hôte:port (ou HTTPS si port==443).
    Retourne dict avec status_code, présent/absent headers, et erreur si présent.
    """
    scheme = 'https' if port == 443 else 'http'
    url = f"{scheme}://{host}:{port}/"
    result: Dict[str, Any] = {'url': url, 'status_code': None, 'headers': {}, 'missing': [], 'error': None}
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        result['status_code'] = resp.status_code
        hdrs = {k: v for k, v in resp.headers.items()}
        result['headers'] = hdrs
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        result['missing'] = missing
    except requests.exceptions.SSLError as e:
        result['error'] = f"SSL error: {e}"
    except requests.exceptions.Timeout:
        result['error'] = 'timeout'
    except requests.exceptions.RequestException as e:
        result['error'] = str(e)

    return result

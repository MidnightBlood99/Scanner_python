"""
Scan réseau (ping sweep) simple utilisant scapy.
Fonctions de niveau débutant, commentaires en français.
"""
from typing import List, Optional
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

try:
    from scapy.all import IP, ICMP, sr1
except Exception:
    raise SystemExit("scapy requis pour network_scan.py (voir requirements).")

logger = logging.getLogger(__name__)


def ping_host(host: str, timeout: float = 1.0) -> bool:
    """Ping ICMP simple. Retourne True si l'hôte répond."""
    try:
        pkt = IP(dst=str(host)) / ICMP()
        resp = sr1(pkt, verbose=0, timeout=timeout)
        return resp is not None
    except PermissionError:
        logger.warning("Permission refusée pour envoyer ICMP (droits admin requis).")
        return False
    except Exception as e:
        logger.debug(f"Erreur ping {host}: {e}")
        return False


def scan_network(target: str, timeout: float = 1.0, threads: int = 50) -> List[str]:
    """
    Scanne une cible qui peut être une IP unique, un hostname resolvable,
    ou un CIDR (ex: 192.168.1.0/24). Retourne la liste des hôtes "up".
    """
    hosts = []
    try:
        if '/' in target:
            net = ipaddress.ip_network(target, strict=False)
            candidates = [str(ip) for ip in net.hosts()]
        else:
            candidates = [target]
    except Exception:
        candidates = [target]

    up_hosts: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(ping_host, h, timeout): h for h in candidates}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                if fut.result():
                    up_hosts.append(h)
            except Exception as e:
                logger.debug(f"Erreur durant le ping de {h}: {e}")

    return up_hosts

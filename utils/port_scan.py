"""
Scans de ports basiques : TCP Connect et TCP Stealth (SYN) via scapy.
Commentaires en français, fonctions simples réutilisables.
"""
from typing import List, Dict
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


def parse_ports(port_str: str) -> List[int]:
    """Parse une chaîne comme '22,80,1000-1010' en liste d'entiers."""
    ports = set()
    if not port_str:
        return []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a_i = int(a); b_i = int(b)
                ports.update(range(a_i, b_i + 1))
            except Exception:
                continue
        else:
            try:
                ports.add(int(part))
            except Exception:
                continue
    return sorted(p for p in ports if 0 < p < 65536)


def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """Scan par socket TCP connect (méthode simple).
    Retourne True si le port est ouvert.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception as e:
        logger.debug(f"tcp_connect_scan {host}:{port} -> {e}")
        return False


def tcp_stealth_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """SYN scan minimal avec scapy. Nécessite scapy et souvent des droits admin.
    Retourne True si SYN-ACK reçu (port ouvert).
    """
    if not SCAPY_AVAILABLE:
        logger.warning("scapy non disponible: stealth scan indisponible")
        return False
    try:
        pkt = IP(dst=host) / TCP(dport=port, flags='S')
        resp = sr1(pkt, verbose=0, timeout=timeout)
        if resp is None:
            return False
        # SYN-ACK -> drapeau 'SA' dans scapy (SYN+ACK)
        if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12:
            # envoyer RST pour fermer proprement
            rst = IP(dst=host) / TCP(dport=port, flags='R')
            try:
                sr1(rst, verbose=0, timeout=0.5)
            except Exception:
                pass
            return True
        return False
    except PermissionError:
        logger.warning("PermissionError: stealth scan nécessite privilèges admin/root")
        return False
    except Exception as e:
        logger.debug(f"tcp_stealth_scan {host}:{port} -> {e}")
        return False


def scan_ports_for_host(host: str, ports: List[int], scan_type: str = 'connect', timeout: float = 1.0, threads: int = 50) -> List[int]:
    """Scan simple pour un hôte, retourne la liste des ports ouverts."""
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {}
        for p in ports:
            if scan_type == 'stealth':
                futures[ex.submit(tcp_stealth_scan, host, p, timeout)] = p
            else:
                futures[ex.submit(tcp_connect_scan, host, p, timeout)] = p

        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception as e:
                logger.debug(f"Erreur scan port {host}:{port} -> {e}")

    return sorted(open_ports)

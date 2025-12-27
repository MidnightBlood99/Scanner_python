"""
Script d'exemple simple pour démontrer l'utilisation des fonctions du projet.
Ne lance pas de stealth scan par défaut.
"""
from utils import port_scan
import json

def main():
    target = '127.0.0.1'
    ports = port_scan.parse_ports('22,80')
    print(f"Exemple: scan de {target} sur ports {ports}")
    open_ports = port_scan.scan_ports_for_host(target, ports, scan_type='connect', timeout=1.0, threads=2)
    out = {target: {'open_ports': open_ports}}
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    main()

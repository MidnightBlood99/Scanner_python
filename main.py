"""
Point d'entrée du scanner réseau 

Usage (exemples):
  python main.py --target 192.168.1.0/24 --mode full --ports 22,80,443 --threads 100

Options principales: --target, --mode, --ports, --threads, --timeout, --format, --output,
--scan-type (connect|stealth), --encrypt, --sign, --verbose

Ce fichier orchestre les modules dans `utils/`.
"""
import argparse
import logging
import json
import os
import base64
from typing import List, Dict, Any

from utils import network_scan, port_scan, web_scan, crypto_utils


def setup_logging(verbose: bool):
	level = logging.DEBUG if verbose else logging.INFO
	logging.basicConfig(level=level, format='[%(levelname)s] %(message)s')


def parse_args():
	p = argparse.ArgumentParser(description='Scanner réseau simple - niveau M1 débutant (fr)')
	p.add_argument('--target', '-t', required=True, help='IP, hostname ou CIDR (ex: 192.168.1.0/24)')
	p.add_argument('--mode', choices=['ping-scan', 'port-scan', 'web-scan', 'full'], default='full', help='Mode de scan')
	p.add_argument('--ports', default='22,80,443', help='Liste ou range de ports, ex: 22,80,1000-2000')
	p.add_argument('--threads', type=int, default=50, help='Nombre de threads (par défaut 50)')
	p.add_argument('--timeout', type=float, default=1.0, help='Timeout en secondes pour sockets/reqs')
	p.add_argument('--scan-type', choices=['connect','stealth'], default='connect', help='Méthode de scan de ports')
	p.add_argument('--output', '-o', default='scan_result', help='Chemin de sortie (sans extension)')
	p.add_argument('--format', choices=['json','txt'], default='json', help='Format de sortie')
	p.add_argument('--encrypt', action='store_true', help='Chiffrer la sortie (besoin SCANNER_SECRET_KEY env base64)')
	p.add_argument('--sign', action='store_true', help='Signer la sortie (besoin SCANNER_SIGNING_KEY env base64)')
	p.add_argument('--verbose', action='store_true', help='Verbose / debug logs')
	return p.parse_args()


def save_output(data: Dict[str, Any], outpath: str, fmt: str = 'json') -> str:
	"""Enregistre les résultats et retourne le chemin du fichier écrit."""
	if fmt == 'json':
		path = outpath + '.json'
		with open(path, 'w', encoding='utf-8') as f:
			json.dump(data, f, ensure_ascii=False, indent=2)
	else:
		path = outpath + '.txt'
		with open(path, 'w', encoding='utf-8') as f:
			# rendu texte basique pour étudiants
			for h, info in data.get('hosts', {}).items():
				f.write(f"Host: {h}\n")
				f.write(f"  up: {info.get('up')}\n")
				f.write(f"  open_ports: {info.get('open_ports')}\n")
				if info.get('web'):
					f.write(f"  web: {info.get('web')}\n")
				f.write('\n')
	return path


def main():
	args = parse_args()
	setup_logging(args.verbose)
	logger = logging.getLogger(__name__)
"""
Point d'entrée du scanner réseau étudiant.

Usage (exemples):
  python main.py --target 192.168.1.0/24 --mode full --ports 22,80,443 --threads 100

Options principales: --target, --mode, --ports, --threads, --timeout, --format, --output,
--scan-type (connect|stealth), --encrypt, --sign, --verbose

Ce fichier orchestre les modules dans `utils/`.
"""
import argparse
import logging
import json
import os
import base64
from typing import List, Dict, Any

from utils import network_scan, port_scan, web_scan, crypto_utils


def setup_logging(verbose: bool):
	level = logging.DEBUG if verbose else logging.INFO
	logging.basicConfig(level=level, format='[%(levelname)s] %(message)s')


def parse_args():
	p = argparse.ArgumentParser(description='Scanner réseau simple - niveau M1 débutant (fr)')
	p.add_argument('--target', '-t', required=True, help='IP, hostname ou CIDR (ex: 192.168.1.0/24)')
	p.add_argument('--mode', choices=['ping-scan', 'port-scan', 'web-scan', 'full'], default='full', help='Mode de scan')
	p.add_argument('--ports', default='22,80,443', help='Liste ou range de ports, ex: 22,80,1000-2000')
	p.add_argument('--threads', type=int, default=50, help='Nombre de threads (par défaut 50)')
	p.add_argument('--timeout', type=float, default=1.0, help='Timeout en secondes pour sockets/reqs')
	p.add_argument('--scan-type', choices=['connect','stealth'], default='connect', help='Méthode de scan de ports')
	p.add_argument('--output', '-o', default='scan_result', help='Chemin de sortie (sans extension)')
	p.add_argument('--format', choices=['json','txt'], default='json', help='Format de sortie')
	p.add_argument('--encrypt', action='store_true', help='Chiffrer la sortie (besoin SCANNER_SECRET_KEY env base64)')
	p.add_argument('--sign', action='store_true', help='Signer la sortie (besoin SCANNER_SIGNING_KEY env base64)')
	p.add_argument('--verbose', action='store_true', help='Verbose / debug logs')
	return p.parse_args()


def save_output(data: Dict[str, Any], outpath: str, fmt: str = 'json') -> str:
	"""Enregistre les résultats et retourne le chemin du fichier écrit."""
	if fmt == 'json':
		path = outpath + '.json'
		with open(path, 'w', encoding='utf-8') as f:
			json.dump(data, f, ensure_ascii=False, indent=2)
	else:
		path = outpath + '.txt'
		with open(path, 'w', encoding='utf-8') as f:
			# rendu texte basique pour étudiants
			for h, info in data.get('hosts', {}).items():
				f.write(f"Host: {h}\n")
				f.write(f"  up: {info.get('up')}\n")
				f.write(f"  open_ports: {info.get('open_ports')}\n")
				if info.get('web'):
					f.write(f"  web: {info.get('web')}\n")
				f.write('\n')
	return path


def main():
	args = parse_args()
	setup_logging(args.verbose)
	logger = logging.getLogger(__name__)

	ports = port_scan.parse_ports(args.ports)
	result: Dict[str, Any] = {'target': args.target, 'mode': args.mode, 'hosts': {}}

	# Étape ping-scan si demandée ou en mode full
	hosts = []
	if args.mode in ('ping-scan', 'full'):
		logger.info(f"Lancement ping-scan sur {args.target} (timeout={args.timeout})")
		hosts = network_scan.scan_network(args.target, timeout=args.timeout, threads=args.threads)
	else:
		hosts = [args.target]

	if not hosts:
		logger.info("Aucun hôte trouvé par le ping-scan; on continue avec la cible fournie si possible.")
		hosts = [args.target]

	# Pour chaque hôte, on réalise le scan de ports si demandé
	if args.mode in ('port-scan','full'):
		logger.info(f"Scan de ports ({args.scan_type}) sur {len(hosts)} hôte(s)")
		for h in hosts:
			try:
				open_ports = port_scan.scan_ports_for_host(h, ports, scan_type=args.scan_type, timeout=args.timeout, threads=args.threads)
			except Exception as e:
				logger.debug(f"Erreur scan ports {h}: {e}")
				open_ports = []
			result['hosts'][h] = {'up': True, 'open_ports': open_ports}
	else:
		for h in hosts:
			result['hosts'][h] = {'up': True, 'open_ports': []}

	# Audit web si demandé
	if args.mode in ('web-scan','full'):
		logger.info("Lancement audit web sur ports 80/443 détectés")
		for h, info in result['hosts'].items():
			web_results = []
			for p in info.get('open_ports', []):
				if p in (80, 443):
					r = web_scan.audit_web(h, p, timeout=args.timeout)
					web_results.append(r)
			info['web'] = web_results

	# Enregistrement
	outpath = args.output
	saved = save_output(result, outpath, fmt=args.format)
	logger.info(f"Résultats sauvegardés dans {saved}")

	# chiffrement / signature optionnels
	if args.encrypt:
		key_b64 = os.environ.get('SCANNER_SECRET_KEY')
		if not key_b64:
			logger.error('SCANNER_SECRET_KEY non défini; impossible de chiffrer')
		else:
			key = base64.b64decode(key_b64)
			with open(saved, 'rb') as f:
				data = f.read()
			ct = crypto_utils.encrypt_bytes(key, data)
			enc_path = saved + '.enc'
			with open(enc_path, 'wb') as f:
				f.write(ct)
			logger.info(f"Sortie chiffrée: {enc_path}")

	if args.sign:
		sk_b64 = os.environ.get('SCANNER_SIGNING_KEY')
		if not sk_b64:
			logger.error('SCANNER_SIGNING_KEY non défini; impossible de signer')
		else:
			sk = base64.b64decode(sk_b64)
			with open(saved, 'rb') as f:
				data = f.read()
			sig = crypto_utils.sign_bytes(sk, data)
			sig_path = saved + '.sig'
			with open(sig_path, 'wb') as f:
				f.write(sig)
			logger.info(f"Signature générée: {sig_path}")


if __name__ == '__main__':
	main()

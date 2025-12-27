<<<<<<< HEAD
# Scanner_python
Projet_sécu_python
=======
(The file `c:\Users\kamali\Documents (local)\python_s\u00e9cu\projet\README.md` exists, but is empty)
# Scanner réseau - Projet M1 débutant (fr)

Petit scanner réseau pédagogique (ping, port scan, audit web) écrit en Python.

Prérequis
- Python 3.8+ (virtualenv recommandé)
- Installer les dépendances :

```bash
python -m pip install -r requirements.txt
```

Notes importantes
- Le SYN/stealth scan nécessite `scapy` et souvent des privilèges administrateur/root.
- Les requêtes ICMP (ping) peuvent être bloquées par des firewalls ; résultat non garanti.
- Le chiffrement/signature utilise PyNaCl. Les clés doivent être fournies via variables d'environnement en base64 (voir ci-dessous).

Usage (exemples)

- Scan complet d'un /24 (ping + ports + web) :

```bash
python main.py --target 192.168.1.0/24 --mode full --ports 22,80,443 --threads 100
```

- Scan de ports (connect) d'une IP :

```bash
python main.py -t 10.0.0.5 --mode port-scan --ports 1-1024 --threads 50
```

- Audit web pour ports détectés (80/443) :

```bash
python main.py -t example.com --mode web-scan
```

Options utiles
- `--target`: IP, hostname ou CIDR
- `--mode`: `ping-scan`, `port-scan`, `web-scan`, `full`
- `--ports`: liste/range de ports (ex: `22,80,1000-2000`)
- `--threads`: nombre de threads (par défaut 50)
- `--timeout`: timeout en secondes
- `--scan-type`: `connect` ou `stealth`
- `--format`: `json` ou `txt` (format de sortie)
- `--output`: préfixe du fichier de sortie
- `--encrypt`: chiffrer la sortie (nécessite variable SCANNER_SECRET_KEY)
- `--sign`: signer la sortie (nécessite SCANNER_SIGNING_KEY)

# Scanner_python

Scanner réseau - Projet M1 débutant (fr)

Petit scanner réseau pédagogique (ping, port scan, audit web) écrit en Python.

Prérequis
- Python 3.8+ (virtualenv recommandé)
- Installer les dépendances :

```bash
python -m pip install -r requirements.txt
```

Notes importantes
- Le SYN/stealth scan nécessite `scapy` et souvent des privilèges administrateur/root.
- Les requêtes ICMP (ping) peuvent être bloquées par des firewalls ; résultat non garanti.
- Le chiffrement/signature utilise PyNaCl. Les clés doivent être fournies via variables d'environnement en base64 (voir ci-dessous).

Usage (exemples)

- Scan complet d'un /24 (ping + ports + web) :

```bash
python main.py --target 192.168.1.0/24 --mode full --ports 22,80,443 --threads 100
```

- Scan de ports (connect) d'une IP :

```bash
python main.py -t 10.0.0.5 --mode port-scan --ports 1-1024 --threads 50
```

- Audit web pour ports détectés (80/443) :

```bash
python main.py -t example.com --mode web-scan
```

Options utiles
- `--target`: IP, hostname ou CIDR
- `--mode`: `ping-scan`, `port-scan`, `web-scan`, `full`
- `--ports`: liste/range de ports (ex: `22,80,1000-2000`)
- `--threads`: nombre de threads (par défaut 50)
- `--timeout`: timeout en secondes
- `--scan-type`: `connect` ou `stealth`
- `--format`: `json` ou `txt` (format de sortie)
- `--output`: préfixe du fichier de sortie
- `--encrypt`: chiffrer la sortie (nécessite variable SCANNER_SECRET_KEY)
- `--sign`: signer la sortie (nécessite SCANNER_SIGNING_KEY)

Clés pour chiffrement / signature
- Fournir les clés en base64 via variables d'environnement :
	- `SCANNER_SECRET_KEY` : clé 32 bytes encodée en base64 pour SecretBox
	- `SCANNER_SIGNING_KEY` : clé SigningKey encodée en base64

Exemple de génération (linux/mac) :

```bash
python - <<'PY'
import base64, os
print('SCANNER_SECRET_KEY=' + base64.b64encode(os.urandom(32)).decode())
from nacl.signing import SigningKey
sk = SigningKey.generate()
print('SCANNER_SIGNING_KEY=' + base64.b64encode(sk.encode()).decode())
PY
```

Déchiffrer et vérifier
- Déchiffrer (Python rapide) : utiliser `crypto_utils.decrypt_bytes` après avoir décodé la clé base64.
- Vérifier signature : `crypto_utils.verify_signature(verify_key, data, signature)`

Limitations / avertissements
- Ce projet est pédagogique. Ne lancez pas de scans sur des réseaux que vous ne gérez pas.
- Le stealth scan peut être détecté et requiert des droits. ICMP peut être bloqué par des FW.

Structure
- `main.py` : point d'entrée
- `utils/network_scan.py` : ping-sweep
- `utils/port_scan.py` : connect & stealth
- `utils/web_scan.py` : audit HTTP/HTTPS
- `utils/crypto_utils.py` : chiffrement/signature (PyNaCl)

Support / tests rapides
- Vérifiez que `python main.py --help` affiche l'aide.
- Test local simple : `python main.py -t 127.0.0.1 --mode port-scan --ports 22,80 --format txt`

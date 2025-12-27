from typing import Optional

try:
    from scapy.all import IP, TCP, send, sr1, ICMP
except ImportError:
    raise SystemExit(
        "scapy is not installed in the current Python environment. "
        "Install it into the project's venv with:\n"
        "  cd projet && ./venv/Scripts/python -m pip install scapy\n"
        "Then ensure VS Code uses that interpreter (Reload window).")


target_ip = "127.0.0.1"

def simple_ping(target_ip: str, timeout: Optional[int] = 2) -> bool:
    """Send an ICMP ping to `target_ip`. Returns True if reply received."""
    pkt = IP(dst=target_ip) / ICMP()
    response = sr1(pkt, verbose=0, timeout=timeout)

    if response:
        print(f"\n{target_ip} is reachable: {response.summary()}")
        return True
    else:
        print(f"\n{target_ip} timeout")
        return False
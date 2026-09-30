import subprocess
from netfilterqueue import NetfilterQueue
from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR

QUEUE = [
    "OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass",
    "OUTPUT -p tcp --sport 22 -j ACCEPT",
    "INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1 --queue-bypass",
]

def iptables(flag):
    for cmd in ("iptables", "ip6tables"):
        for r in QUEUE:
            subprocess.run([cmd, flag, *r.split()])

rules = [l.split() for l in open("rules.txt") if l.strip() and not l.startswith("#")]
names = {}

def match(kind, value, ip, port):
    if kind == "all":
        return True
    if kind == "ip":
        return ip == value
    if kind == "port":
        return port == int(value)
    if kind == "domain":
        d = names.get(ip, "")
        return d == value or d.endswith("." + value)

def handle(pkt):
    raw = pkt.get_payload()
    p = IP(raw) if raw[0] >> 4 == 4 else IPv6(raw)

    if p.haslayer(DNSQR) and p[DNS].qr == 1:
        name = p[DNSQR].qname.decode().rstrip(".")
        for rr in p[DNS].an or []:
            if rr.type in (1, 28):
                names[str(rr.rdata)] = name
        return pkt.accept()

    l4 = p.getlayer(TCP) or p.getlayer(UDP)
    port = l4.dport if l4 else 0
    for action, kind, *value in rules:
        if match(kind, value[0] if value else None, p.dst, port):
            if action == "block":
                print("blocked", names.get(p.dst, p.dst), port)
                return pkt.drop()
            return pkt.accept()
    pkt.accept()

iptables("-I")
nfq = NetfilterQueue()
nfq.bind(1, handle)
try:
    nfq.run()
except KeyboardInterrupt:
    pass
finally:
    nfq.unbind()
    iptables("-D")

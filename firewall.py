import re, sqlite3, subprocess, time
from datetime import datetime
from netfilterqueue import NetfilterQueue
from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR

QUEUE = [
    "OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass",
    "INPUT -j NFQUEUE --queue-num 1 --queue-bypass",
    "OUTPUT -p tcp --sport 22 -j ACCEPT",
    "INPUT -p tcp --dport 22 -j ACCEPT",
    "OUTPUT -p tcp --sport 8080 -j ACCEPT",
    "INPUT -p tcp --dport 8080 -j ACCEPT",
]
TIMEOUT = 300
WINDOW = re.compile(r"\d\d:\d\d-\d\d:\d\d$")

db = sqlite3.connect("firewall.db")
db.execute("create table if not exists events (ts real, kind text, detail text)")

def log(kind, detail):
    print(kind, detail)
    db.execute("insert into events values (?,?,?)", (time.time(), kind, detail))
    db.commit()

def iptables(flag):
    for cmd in ("iptables", "ip6tables"):
        for r in QUEUE:
            subprocess.run([cmd, flag, *r.split()])

def load(path):
    return [l.split() for l in open(path) if l.strip() and not l.startswith("#")]

def parse(l):
    window = l.pop() if WINDOW.match(l[-1]) else None
    return l[0], l[1], l[2] if len(l) > 2 else None, window

rules = [parse(l) for l in load("rules.txt")]
blocklist = {l[-1] for l in load("blocklist.txt")}
names, conns, scans = {}, {}, {}
last_clean = time.time()

def in_window(w):
    if not w:
        return True
    start, end = w.split("-")
    now = datetime.now().strftime("%H:%M")
    return start <= now < end if start < end else now >= start or now < end

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

def decide(ip, port):
    for action, kind, value, window in rules:
        if in_window(window) and match(kind, value, ip, port):
            return action
    return "allow"

def on_blocklist(name):
    parts = name.split(".")
    return any(".".join(parts[i:]) in blocklist for i in range(len(parts)))

def nxdomain(p):
    q = p[DNS]
    ip = IP if p.version == 4 else IPv6
    return (ip(src=p.dst, dst=p.src)
            / UDP(sport=p[UDP].dport, dport=p[UDP].sport)
            / DNS(id=q.id, qr=1, rd=q.rd, ra=1, rcode=3, qd=q.qd))

def handle(pkt):
    global last_clean
    raw = pkt.get_payload()
    p = IP(raw) if raw[0] >> 4 == 4 else IPv6(raw)
    now = time.time()
    incoming = pkt.hook == 1

    if p.haslayer(DNSQR):
        name = p[DNSQR].qname.decode().rstrip(".")
        if p[DNS].qr == 1:
            for rr in p[DNS].an or []:
                if rr.type in (1, 28):
                    names[str(rr.rdata)] = name
        elif not incoming and p.haslayer(UDP) and on_blocklist(name):
            log("dns blocked", name)
            pkt.set_payload(bytes(nxdomain(p)))
            return pkt.accept()

    l4 = p.getlayer(TCP) or p.getlayer(UDP)
    proto = l4.name if l4 else "other"
    sport, dport = (l4.sport, l4.dport) if l4 else (0, 0)

    if incoming:
        local = p.src.startswith("127.") or p.src == "::1"
        ipv6_control = p.version == 6 and p.nh == 58
        reply = conns.get((proto, p.dst, dport, p.src, sport), 0) > now - TIMEOUT
        if local or ipv6_control or reply:
            return pkt.accept()
        log("unsolicited", f"{p.src}:{dport}")
        ports = scans.setdefault(p.src, set())
        ports.add(dport)
        if len(ports) == 10:
            log("ALERT port scan", p.src)
        return pkt.drop()

    if decide(p.dst, dport) == "block":
        log("blocked", f"{names.get(p.dst, p.dst)}:{dport}")
        return pkt.drop()
    conns[(proto, p.src, sport, p.dst, dport)] = now
    pkt.accept()

    if now - last_clean > 60:
        for k in [k for k, t in conns.items() if t < now - TIMEOUT]:
            del conns[k]
        scans.clear()
        last_clean = now

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

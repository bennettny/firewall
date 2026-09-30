import sqlite3, time
from datetime import date
from scapy.all import sniff, conf, get_if_hwaddr, IP, IPv6, TCP, UDP, DNS, DNSQR

db = sqlite3.connect("firewall.db")
db.executescript("""
create table if not exists dns (ts real, day text, domain text);
create table if not exists names (ip text primary key, domain text);
create table if not exists flows (day text, proto text, ip text, port int, pkts int, bytes int,
    primary key (day, proto, ip, port));
""")

me = get_if_hwaddr(conf.iface)
flows = {}
last = time.time()

def flush():
    db.executemany("""insert into flows values (?,?,?,?,?,?) on conflict do update
        set pkts = pkts + excluded.pkts, bytes = bytes + excluded.bytes""",
        [k + tuple(v) for k, v in flows.items()])
    db.commit()
    flows.clear()

def handle(p):
    global last
    ip = p.getlayer(IP) or p.getlayer(IPv6)
    if not ip:
        return
    out = p.src == me
    l4 = p.getlayer(TCP) or p.getlayer(UDP)
    port = (l4.dport if out else l4.sport) if l4 else 0
    key = (date.today().isoformat(), l4.name if l4 else "other", ip.dst if out else ip.src, port)
    f = flows.setdefault(key, [0, 0])
    f[0] += 1
    f[1] += len(p)

    if p.haslayer(DNSQR):
        name = p[DNSQR].qname.decode().rstrip(".")
        if out and p[DNS].qr == 0 and p[DNSQR].qtype == 1:
            db.execute("insert into dns values (?,?,?)", (time.time(), key[0], name))
            print(name)
        for rr in p[DNS].an or []:
            if rr.type in (1, 28):
                db.execute("insert or replace into names values (?,?)", (str(rr.rdata), name))

    if time.time() - last > 5:
        flush()
        last = time.time()

sniff(filter="not port 22", prn=handle, store=False)
flush()

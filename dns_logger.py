import os, sqlite3, time, urllib.request
from collections import Counter
from datetime import datetime
from scapy.all import sniff, DNS, DNSQR, IP, IPv6

HOSTS = "hosts.txt"
if not os.path.exists(HOSTS):
    urllib.request.urlretrieve("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", HOSTS)
blocked = {l.split()[1] for l in open(HOSTS) if l.startswith("0.0.0.0 ")}

db = sqlite3.connect("traffic.db")
db.execute("CREATE TABLE IF NOT EXISTS lookups (ts TEXT, src TEXT, domain TEXT, tracker INT)")

seen, counts, trackers = {}, Counter(), set()


def is_tracker(d):
    p = d.split(".")
    return any(".".join(p[i:]) in blocked for i in range(len(p) - 1))


def handle(pkt):
    if not pkt.haslayer(DNSQR) or pkt[DNS].qr:
        return
    name = pkt[DNSQR].qname.decode().rstrip(".").lower()
    if time.time() - seen.get(name, 0) < 2:
        return
    seen[name] = time.time()

    src = pkt[IP].src if IP in pkt else pkt[IPv6].src if IPv6 in pkt else "?"
    bad = is_tracker(name)
    counts[name] += 1
    if bad:
        trackers.add(name)

    ts = datetime.now()
    db.execute("INSERT INTO lookups VALUES (?,?,?,?)", (ts.isoformat(timespec="seconds"), src, name, bad))
    db.commit()
    print(f"{ts:%H:%M:%S}  {src:15}  {name}" + ("  \033[91m[tracker]\033[0m" if bad else ""))


try:
    sniff(filter="udp port 53", prn=handle, store=False)
except KeyboardInterrupt:
    pass
finally:
    total = sum(counts.values())
    bad = sum(counts[d] for d in trackers)
    if total:
        print(f"\n{total} lookups, {bad} trackers ({bad / total:.0%})")
        for d, n in counts.most_common(10):
            print(f"{n:5}  {d}" + ("  [tracker]" if d in trackers else ""))

            # run with sudo $(which python) dns_logger.py
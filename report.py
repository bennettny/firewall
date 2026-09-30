import sqlite3, sys
from datetime import date

day = sys.argv[1] if len(sys.argv) > 1 else date.today().isoformat()
db = sqlite3.connect("firewall.db")

print(f"top 20 by data, {day}")
for who, kb, pkts in db.execute("""
    select coalesce(n.domain, f.ip) who, sum(bytes) / 1024, sum(pkts) from flows f
    left join names n using (ip) where day = ? group by who order by 2 desc limit 20""", (day,)):
    print(f"{kb:>8} KB {pkts:>7} pkts  {who}")

print(f"\ntop 20 lookups, {day}")
for domain, n in db.execute("""select domain, count(*) from dns where day = ?
    group by domain order by 2 desc limit 20""", (day,)):
    print(f"{n:>5}  {domain}")

import sqlite3, time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

def table(title, rows):
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<h3>{title}</h3><table>{body}</table>"

class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        db = sqlite3.connect("firewall.db")
        day = time.time() - 86400
        counts = db.execute("select kind, count(*) from events where ts > ? group by kind", (day,))
        top = db.execute("""select detail, count(*) from events where kind = 'dns blocked' and ts > ?
                            group by detail order by 2 desc limit 15""", (day,))
        recent = [(datetime.fromtimestamp(t).strftime("%H:%M:%S"), k, d) for t, k, d in
                  db.execute("select * from events order by ts desc limit 30")]
        html = f"""<meta http-equiv="refresh" content="5">
<style>body{{font-family:monospace;margin:2em}} td{{padding:2px 12px}}</style>
<h2>firewall</h2>
{table("last 24h", counts)}{table("top blocked domains", top)}{table("recent", recent)}"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, *args):
        pass

HTTPServer(("", 8080), Page).serve_forever()

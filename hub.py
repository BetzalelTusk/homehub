#!/usr/bin/env python3
"""Home hub: LAN device inventory, presence, internet monitor. stdlib only."""
import calendar, collections, hashlib, hmac, json, os, queue, re, secrets, socket, sqlite3, subprocess, sys, threading, time
import urllib.request, xml.etree.ElementTree as ET
import ident
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "hub.db")
CONF = os.path.join(HERE, "config.json")
SCHOOL = os.path.join(HERE, "school.json")   # schedule exported from Brightspace by tools/thisweek.js
FEED_CACHE = os.path.join(HERE, "school_feed.json")   # last good copy of the Brightspace calendar feed
FEED_EVERY = 1800        # seconds between Brightspace calendar feed fetches
SUBNET = "192.168.1.0/24"
PORT = 8080
SCAN_EVERY = 60          # seconds between LAN sweeps
DISCOVER_EVERY = 300     # mDNS / SSDP discovery
AWAY_AFTER = 600         # phones sleep Wi-Fi; only call them away after this long unseen
OFFLINE_AFTER = 180      # other devices count as offline after this long unseen
ONLINE_EVENT_AFTER = 1800  # only log "came online" after being gone this long (phones nap constantly)
SESSION_GAP = 300        # a sighting within this long of the last one extends the same online session
PING_EVERY = 10
PING_TARGETS = ["1.1.1.1", "8.8.8.8"]
FAILS_FOR_OUTAGE = 3     # consecutive failed rounds before an outage is recorded
FP_EVERY = 7 * 86400     # re-fingerprint each device weekly
WATCH_AFTER = 300        # default: a watched device counts as offline after this long unseen (configurable)
COOKIE_DAYS = 30

lock = threading.Lock()
scanning = set()         # MACs with a port scan in progress
SELF = set()             # the Pi's own MAC

def db():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS devices(
          mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, name TEXT,
          is_person INTEGER DEFAULT 0, known INTEGER DEFAULT 0,
          first_seen REAL, last_seen REAL);
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY, ts REAL, kind TEXT, mac TEXT, msg TEXT);
        CREATE TABLE IF NOT EXISTS pings(ts REAL, ok INTEGER, ms REAL);
        CREATE TABLE IF NOT EXISTS outages(id INTEGER PRIMARY KEY, start REAL, end REAL);
        CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, mac TEXT, start REAL, end REAL);
        CREATE INDEX IF NOT EXISTS sessions_mac ON sessions(mac, end);
        CREATE INDEX IF NOT EXISTS events_mac ON events(mac);
        CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS leases(ip TEXT PRIMARY KEY, mac TEXT, ts REAL, hostname TEXT);
        CREATE TABLE IF NOT EXISTS ping_hours(t INTEGER PRIMARY KEY, n INTEGER, ok INTEGER, ms_sum REAL, ms_n INTEGER);
        CREATE TABLE IF NOT EXISTS speedtests(id INTEGER PRIMARY KEY, ts REAL, down REAL, up REAL, ping REAL, jitter REAL, err TEXT);
        CREATE INDEX IF NOT EXISTS pings_ts ON pings(ts);
        CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
        """)
        have = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
        for col, typ in [("vendor", "TEXT"), ("notes", "TEXT"), ("info", "TEXT"),
                         ("ports", "TEXT"), ("scan_ts", "REAL"), ("scan_err", "TEXT"), ("type_override", "TEXT"),
                         ("owner", "TEXT"), ("location", "TEXT"), ("watch", "INTEGER DEFAULT 0"), ("via", "TEXT")]:
            if col not in have:
                c.execute(f"ALTER TABLE devices ADD COLUMN {col} {typ}")

def event(c, kind, mac, msg):
    now = time.time()
    c.execute("INSERT INTO events(ts,kind,mac,msg) VALUES(?,?,?,?)", (now, kind, mac, msg))
    OUTBOX.put((now, kind, mac, msg))

def dev_label(row, info=None):
    """Python twin of the UI's label(): the name a person would recognise."""
    d = dict(row)
    info = info if info is not None else json.loads(d.get("info") or "{}")
    return d.get("name") or ident.auto_name({**d, "dname": disc_name(info)}, info) or d.get("hostname") or d.get("ip") or d.get("mac")

# ---------- vendor lookup (Wireshark manuf file, falls back to nmap's list) ----------
OUI = {}  # (prefix_bits, int_prefix) -> vendor
def load_oui():
    path = os.path.join(HERE, "manuf")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8", errors="ignore"):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            pre, bits = parts[0].strip(), 24
            if "/" in pre:
                pre, b = pre.split("/"); bits = int(b)
            hexs = pre.replace(":", "").replace("-", "")
            try:
                val = int(hexs, 16) >> (len(hexs) * 4 - bits)
            except ValueError:
                continue
            OUI[(bits, val)] = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
    else:
        for line in open("/usr/share/nmap/nmap-mac-prefixes", errors="ignore"):
            if len(line) > 7 and not line.startswith("#"):
                OUI[(24, int(line[:6], 16))] = line[7:].strip()

def vendor(mac):
    if "@" in mac:  # behind a Wi-Fi extender: the MAC is the extender's, not the device's
        return None
    n = int(mac.replace(":", ""), 16)
    for bits in (36, 28, 24):
        v = OUI.get((bits, n >> (48 - bits)))
        if v:
            return v
    return None

def private_mac(mac):
    return bool(int(mac[:2], 16) & 2)

def behind_extender(key):
    return "@" in key

# ---------- LAN scanner ----------
# ---------- Wi-Fi extender ----------
# A MAC-rewriting extender (the Netgear EX6100) answers for every client behind it with its own MAC, so on the
# network those clients all look alike. Their DHCP requests still carry their real MAC inside the packet, and the
# hub overhears those, so it learns which IP belongs to which real device and keys them by their real MAC.
LEASES = {}        # ip -> real MAC, from overheard DHCP requests
EXTENDERS = set()  # MACs seen answering for several IPs at once
EXT_VIA = {}       # device key -> extender MAC it was reached through in the latest sweep

def load_extender_state():
    with db() as c:
        LEASES.update({r["ip"]: r["mac"] for r in c.execute("SELECT ip, mac FROM leases")})
        r = c.execute("SELECT v FROM kv WHERE k='extenders'").fetchone()
        if r:
            EXTENDERS.update(json.loads(r["v"]))
        # older versions keyed extender clients as "<extender mac>@<ip>"
        EXTENDERS.update(k.split("@")[0] for (k,) in c.execute("SELECT mac FROM devices WHERE mac LIKE '%@%'").fetchall()
                         if not private_mac(k))
        remember_extenders(c, ())

def remember_extenders(c, macs):
    EXTENDERS.update(macs)
    c.execute("INSERT OR REPLACE INTO kv VALUES('extenders', ?)", (json.dumps(sorted(EXTENDERS)),))

def learn_lease(c, ip, mac, host=None):
    if not ip or not ip.startswith(SUBNET.rsplit(".", 1)[0] + ".") or mac in EXTENDERS or mac in SELF:
        return
    for old in [k for k, v in LEASES.items() if v == mac and k != ip]:
        del LEASES[old]
    LEASES[ip] = mac
    c.execute("DELETE FROM leases WHERE mac=? AND ip<>?", (mac, ip))
    c.execute("INSERT OR REPLACE INTO leases(ip, mac, ts, hostname) VALUES(?,?,?,?)", (ip, mac, time.time(), host))

def sweep():
    """One LAN sweep. Returns ({device key: ip}, {device key: extender MAC it was seen through}, extender MACs seen now)."""
    out = subprocess.run(["nmap", "-sn", "-n", "-T4", SUBNET], capture_output=True, text=True, timeout=120).stdout
    hosts = set(re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", out))
    neigh = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
    macs = {}
    for line in neigh.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+) dev \S+ lladdr (\S+) (\S+)", line)
        if m and m.group(3) != "FAILED":
            macs[m.group(1)] = m.group(2).lower()
    prefix = SUBNET.rsplit(".", 1)[0]
    ips = [ip for ip in hosts | set(macs) if ip in macs and ip.startswith(prefix)]
    # An extender has a fixed, vendor-assigned MAC. A phone's private (randomised) MAC at two IPs is just a stale
    # neighbour entry for its old address, so it never counts.
    multi = {m for m in {macs[ip] for ip in ips}
             if not private_mac(m) and sum(1 for ip in ips if macs[ip] == m and ip in hosts) > 1}
    found, via = {}, {}
    for ip in sorted(ips, key=lambda x: x not in hosts):   # addresses that answered this sweep beat stale ones
        m = macs[ip]
        if m in multi or m in EXTENDERS:
            key = LEASES.get(ip) or f"{m}@{ip}"
            if key not in found:
                found[key], via[key] = ip, m
        elif m not in found:
            found[m] = ip
    # the Pi itself never shows up in its own neighbour table
    me = subprocess.run(["ip", "-o", "link", "show", "wlan0"], capture_output=True, text=True).stdout
    m = re.search(r"link/ether (\S+)", me)
    myip = local_ip()
    if m and myip:
        found[m.group(1).lower()] = myip
        SELF.add(m.group(1).lower())
    return found, via, multi

def merge_device(c, old, new):
    """Fold the device record `old` into `new` (or just rename it if `new` doesn't exist yet), keeping anything the user set."""
    o = c.execute("SELECT * FROM devices WHERE mac=?", (old,)).fetchone()
    if not o or old == new:
        return
    n = c.execute("SELECT * FROM devices WHERE mac=?", (new,)).fetchone()
    c.execute("UPDATE sessions SET mac=? WHERE mac=?", (new, old))
    if n is None:
        c.execute("UPDATE devices SET mac=?, vendor=COALESCE(?, vendor) WHERE mac=?", (new, vendor(new), old))
        c.execute("UPDATE events SET mac=? WHERE mac=?", (new, old))
    else:   # the "new device" / "changed IP" events of a duplicate were false alarms
        c.execute("UPDATE events SET mac=? WHERE mac=? AND kind NOT IN ('new','ip')", (new, old))
        c.execute("DELETE FROM events WHERE mac=?", (old,))
        newer = (o["last_seen"] or 0) > (n["last_seen"] or 0)
        info = {**json.loads(o["info"] or "{}"), **json.loads(n["info"] or "{}")}
        c.execute("""UPDATE devices SET name=COALESCE(name,?), notes=COALESCE(notes,?), type_override=COALESCE(type_override,?),
                     owner=COALESCE(owner,?), location=COALESCE(location,?), hostname=COALESCE(hostname,?),
                     is_person=MAX(is_person,?), known=MAX(known,?), watch=MAX(watch,?), first_seen=MIN(first_seen,?),
                     last_seen=MAX(last_seen,?), ip=?, info=?, ports=COALESCE(ports,?), scan_ts=COALESCE(scan_ts,?) WHERE mac=?""",
                  (o["name"], o["notes"], o["type_override"], o["owner"], o["location"], o["hostname"], o["is_person"], o["known"],
                   o["watch"], o["first_seen"], o["last_seen"], o["ip"] if newer else n["ip"], json.dumps(info), o["ports"], o["scan_ts"], new))
        c.execute("DELETE FROM devices WHERE mac=?", (old,))
    print(f"merged {old} into {new}", flush=True)

def migrate_extender_records():
    """Re-key old '<extender mac>@<ip>' records whose real MAC the DHCP listener has already learned."""
    with lock, db() as c:
        for r in c.execute("SELECT mac, ip, info FROM devices WHERE mac LIKE '%@%'").fetchall():
            base, ip = r["mac"].split("@", 1)
            if private_mac(base):          # a phone's private MAC, wrongly treated as an extender before
                merge_device(c, r["mac"], base)
                continue
            dh = json.loads(r["info"] or "{}").get("dhcp") or {}
            if dh.get("mac") and dh["mac"] != base and (dh.get("requested_ip") or dh.get("ip")) == ip:
                learn_lease(c, ip, dh["mac"], dh.get("hostname"))
                merge_device(c, r["mac"], dh["mac"])

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return None

def rdns(ip):
    try:
        r = subprocess.run(["getent", "hosts", ip], capture_output=True, text=True, timeout=3).stdout.split()
        return r[1] if len(r) > 1 else None
    except Exception:
        return None

def scan_loop():
    while True:
        try:
            found, via, multi = sweep()
            now = time.time()
            with lock, db() as c:
                if multi - EXTENDERS:
                    remember_extenders(c, multi)
                seed = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
                for key, ip in found.items():   # adopt an older "<extender>@<ip>" record once the real MAC is known
                    if "@" not in key and key in via:
                        merge_device(c, f"{via[key]}@{ip}", key)
                resolve_extender_aliases(c, found, via)
                EXT_VIA.clear(); EXT_VIA.update(via)
                for mac, ip in found.items():
                    row = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
                    if row is None:
                        host = rdns(ip)
                        # first ever scan: treat everything present as known (baseline)
                        early = DHCP_SEEN.get(mac)
                        c.execute("INSERT INTO devices(mac,ip,hostname,vendor,known,first_seen,last_seen,info,via) VALUES(?,?,?,?,?,?,?,?,?)",
                                  (mac, ip, host, vendor(mac), 1 if seed or mac in SELF else 0, now, now,
                                   json.dumps({"dhcp": {k: v for k, v in early.items() if k != "msg"}}) if early else None, via.get(mac)))
                        if not seed and mac not in SELF:
                            event(c, "new", mac, f"New device joined: {host or vendor(mac) or ip} ({ip})")
                    else:
                        was_off = now - (row["last_seen"] or 0) > (AWAY_AFTER if row["is_person"] else ONLINE_EVENT_AFTER)
                        host = rdns(ip) or row["hostname"]
                        if row["ip"] and row["ip"] != ip and ip != VIA_EXTENDER.get(mac) and row["ip"] not in (VIA_EXTENDER.get(mac), ) \
                                and not c.execute("SELECT 1 FROM events WHERE mac=? AND kind='ip' AND ts>?", (mac, now - 3600)).fetchone():
                            event(c, "ip", mac, f"{row['name'] or host or mac} changed IP {row['ip']} → {ip}")
                        c.execute("UPDATE devices SET ip=?,hostname=?,vendor=COALESCE(vendor,?),last_seen=?,via=? WHERE mac=?",
                                  (ip, host, vendor(mac), now, via.get(mac), mac))
                        if row["watch"] and not row["is_person"]:
                            last = c.execute("SELECT kind, ts FROM events WHERE mac=? AND kind IN ('online','offline') ORDER BY id DESC LIMIT 1",
                                             (mac,)).fetchone()
                            if last and last["kind"] == "offline":
                                event(c, "online", mac, f"{dev_label(row)} is back online (was offline {fmt_dur(now - last['ts'])})")
                        elif was_off:
                            nm = row["name"] or host or ip
                            event(c, "arrive" if row["is_person"] else "online", mac,
                                  f"{nm} {'arrived home' if row['is_person'] else 'came online'}")
                    s = c.execute("SELECT id,end FROM sessions WHERE mac=? ORDER BY end DESC LIMIT 1", (mac,)).fetchone()
                    if s and now - s["end"] <= SESSION_GAP:
                        c.execute("UPDATE sessions SET end=? WHERE id=?", (now, s["id"]))
                    else:
                        c.execute("INSERT INTO sessions(mac,start,end) VALUES(?,?,?)", (mac, now, now))
                c.execute("DELETE FROM sessions WHERE end < ?", (now - 90 * 86400,))
                grace = (load_conf().get("alerts") or {}).get("watch_after_min", WATCH_AFTER // 60) * 60
                for row in c.execute("SELECT * FROM devices WHERE watch=1 AND is_person=0").fetchall():
                    if now - (row["last_seen"] or 0) <= grace:
                        continue
                    last = c.execute("SELECT kind FROM events WHERE mac=? AND kind IN ('online','offline') ORDER BY id DESC LIMIT 1",
                                     (row["mac"],)).fetchone()
                    if last is None or last["kind"] == "online":
                        event(c, "offline", row["mac"], f"{dev_label(row)} went offline (last seen {time.strftime('%H:%M', time.localtime(row['last_seen']))})")
                for row in c.execute("SELECT * FROM devices WHERE is_person=1").fetchall():
                    gone = now - row["last_seen"] > AWAY_AFTER
                    last = c.execute("SELECT kind FROM events WHERE mac=? AND kind IN ('arrive','leave') ORDER BY id DESC LIMIT 1",
                                     (row["mac"],)).fetchone()
                    if gone and (last is None or last["kind"] == "arrive"):
                        event(c, "leave", row["mac"], f"{row['name'] or row['hostname'] or row['ip']} left home")
        except Exception as e:
            print("scan error:", e, flush=True)
        time.sleep(SCAN_EVERY)

# ---------- discovery: mDNS (avahi) + SSDP/UPnP ----------
TXT_KEYS = {"md", "model", "ty", "fn", "am", "product", "usb_mfg", "usb_mdl", "manufacturer", "rpmd", "deviceid", "osxvers", "n"}

def mdns():
    try:
        out = subprocess.run(["avahi-browse", "-atrpk"], capture_output=True, text=True, timeout=20).stdout
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="ignore") if isinstance(e.stdout, bytes) else (e.stdout or "")
    res = {}
    for line in out.splitlines():
        f = line.split(";")
        if len(f) < 9 or f[0] != "=" or f[2] != "IPv4":
            continue
        # avahi escapes each byte as \DDD; rebuild the bytes and decode as UTF-8 (so ’ doesn't become â€™)
        name = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), f[3]).encode("latin-1", "replace").decode("utf-8", "replace")
        ip, d = f[7], res.setdefault(f[7], {"hostname": None, "services": {}, "txt": {}})
        d["hostname"] = f[6]
        d["services"][f[4]] = {"name": name, "port": int(f[8]) if f[8].isdigit() else None}
        for kv in re.findall(r'"([^"]*)"', ";".join(f[9:])):
            k, _, v = kv.partition("=")
            if k.lower() in TXT_KEYS and v:
                d["txt"][k.lower()] = v[:120]
    return res

def ssdp():
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(1)
    locs = {}
    try:
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + 4
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            srv = re.search(rb"(?im)^server:\s*(.+?)\r?$", data)
            d = locs.setdefault(addr[0], {"locs": set(), "server": None})
            if m: d["locs"].add(m.group(1).decode(errors="ignore"))
            if srv: d["server"] = srv.group(1).decode(errors="ignore").strip()[:120]
    finally:
        s.close()
    res = {}
    for ip, d in locs.items():
        info = {"server": d["server"]}
        for loc in sorted(d["locs"])[:3]:
            if urlparse(loc).hostname != ip:
                continue
            try:
                x = urllib.request.urlopen(loc, timeout=3).read(200000)
                root = ET.fromstring(x)
                dev = next((e for e in root.iter() if e.tag.endswith("}device") or e.tag == "device"), None)
                if dev is None:
                    continue
                for e in dev:
                    tag = e.tag.split("}")[-1]
                    if tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "deviceType") and e.text:
                        info.setdefault(tag, e.text.strip()[:120])
                if "modelName" in info:
                    break
            except Exception:
                continue
        res[ip] = info
    return res

def discover_loop():
    time.sleep(15)
    while True:
        try:
            m, u = mdns(), ssdp()
            with db() as c:
                rows = c.execute("SELECT mac, ip, info, last_seen FROM devices").fetchall()
            probes = {}
            for r in rows:  # cheap unicast probes, only for devices that are around
                if time.time() - (r["last_seen"] or 0) > OFFLINE_AFTER:
                    continue
                old = json.loads(r["info"] or "{}")
                p = {"ttl": ident.ttl_of(r["ip"])}
                if time.time() - old.get("nb_ts", 0) > 6 * 3600:
                    nb = ident.netbios_name(r["ip"])
                    p["nb_ts"] = time.time()
                    if nb: p["nbname"], p["workgroup"] = nb
                probes[r["mac"]] = p
            with lock, db() as c:
                for r in c.execute("SELECT mac, ip, info FROM devices").fetchall():
                    old = json.loads(r["info"] or "{}")
                    new = dict(old)
                    if r["ip"] in m: new["mdns"] = m[r["ip"]]
                    if r["ip"] in u: new["upnp"] = u[r["ip"]]
                    for k, v in probes.get(r["mac"], {}).items():
                        if v is not None: new[k] = v
                    if new != old:
                        c.execute("UPDATE devices SET info=? WHERE mac=?", (json.dumps(new), r["mac"]))
        except Exception as e:
            print("discover error:", e, flush=True)
        time.sleep(DISCOVER_EVERY)

# ---------- per-device tools ----------
def can_raw():
    """True when this process may open raw sockets (needed for nmap OS detection)."""
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
        return True
    except PermissionError:
        return False

def port_scan(mac, ip):
    """Full fingerprint: open ports, service versions, OS detection, TLS cert names, NetBIOS name."""
    res, err = {"ports": []}, None
    try:
        res = ident.fingerprint(ip, privileged=can_raw())
    except Exception as e:
        err = str(e)[:200]
    with lock, db() as c:
        r = c.execute("SELECT info FROM devices WHERE mac=?", (mac,)).fetchone()
        if r:
            info = json.loads(r["info"] or "{}")
            if res.get("os"): info["os"] = res["os"]
            if res.get("certs"): info["certs"] = res["certs"]
            if res.get("nbname"): info["nbname"] = res["nbname"]
            c.execute("UPDATE devices SET ports=?, scan_ts=?, scan_err=?, info=? WHERE mac=?",
                      (json.dumps(res["ports"]), time.time(), err, json.dumps(info), mac))
    scanning.discard(mac)

def fingerprint_loop():
    """Fingerprint every device in the background: new ones first, then a weekly refresh. One at a time."""
    time.sleep(90)
    while True:
        try:
            now = time.time()
            with db() as c:
                r = c.execute("""SELECT mac, ip FROM devices WHERE last_seen > ? AND (scan_ts IS NULL OR scan_ts < ?)
                                 ORDER BY scan_ts IS NOT NULL, first_seen DESC LIMIT 1""",
                              (now - OFFLINE_AFTER, now - FP_EVERY)).fetchone()
            if r and r["mac"] not in scanning:
                scanning.add(r["mac"])
                port_scan(r["mac"], r["ip"])
                continue
        except Exception as e:
            print("fingerprint error:", e, flush=True)
        time.sleep(60)

DHCP_SEEN = {}  # mac -> latest request, for devices not in the table yet
VIA_EXTENDER = {}  # real mac -> IP it currently has while connected through the MAC-rewriting extender

GENERIC_HOSTS = re.compile(r"^(iphone|ipad|android|localhost|none|unknown|esp_?[0-9a-f]*|galaxy|amazon|echo|wlan0|espressif|[0-9a-f-]{12,})$", re.I)
def resolve_extender_aliases(c, found, via):
    """A device behind the extender whose DHCP we haven't overheard yet is keyed '<extender mac>@<ip>'. If its network
    name matches exactly one device we already know, it *is* that device (e.g. a phone that roamed to the extender):
    count the sighting for the real device and fold any duplicate record into it."""
    direct = {}
    for r in c.execute("SELECT mac, hostname FROM devices WHERE mac NOT LIKE '%@%' AND hostname IS NOT NULL"):
        h = r["hostname"].lower().replace(".local", "")
        direct.setdefault(h, []).append(r["mac"])
    VIA_EXTENDER.clear()
    for key, ip in list(found.items()):
        if "@" not in key:
            continue
        dup = c.execute("SELECT hostname FROM devices WHERE mac=?", (key,)).fetchone()
        host = (rdns(ip) or (dup["hostname"] if dup else "") or "").lower().replace(".local", "")
        real = direct.get(host)
        if not host or GENERIC_HOSTS.match(host) or not real or len(real) != 1 or real[0] in found:
            continue
        real = real[0]
        del found[key]
        found[real] = ip
        via[real] = via.pop(key, None)
        VIA_EXTENDER[real] = ip
        merge_device(c, key, real)

def on_dhcp(req):
    """Attach an overheard DHCP request to the device it came from (by MAC, or by IP for devices behind the extender)."""
    DHCP_SEEN[req["mac"]] = req
    ip = req.get("ip") or req.get("requested_ip")
    with lock, db() as c:
        learn_lease(c, ip, req["mac"], req.get("hostname"))
        r = c.execute("SELECT mac, info FROM devices WHERE mac=?", (req["mac"],)).fetchone()
        if not r and ip:
            r = c.execute("SELECT mac, info FROM devices WHERE ip=? AND mac LIKE '%@%'", (ip,)).fetchone()
        if r:
            info = json.loads(r["info"] or "{}")
            info["dhcp"] = {**(info.get("dhcp") or {}), **{k: v for k, v in req.items() if v is not None and k != "msg"}}
            c.execute("UPDATE devices SET info=? WHERE mac=?", (json.dumps(info), r["mac"]))

def ping_device(ip):
    r = subprocess.run(["ping", "-c", "4", "-i", "0.3", "-W", "2", ip], capture_output=True, text=True, timeout=20).stdout
    times = [float(x) for x in re.findall(r"time=([\d.]+) ms", r)]
    return {"sent": 4, "received": len(times), "times": times,
            "avg": sum(times) / len(times) if times else None}

def wake(mac):
    pkt = b"\xff" * 6 + bytes.fromhex(mac[:17].replace(":", "")) * 16
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for port in (9, 7):
        s.sendto(pkt, ("255.255.255.255", port))
    s.close()

# ---------- internet monitor ----------
def ping(host):
    r = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True)
    m = re.search(r"time=([\d.]+) ms", r.stdout)
    return float(m.group(1)) if m else None

def aggregate_pings(c, since=None):
    """Roll raw pings up into hourly rows (kept for a year; raw pings are kept for 8 days). Redoes the last full hour
    and the current partial one, so long-range charts are never more than a few minutes behind."""
    if since is None:
        last = c.execute("SELECT MAX(t) FROM ping_hours").fetchone()[0]
        since = (last - 3600) if last else 0
    c.execute("""INSERT OR REPLACE INTO ping_hours(t, n, ok, ms_sum, ms_n)
                 SELECT CAST(ts/3600 AS INT)*3600 AS h, COUNT(*), SUM(ok), SUM(ms), COUNT(ms) FROM pings WHERE ts>=? GROUP BY h""", (since,))
    c.execute("DELETE FROM ping_hours WHERE t < ?", (time.time() - 400 * 86400,))

def ping_loop():
    fails, outage_id, rounds = 0, None, 0
    while True:
        try:
            ms = None
            for t in PING_TARGETS:
                ms = ping(t)
                if ms is not None:
                    break
            now = time.time()
            with lock, db() as c:
                c.execute("INSERT INTO pings VALUES(?,?,?)", (now, 1 if ms is not None else 0, ms))
                c.execute("DELETE FROM pings WHERE ts < ?", (now - 8 * 86400,))
                rounds += 1
                if rounds % 60 == 1:   # every 10 minutes
                    aggregate_pings(c)
                if ms is None:
                    fails += 1
                    if fails == FAILS_FOR_OUTAGE and outage_id is None:
                        cur = c.execute("INSERT INTO outages(start) VALUES(?)", (now - PING_EVERY * (FAILS_FOR_OUTAGE - 1),))
                        outage_id = cur.lastrowid
                        event(c, "outage", None, "Internet went down")
                else:
                    if outage_id is not None:
                        c.execute("UPDATE outages SET end=? WHERE id=?", (now, outage_id))
                        start = c.execute("SELECT start FROM outages WHERE id=?", (outage_id,)).fetchone()[0]
                        event(c, "restored", None, f"Internet restored after {fmt_dur(now - start)} "
                                                   f"(down since {time.strftime('%H:%M', time.localtime(start))})")
                        outage_id = None
                    fails = 0
        except Exception as e:
            print("ping error:", e, flush=True)
        time.sleep(PING_EVERY)

# ---------- notifications (ntfy / Telegram) ----------
OUTBOX = queue.Queue()   # (ts, kind, mac, msg) for every event, filled by event()
ALERT_KINDS = {          # setting -> event kinds it covers; defaults chosen to stay quiet
    "new": (["new"], True), "watch": (["offline", "online"], True), "internet": (["outage", "restored"], True),
    "people": (["arrive", "leave"], False), "ip": (["ip"], False)}
PUSH = {"new": ("New device on your network", 4, "warning"), "offline": ("Device offline", 4, "red_circle"),
        "online": ("Device back online", 3, "green_circle"), "outage": ("Internet down", 4, "rotating_light"),
        "restored": ("Internet restored", 3, "white_check_mark"), "arrive": ("Arrived home", 2, "house"),
        "leave": ("Left home", 2, "wave"), "ip": ("IP address changed", 2, "arrows_counterclockwise"),
        "digest": ("Home network summary", 2, "bar_chart"), "test": ("Home Hub test", 3, "bell")}

def fmt_dur(s):
    s = max(0, int(s))
    return f"{s} sec" if s < 90 else f"{round(s / 60)} min" if s < 5400 else f"{s / 3600:.1f} hours" if s < 172800 else f"{s / 86400:.1f} days"

def alert_conf():
    a = load_conf().get("alerts") or {}
    a.setdefault("kinds", {k: v[1] for k, v in ALERT_KINDS.items()})
    a.setdefault("watch_after_min", WATCH_AFTER // 60)
    a.setdefault("digest_hour", None)
    return a

def hub_url(mac=None):
    return f"http://{local_ip() or 'localhost'}:{PORT}/" + (f"#device/{mac}" if mac else "")

def push(kind, msg, mac=None, conf=None):
    """Send one notification to every configured channel. Raises if any channel fails."""
    a = conf or alert_conf()
    title, prio, tag = PUSH.get(kind, ("Home Hub", 3, "house"))
    errs, sent = [], 0
    if a.get("ntfy_url"):
        u = urlparse(a["ntfy_url"].strip())
        body = {"topic": u.path.strip("/"), "title": title, "message": msg, "priority": prio, "tags": [tag], "click": hub_url(mac)}
        hdr = {"Content-Type": "application/json"}
        if a.get("ntfy_token"):
            hdr["Authorization"] = "Bearer " + a["ntfy_token"]
        try:
            urllib.request.urlopen(urllib.request.Request(f"{u.scheme}://{u.netloc}/", json.dumps(body).encode(), hdr), timeout=10).read()
            sent += 1
        except Exception as e:
            errs.append(f"ntfy: {e}")
    if a.get("tg_token") and a.get("tg_chat"):
        body = {"chat_id": a["tg_chat"], "text": f"{title}\n{msg}", "disable_web_page_preview": True}
        try:
            urllib.request.urlopen(urllib.request.Request(f"https://api.telegram.org/bot{a['tg_token']}/sendMessage",
                                   json.dumps(body).encode(), {"Content-Type": "application/json"}), timeout=10).read()
            sent += 1
        except Exception as e:
            errs.append(f"Telegram: {str(e).replace(a['tg_token'], '…')}")
    if errs:
        raise RuntimeError("; ".join(errs))
    return sent

def wanted(c, kind, mac, a):
    for key, (kinds, _) in ALERT_KINDS.items():
        if kind in kinds and a["kinds"].get(key):
            if key == "watch":  # "came online" also fires for unwatched devices; only push for watched ones
                r = c.execute("SELECT watch FROM devices WHERE mac=?", (mac,)).fetchone()
                return bool(r and r["watch"])
            return True
    return False

def digest_text(now):
    day = now - 86400
    with db() as c:
        devs = c.execute("SELECT * FROM devices").fetchall()
        n_new = c.execute("SELECT COUNT(*) FROM events WHERE kind='new' AND ts>?", (day,)).fetchone()[0]
        p = c.execute("SELECT COUNT(*) n, SUM(ok) ok, AVG(ms) avg FROM pings WHERE ts>?", (day,)).fetchone()
        outs = c.execute("SELECT start, COALESCE(end, ?) e FROM outages WHERE COALESCE(end, ?)>?", (now, now, day)).fetchall()
        sp = c.execute("SELECT down, up, ping FROM speedtests WHERE err IS NULL AND ts>? ORDER BY ts DESC LIMIT 1", (day,)).fetchone()
    seen = sum(1 for d in devs if (d["last_seen"] or 0) > day)
    online = sum(1 for d in devs if now - (d["last_seen"] or 0) <= (AWAY_AFTER if d["is_person"] else OFFLINE_AFTER))
    unknown = [dev_label(d) for d in devs if not d["known"]]
    down = [dev_label(d) for d in devs if d["watch"] and not d["is_person"] and now - (d["last_seen"] or 0) > OFFLINE_AFTER]
    home = [dev_label(d) for d in devs if d["is_person"] and now - (d["last_seen"] or 0) <= AWAY_AFTER]
    lines = [f"{online} devices online now, {seen} seen in the last 24 h."]
    if n_new: lines.append(f"{n_new} new device{'s' if n_new > 1 else ''} joined.")
    if unknown: lines.append(f"Waiting for approval: {', '.join(unknown[:5])}{' and more' if len(unknown) > 5 else ''}.")
    if p["n"]:
        up = (p["ok"] or 0) / p["n"] * 100
        lines.append(f"Internet: {up:.1f}% up, {p['avg'] or 0:.0f} ms average" +
                     (f", {len(outs)} outage{'s' if len(outs) > 1 else ''} ({fmt_dur(sum(o['e'] - max(o['start'], day) for o in outs))} total)." if outs else ", no outages."))
    if sp:
        lines.append(f"Speed (over the Pi's Wi-Fi): {sp['down']:.0f} Mbps down, {sp['up']:.0f} up, {sp['ping']:.0f} ms.")
    if down: lines.append(f"Watched devices offline: {', '.join(down)}.")
    if any(d["is_person"] for d in devs): lines.append(f"Home now: {', '.join(home) if home else 'nobody'}.")
    return "\n".join(lines)

def notify_loop():
    """Deliver queued events. Failed sends (e.g. during an internet outage) are retried for up to 12 hours."""
    pending = []
    while True:
        try:
            item = OUTBOX.get(timeout=30)
            items = [item]
            while not OUTBOX.empty():
                items.append(OUTBOX.get_nowait())
        except queue.Empty:
            items = []
        try:
            a, now = alert_conf(), time.time()
            enabled = a.get("ntfy_url") or (a.get("tg_token") and a.get("tg_chat"))
            if enabled and items:
                with db() as c:
                    pending += [(k, m, msg, ts) for ts, k, m, msg in items if wanted(c, k, m, a)]
            hour = a.get("digest_hour")
            if enabled and hour is not None and time.localtime(now).tm_hour == int(hour):
                today = time.strftime("%Y-%m-%d", time.localtime(now))
                with lock, db() as c:
                    r = c.execute("SELECT v FROM kv WHERE k='digest'").fetchone()
                    due = not r or r["v"] != today
                    if due:
                        c.execute("INSERT OR REPLACE INTO kv VALUES('digest', ?)", (today,))
                if due:
                    pending.append(("digest", None, digest_text(now), now))
            pending = [x for x in pending if now - x[3] < 12 * 3600][-50:]
            while pending and enabled:
                k, m, msg, ts = pending[0]
                late = f" (at {time.strftime('%H:%M', time.localtime(ts))})" if now - ts > 120 else ""
                push(k, msg + late, m, a)
                pending.pop(0)
        except Exception as e:
            print("notify error:", e, flush=True)
            time.sleep(30)

# ---------- speed test (Cloudflare's speed.cloudflare.com) ----------
SPEED_EVERY = 6          # default hours between automatic tests (0 = only when asked)
SPEED = {"running": False, "phase": None}
SPEED_LOCK = threading.Lock()

def claim_speed_test():
    """Mark a test as running; False if one already is. Callers then run speed_test()."""
    with SPEED_LOCK:
        if SPEED["running"]:
            return False
        SPEED.update(running=True, phase="starting")
        return True

def speed_test():
    """Latency, download and upload against speed.cloudflare.com, like its web speed test (about 50 MB of traffic).
    The Pi is on Wi-Fi, so this is the speed a Wi-Fi device gets here rather than the plan's full speed."""
    import http.client, statistics
    SPEED["phase"] = "latency"
    res = {"ts": time.time(), "down": None, "up": None, "ping": None, "jitter": None, "err": None}
    try:
        conn = http.client.HTTPSConnection("speed.cloudflare.com", timeout=30)
        lat, raw = [], []
        for i in range(11):   # the first request also sets up TLS, so it doesn't count
            t = time.perf_counter()
            conn.request("GET", "/__down?bytes=0")
            r = conn.getresponse(); r.read()
            ms = (time.perf_counter() - t) * 1000
            # Cloudflare reports the connection's measured network round trip (cfL4 rtt, in microseconds); that's the
            # true latency. Timing the request ourselves also counts the Pi's own TLS work, so it's only a fallback.
            st = r.getheader("Server-Timing") or ""
            rtt, work = re.search(r"[?&]rtt=(\d+)", st), re.search(r"cfSpeedWorker;dur=([\d.]+)", st)
            if i:
                lat.append(int(rtt.group(1)) / 1000 if rtt else ms)
                raw.append(ms - (float(work.group(1)) if work else 0))   # minus Cloudflare's own (variable) processing time
        res["ping"] = statistics.median(lat)
        res["jitter"] = statistics.mean(abs(a - b) for a, b in zip(raw, raw[1:]))   # rtt is smoothed, so use our own timings
        SPEED["phase"] = "download"
        rates = []
        for n in (1_000_000, 10_000_000, 25_000_000):
            conn.request("GET", f"/__down?bytes={n}")
            r, first, got = conn.getresponse(), None, 0
            while True:
                b = r.read(65536)
                if not b:
                    break
                if first is None:
                    first = time.perf_counter()
                got += len(b)
            dt = time.perf_counter() - first
            rates.append(got * 8 / max(dt, 1e-3) / 1e6)
            if dt > 8:      # slow line: skip the bigger file
                break
        res["down"] = max(rates[1:] or rates)   # the 1 MB warm-up is too short to measure well
        SPEED["phase"] = "upload"
        rates = []
        for n in (1_000_000, 5_000_000, 10_000_000):
            body = bytes(n)
            t = time.perf_counter()
            conn.request("POST", "/__up", body=body, headers={"Content-Type": "application/octet-stream"})
            conn.getresponse().read()
            dt = time.perf_counter() - t - res["ping"] / 1000
            rates.append(n * 8 / max(dt, 1e-3) / 1e6)
            if dt > 8:
                break
        res["up"] = max(rates[1:] or rates)
        conn.close()
    except Exception as e:
        res["err"] = str(e)[:200]
    finally:
        with lock, db() as c:
            c.execute("INSERT INTO speedtests(ts,down,up,ping,jitter,err) VALUES(?,?,?,?,?,?)",
                      (res["ts"], res["down"], res["up"], res["ping"], res["jitter"], res["err"]))
        SPEED.update(running=False, phase=None)
    print("speed test:", {k: round(v, 1) if isinstance(v, float) else v for k, v in res.items() if k != "ts"}, flush=True)

def speed_every():
    return (load_conf().get("speed") or {}).get("every_h", SPEED_EVERY)

def speed_loop():
    time.sleep(180)
    while True:
        try:
            every = speed_every()
            if every and not SPEED["running"]:
                with db() as c:
                    last = c.execute("SELECT MAX(ts) FROM speedtests").fetchone()[0] or 0
                if time.time() - last >= every * 3600 and claim_speed_test():
                    speed_test()
        except Exception as e:
            print("speed error:", e, flush=True)
        time.sleep(60)

def api_speed():
    with db() as c:
        recent = [dict(r) for r in c.execute("SELECT ts,down,up,ping,jitter,err FROM speedtests ORDER BY ts DESC LIMIT 10")]
    return {"running": SPEED["running"], "phase": SPEED["phase"], "every_h": speed_every(),
            "last": next((r for r in recent if not r["err"]), None), "recent": recent}

# ---------- packet capture (tcpdump; open the saved .pcap in Wireshark) ----------
# On Wi-Fi the Pi only sees its own traffic plus broadcast / multicast "chatter" (ARP, DHCP, mDNS, SSDP, ...);
# other devices' private traffic goes straight between them and the router.
CAPDIR = os.path.join(HERE, "captures")
CAP_KEEP = 10                       # saved captures to keep
CAP_PRESETS = {"all": "", "discovery": "arp or udp port 5353 or udp port 1900", "dhcp": "udp port 67 or udp port 68",
               "dns": "port 53 or udp port 5353", "pi": ""}
CAP_SAFE = re.compile(r"^[A-Za-z0-9 .:/()!&|=<>\[\]-]{0,200}$")
APP_PORTS = {53: "DNS", 5353: "mDNS", 1900: "SSDP", 67: "DHCP", 68: "DHCP", 443: "TLS", 80: "HTTP", 123: "NTP", 137: "NetBIOS",
             138: "NetBIOS", 5355: "LLMNR", 3702: "WS-Discovery", 8080: "HTTP", 22: "SSH", 1883: "MQTT", 6666: "Tuya", 6667: "Tuya",
             9999: "Kasa", 8009: "Cast", 7000: "AirPlay", 554: "RTSP", 3478: "STUN", 41641: "Tailscale"}
CAP = {"id": None, "proc": None, "running": False, "started": None, "ends": None, "filter": "", "label": "", "seq": 0,
       "rows": collections.deque(maxlen=3000), "protos": collections.Counter(), "talkers": collections.Counter(), "error": None}
CAP_LOCK = threading.Lock()

def _split_addr(a):
    """tcpdump writes '192.168.1.5.443' / 'fe80::1.5353': split off the port."""
    if a.count(".") >= 4 or (":" in a and "." in a):
        host, _, port = a.rpartition(".")
        return host, int(port) if port.isdigit() else None
    return a, None

def parse_packet(line):
    m = re.match(r"^(\d+\.\d+) (.*)$", line)
    if not m:
        return None
    ts, rest = float(m.group(1)), m.group(2)
    length = re.findall(r"length (\d+)", rest) or re.findall(r"\((\d+)\)$", rest)   # DNS lines end in "(29)"
    row = {"t": ts, "src": "", "dst": "", "proto": "Other", "len": int(length[-1]) if length else None, "info": rest}
    if rest.startswith("ARP"):
        row["proto"] = "ARP"
        a = re.search(r"tell (\S+?),", rest) or re.search(r"Reply (\S+) is-at", rest)
        row["src"], row["info"] = (a.group(1) if a else ""), rest[5:]
        return row
    m = re.match(r"^(IP6?) (\S+) > (\S+?): (.*)$", rest)
    if not m:
        row["proto"] = rest.split(",")[0].split(" ")[0][:12] or "Other"
        return row
    (src, sp), (dst, dp), info = _split_addr(m.group(2)), _split_addr(m.group(3)), m.group(4)
    row.update(src=src, dst=dst, info=info)
    app = APP_PORTS.get(sp) or APP_PORTS.get(dp)
    if "ICMP" in info:
        row["proto"] = "ICMPv6" if m.group(1) == "IP6" else "ICMP"
    elif app:
        row["proto"] = app
    elif "Flags [" in info:
        row["proto"] = "TCP"
    elif "UDP" in info:
        row["proto"] = "UDP"
    elif "igmp" in info.lower():
        row["proto"] = "IGMP"
    else:
        row["proto"] = m.group(1)
    if sp or dp:
        row["sport"], row["dport"] = sp, dp
    return row

def list_captures():
    out = []
    if os.path.isdir(CAPDIR):
        for f in sorted(os.listdir(CAPDIR), reverse=True):
            if f.endswith(".json"):
                try:
                    meta = json.load(open(os.path.join(CAPDIR, f)))
                    pcap = os.path.join(CAPDIR, f[:-5] + ".pcap")
                    meta["size"] = os.path.getsize(pcap) if os.path.exists(pcap) else 0
                    out.append(meta)
                except Exception:
                    pass
    return out

def _capture_reader(proc, cid):
    for line in proc.stdout:
        r = parse_packet(line.rstrip("\n"))
        if not r:
            continue
        with CAP_LOCK:
            if CAP["id"] != cid:
                break
            CAP["seq"] += 1
            r["n"] = CAP["seq"]
            CAP["rows"].append(r)
            CAP["protos"][r["proto"]] += 1
            if r["src"]:
                CAP["talkers"][r["src"]] += 1
    err = proc.stderr.read().strip() if proc.stderr else ""
    proc.wait()
    with CAP_LOCK:
        if CAP["id"] == cid:
            CAP["running"] = False
            lines = [l for l in err.splitlines() if not re.match(r"^(tcpdump: listening|\d+ packets)", l)]
            if proc.returncode not in (0, -15) and lines:
                CAP["error"] = lines[-1][:200]
            meta = {"id": cid, "ts": CAP["started"], "seconds": round(time.time() - CAP["started"]), "filter": CAP["filter"],
                    "label": CAP["label"], "packets": CAP["seq"]}
    try:
        json.dump(meta, open(os.path.join(CAPDIR, cid + ".json"), "w"))
        for old in list_captures()[CAP_KEEP:]:          # keep the newest few
            for ext in (".pcap", ".json"):
                try: os.remove(os.path.join(CAPDIR, old["id"] + ext))
                except FileNotFoundError: pass
    except Exception as e:
        print("capture save error:", e, flush=True)

def start_capture(d):
    preset = d.get("preset", "all")
    if preset == "device":
        ip = str(d.get("ip", ""))
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            raise ValueError("Pick a device to capture.")
        filt, label = f"host {ip}", f"Device {ip}"
    elif preset == "custom":
        filt, label = str(d.get("filter", "")).strip(), "Custom filter"
        if not CAP_SAFE.match(filt):
            raise ValueError("That filter has characters tcpdump filters don't use.")
    else:
        filt, label = CAP_PRESETS.get(preset, ""), {"all": "Everything the Pi can see", "discovery": "Discovery chatter",
                                                    "dhcp": "Devices joining (DHCP)", "dns": "Name lookups (DNS)"}.get(preset, preset)
    secs = min(300, max(5, int(d.get("seconds", 30))))
    with CAP_LOCK:
        if CAP["running"]:
            raise ValueError("A capture is already running.")
        os.makedirs(CAPDIR, exist_ok=True)
        cid = time.strftime("%Y%m%d-%H%M%S")
        cmd = ["tcpdump", "-i", "wlan0", "-n", "-l", "-tt", "-U", "-c", "20000", "-w", os.path.join(CAPDIR, cid + ".pcap"), "--print"]
        if filt:
            cmd += ["--", filt]     # "--" so a filter can never be read as a tcpdump option
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        CAP.update(id=cid, proc=proc, running=True, started=time.time(), ends=time.time() + secs, filter=filt, label=label,
                   seq=0, error=None)
        CAP["rows"].clear(); CAP["protos"].clear(); CAP["talkers"].clear()
    threading.Thread(target=_capture_reader, args=(proc, cid), daemon=True).start()
    threading.Timer(secs, stop_capture, args=(cid,)).start()

def stop_capture(cid=None):
    with CAP_LOCK:
        if CAP["running"] and CAP["proc"] and (cid is None or CAP["id"] == cid):
            CAP["proc"].terminate()

WELL_KNOWN = {"224.0.0.251": "mDNS multicast", "ff02::fb": "mDNS multicast", "239.255.255.250": "SSDP multicast",
              "ff02::c": "SSDP multicast", "255.255.255.255": "broadcast", "224.0.0.1": "all-hosts multicast", "ff02::1": "all-nodes multicast",
              "224.0.0.22": "IGMP multicast", "ff02::16": "MLD multicast", "224.0.0.252": "LLMNR multicast", "ff02::1:3": "LLMNR multicast",
              "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS", "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS"}
LLM_PROMPT = """Below is a packet capture from my home network, taken by a Raspberry Pi network monitor. Please analyse it:
explain what each device is doing, point out anything unusual, insecure or worth fixing (for example unencrypted
traffic, unexpected devices or services, chatty or misconfigured devices), and finish with a short plain-English summary."""

def _records(text):
    """Group tcpdump output into one record per packet (decode lines after the first are indented)."""
    recs = []
    for line in text.splitlines():
        if re.match(r"^\d+\.\d+ ", line):
            recs.append([line])
        elif recs and line.strip():
            recs[-1].append(line.strip())
    return recs

def capture_llm_text(cid, detail="full"):
    """A capture as one paste-ready text for an LLM: context, device map, summary, then every packet."""
    pcap = os.path.join(CAPDIR, cid + ".pcap")
    meta = json.load(open(os.path.join(CAPDIR, cid + ".json")))
    run = lambda *a: subprocess.run(["tcpdump", "-r", pcap, "-n", "-tt", *a], capture_output=True, text=True, timeout=120).stdout
    brief = _records(run())
    rows = [parse_packet(r[0]) for r in brief]
    full = _records(run("-e", "-vv")) if detail == "full" else None
    if full is not None and len(full) != len(brief):
        full = None
    devs = api_state()["devices"]
    by_ip = {d["ip"]: d for d in devs if d.get("ip")}
    by_mac = {d["mac"].split("@")[0]: d for d in devs}
    def dname(d):
        idn = d.get("ident") or {}
        typ = " ".join(x for x in [idn.get("maker"), (idn.get("type") or "").lower()] if x and x != "unknown")
        return d.get("name") or d.get("auto_name") or d.get("dname") or (d.get("hostname") or "").replace(".local", "") or typ or d.get("ip")
    # IPv6: the Pi's own addresses, and local ones (link-local or our /64) matched to devices by the MAC they came from
    import ipaddress
    v6 = subprocess.run(["ip", "-o", "-6", "addr", "show", "dev", "wlan0"], capture_output=True, text=True).stdout
    mine6 = re.findall(r"inet6 ([0-9a-f:]+)/", v6)
    prefixes = {ipaddress.ip_address(a).exploded[:19] for a in mine6 if not a.startswith("fe80")}
    pi = next((d for d in devs if d.get("ip") == local_ip()), None)
    if pi:
        by_ip.update({a: pi for a in mine6})
    if full:
        for r, rec in zip(rows, full):
            m = re.match(r"^\d+\.\d+ (\S+) > (\S+),", rec[0])
            if not (r and m):
                continue
            for ip, mac in ((r["src"], m.group(1)), (r["dst"], m.group(2))):
                if ip and ":" in ip and ip not in by_ip and mac in by_mac and mac not in EXTENDERS:
                    try:
                        local = ip.startswith("fe80") or ipaddress.ip_address(ip).exploded[:19] in prefixes
                    except ValueError:
                        local = False
                    if local:
                        by_ip[ip] = by_mac[mac]
    def nm(ip):
        if not ip:
            return "?"
        if ip in by_ip:
            return f"{dname(by_ip[ip])} ({ip})" if dname(by_ip[ip]) != ip else ip
        return f"{WELL_KNOWN[ip]} ({ip})" if ip in WELL_KNOWN else ip
    t0 = rows[0]["t"] if rows and rows[0] else meta["ts"]
    me = local_ip()
    seen_ips = {a for r in rows if r for a in (r["src"], r["dst"]) if a}
    seen_macs = set(re.findall(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", "\n".join(" ".join(r) for r in full))) if full else set()
    shown = [d for d in devs if d.get("ip") in seen_ips or d["mac"].split("@")[0] in seen_macs]
    protos, talkers, convs = collections.Counter(), collections.Counter(), {}
    for r in rows:
        if not r:
            continue
        protos[r["proto"]] += 1
        if r["src"]:
            talkers[r["src"]] += 1
        if r["src"] and r["dst"]:
            k = tuple(sorted((r["src"], r["dst"])))
            cv = convs.setdefault(k, {"n": 0, "bytes": 0, "protos": collections.Counter()})
            cv["n"] += 1; cv["bytes"] += r["len"] or 0; cv["protos"][r["proto"]] += 1
    out = [LLM_PROMPT, "", "=== CAPTURE ===",
           f"When: {time.strftime('%a %d %b %Y, %H:%M:%S %Z', time.localtime(meta['ts']))} · Length: {meta.get('seconds', '?')} s · Packets: {len(rows)} (all included)",
           f"Captured by: a Raspberry Pi home-network monitor (IP {me}) on its Wi-Fi interface (wlan0)",
           f"Filter: {meta.get('filter') or 'none (everything the Pi could hear)'} — {meta.get('label', '')}",
           "Detail: " + ("full tcpdump decode (-e -vv): MAC addresses, IP header fields and protocol details for every packet; no payload bytes"
                         if full else "one line per packet (tcpdump summary); no payload bytes"),
           "What the Pi can see: its own traffic, plus broadcast and multicast from other devices (ARP, DHCP, mDNS, SSDP...). "
           "Other devices' private (unicast) traffic goes directly to the router and is NOT in this capture.",
           f"Network: {SUBNET}, router 192.168.1.1."]
    if EXTENDERS:
        out.append(f"A Wi-Fi extender (MAC {', '.join(sorted(EXTENDERS))}) rewrites the MAC address of every device connected "
                   "through it, so their packets carry the extender's MAC instead of their own.")
    out += ["", "=== DEVICES IN THIS CAPTURE ===", f"{'IP':<16} {'MAC':<18} Name — type, maker"]
    for d in sorted(shown, key=lambda d: tuple(int(x) for x in d["ip"].split(".")) if re.fullmatch(r"[\d.]+", d.get("ip") or "") else (999,)):
        idn = d.get("ident") or {}
        extra = ", ".join(x for x in [idn.get("type") if idn.get("type") != "Unknown" else None, idn.get("maker") or d.get("vendor"), idn.get("model"), idn.get("os")] if x)
        flags = ("this Pi" if d.get("ip") == me else "") + (" · via Wi-Fi extender" if d.get("via") else "")
        out.append(f"{d.get('ip') or '':<16} {d['mac'].split('@')[0]:<18} {dname(d)}" + (f" — {extra}" if extra else "") + (f" [{flags.strip(' ·')}]" if flags else ""))
    out += ["", "=== SUMMARY ===", "Protocols: " + ", ".join(f"{p} {n}" for p, n in protos.most_common()),
            "Top senders: " + ", ".join(f"{nm(ip)} {n}" for ip, n in talkers.most_common(10)), "Conversations (top 20 by packets):"]
    for (a, b), cv in sorted(convs.items(), key=lambda kv: -kv[1]["n"])[:20]:
        out.append(f"  {nm(a)} <-> {nm(b)}: {cv['n']} packets, {cv['bytes']} bytes ({', '.join(p for p, _ in cv['protos'].most_common())})")
    out += ["", "=== PACKETS ===",
            "Format: #number  +seconds since start  source -> destination  protocol  frame length" +
            (", then tcpdump's full decode indented below (first line: MAC src > MAC dst, ethertype, length)" if full else " | tcpdump summary"), ""]
    for i, r in enumerate(rows):
        if not r:
            out.append(f"#{i+1}  {brief[i][0]}")
            continue
        head = f"#{i+1}  +{r['t'] - t0:.3f}  {nm(r['src']) if r['src'] else '?'} -> {nm(r['dst']) if r['dst'] else '(none)'}  {r['proto']}" + (f"  {r['len']} B" if r["len"] else "")
        if full:
            out.append(head)
            out.extend("    " + (re.sub(r"^\d+\.\d+ ", "", line) if j == 0 else line) for j, line in enumerate(full[i]))
        else:
            out.append(f"{head} | {r['info']}")
    return "\n".join(out) + "\n"

def api_capture(since=0):
    with CAP_LOCK:
        rows = [r for r in CAP["rows"] if r["n"] > since][-1000:]
        return {"running": CAP["running"], "id": CAP["id"], "started": CAP["started"], "ends": CAP["ends"], "filter": CAP["filter"],
                "label": CAP["label"], "count": CAP["seq"], "error": CAP["error"], "rows": rows,
                "protos": CAP["protos"].most_common(12), "talkers": CAP["talkers"].most_common(8), "files": list_captures()}

# ---------- history for the range picker ----------
RANGES = {"24h": (86400, 600), "7d": (7 * 86400, 3600), "30d": (30 * 86400, 4 * 3600)}
_hist_cache = {}

def api_history(rng):
    span, step = RANGES.get(rng, RANGES["24h"])
    now = time.time()
    key = (rng, int(now // 60))
    if key in _hist_cache:
        return _hist_cache[key]
    t0, p0 = now - span, now - 2 * span
    with db() as c:
        if rng == "24h":   # fine-grained, straight from the raw pings
            series = [dict(r) for r in c.execute(
                "SELECT CAST(ts/? AS INT)*? AS t, AVG(ms) ms, 1.0-AVG(ok) loss FROM pings WHERE ts>? GROUP BY t ORDER BY t", (step, step, t0))]
            q = "SELECT COUNT(*) n, SUM(ok) ok, AVG(ms) avg FROM pings WHERE ts>? AND ts<=?"
        else:              # longer ranges come from the hourly roll-up
            series = [dict(r) for r in c.execute(
                """SELECT CAST(t/? AS INT)*? AS t, SUM(ms_sum)/NULLIF(SUM(ms_n),0) ms, 1.0-SUM(ok)*1.0/SUM(n) loss
                   FROM ping_hours WHERE t>? GROUP BY 1 ORDER BY 1""", (step, step, t0 - 3600))]
            q = "SELECT SUM(n) n, SUM(ok) ok, SUM(ms_sum)/NULLIF(SUM(ms_n),0) avg FROM ping_hours WHERE t>? AND t<=?"
        cur, prev = c.execute(q, (t0, now)).fetchone(), c.execute(q, (p0, t0)).fetchone()
        outs = [dict(r) for r in c.execute("SELECT * FROM outages WHERE COALESCE(end, ?)>? ORDER BY id DESC", (now, t0))]
        new = c.execute("SELECT COUNT(*) FROM events WHERE kind='new' AND ts>?", (t0,)).fetchone()[0]
        new_prev = c.execute("SELECT COUNT(*) FROM events WHERE kind='new' AND ts>? AND ts<=?", (p0, t0)).fetchone()[0]
        sess = c.execute("SELECT mac, start, end FROM sessions WHERE end>?", (t0 - step,)).fetchall()
        first_sess = c.execute("SELECT MIN(start) FROM sessions").fetchone()[0] or now
        speed = [dict(r) for r in c.execute("SELECT ts,down,up,ping FROM speedtests WHERE ts>? AND err IS NULL ORDER BY ts", (t0,))]
    # devices online per bucket: mark every bucket each online stretch overlaps
    nb = int(span // step)
    b0 = (int(now // step) - nb + 1) * step
    buckets = [set() for _ in range(nb)]
    for m, s0, s1 in sess:
        for i in range(max(0, int((s0 - b0) // step)), min(nb - 1, int((s1 - b0) // step)) + 1):
            buckets[i].add(m)
    online = [{"t": b0 + i * step, "n": len(b) if b0 + (i + 1) * step > first_sess else None} for i, b in enumerate(buckets)]
    pct = lambda r: (r["ok"] or 0) / r["n"] * 100 if r["n"] else None
    out = {"range": rng, "t0": t0, "t1": now, "step": step, "online": online, "new": new, "new_prev": new_prev, "speed": speed,
           "internet": {"series": series, "avg": cur["avg"], "avg_prev": prev["avg"], "uptime": pct(cur), "uptime_prev": pct(prev),
                        "outages": outs}}
    _hist_cache.clear()
    _hist_cache[key] = out
    return out

# ---------- auth ----------
def load_conf():
    try:
        return json.load(open(CONF))
    except FileNotFoundError:
        return {}

def save_conf(conf):
    tmp = CONF + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(conf, f)
    os.replace(tmp, CONF)

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()

def set_password(pw):
    conf = load_conf()
    conf["salt"] = secrets.token_hex(16)
    conf["hash"] = hash_pw(pw, conf["salt"])
    conf["secret"] = secrets.token_hex(32)   # rotating the secret signs everyone out
    save_conf(conf)

def check_password(pw):
    conf = load_conf()
    return "hash" in conf and hmac.compare_digest(hash_pw(pw, conf["salt"]), conf["hash"])

def make_token():
    exp = str(int(time.time()) + COOKIE_DAYS * 86400)
    sig = hmac.new(bytes.fromhex(load_conf()["secret"]), exp.encode(), "sha256").hexdigest()
    return f"{exp}.{sig}"

def valid_token(tok):
    try:
        exp, sig = tok.split(".")
        good = hmac.new(bytes.fromhex(load_conf()["secret"]), exp.encode(), "sha256").hexdigest()
        return hmac.compare_digest(sig, good) and int(exp) > time.time()
    except Exception:
        return False

failures = {}  # ip -> (count, last_ts)

# ---------- web ----------
def api_state():
    now = time.time()
    with db() as c:
        devs = []
        for r in c.execute("SELECT mac,ip,hostname,name,vendor,is_person,known,first_seen,last_seen,info,ports,type_override,owner,location,watch FROM devices ORDER BY last_seen DESC"):
            d = dict(r); info = json.loads(d.pop("info") or "{}"); d.pop("ports")
            lim = AWAY_AFTER if r["is_person"] else OFFLINE_AFTER
            d["online"] = now - (r["last_seen"] or 0) <= lim
            d["model"] = model_of(info)
            d["dname"] = disc_name(info)
            idn = ident.identify(d, info, json.loads(r["ports"]) if r["ports"] else None, vendor)
            d["ident"] = {k: idn[k] for k in ("type", "confidence", "maker", "model", "os")}
            d["auto_name"] = ident.auto_name(d, info)
            d["services"] = list((info.get("mdns") or {}).get("services", {}).keys())
            devs.append(d)
        events = [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 60")]
        day = now - 86400
        p = c.execute("SELECT COUNT(*) n, SUM(ok) ok, AVG(ms) avg FROM pings WHERE ts>?", (day,)).fetchone()
        series = [dict(r) for r in c.execute(
            "SELECT CAST(ts/600 AS INT)*600 AS t, AVG(ms) ms, 1.0-AVG(ok) loss FROM pings WHERE ts>? GROUP BY t ORDER BY t", (day,))]
        outs = [dict(r) for r in c.execute("SELECT * FROM outages WHERE start>? ORDER BY id DESC LIMIT 20", (now - 7 * 86400,))]
        last = c.execute("SELECT ok, ms FROM pings ORDER BY ts DESC LIMIT 1").fetchone()
        prev = c.execute("SELECT COUNT(*) n, SUM(ok) ok, AVG(ms) avg FROM pings WHERE ts>? AND ts<=?", (now - 2 * 86400, day)).fetchone()
        new24 = c.execute("SELECT COUNT(*) FROM events WHERE kind='new' AND ts>?", (day,)).fetchone()[0]
        new_prev = c.execute("SELECT COUNT(*) FROM events WHERE kind='new' AND ts>? AND ts<=?", (now - 2 * 86400, day)).fetchone()[0]
        sess = c.execute("SELECT mac, start, end FROM sessions WHERE end>?", (now - 2 * 86400 - 1800,)).fetchall()
    # devices online per half hour over the last 48 hours (a device counts if it was seen during that half hour)
    b0 = int(now // 1800) * 1800 - 95 * 1800
    online_series = []
    for i in range(96):
        t0 = b0 + i * 1800
        online_series.append({"t": t0, "n": len({m for m, s0, s1 in sess if s0 < t0 + 1800 and s1 >= t0})})
    up = (p["ok"] or 0) / p["n"] * 100 if p["n"] else None
    up_prev = (prev["ok"] or 0) / prev["n"] * 100 if prev["n"] else None
    with db() as c:
        sp = c.execute("SELECT ts,down,up,ping FROM speedtests WHERE err IS NULL ORDER BY ts DESC LIMIT 1").fetchone()
    return {"now": now, "devices": devs, "events": events, "online_series": online_series,
            "speed": {"last": dict(sp) if sp else None, "running": SPEED["running"], "phase": SPEED["phase"]},
            "new_24h": new24, "new_prev": new_prev,
            "internet": {"up": bool(last and last["ok"]), "ms": last["ms"] if last else None,
                         "uptime24h": up, "avg_ms": p["avg"], "series": series, "outages": outs,
                         "avg_prev": prev["avg"], "uptime_prev": up_prev}}

def model_of(info):
    u, t = info.get("upnp") or {}, (info.get("mdns") or {}).get("txt") or {}
    return (" ".join(filter(None, [u.get("manufacturer"), u.get("modelName")])) if u.get("modelName") else None) \
        or t.get("md") or t.get("model") or t.get("ty") or t.get("am") or t.get("rpmd") or t.get("product")

def disc_name(info):
    """Best human name a device advertises about itself."""
    u, md = info.get("upnp") or {}, info.get("mdns") or {}
    t = md.get("txt") or {}
    for k in ("n", "fn"):
        if t.get(k) and not re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", t[k]):  # skip random IDs
            return t[k]
    if u.get("friendlyName"):
        return u["friendlyName"]
    # only trust instance names from services where they are meant for humans
    for svc in ("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_uscan._tcp", "_airplay._tcp", "_googlecast._tcp",
                "_companion-link._tcp", "_hap._tcp", "_smb._tcp", "_device-info._tcp", "_workstation._tcp",
                "_http._tcp", "_dosvc._tcp", "_sftp-ssh._tcp", "_ssh._tcp", "_rfb._tcp"):
        n = ((md.get("services") or {}).get(svc) or {}).get("name") or ""
        if n:
            n = re.sub(r"@.*$", "", n) if svc == "_raop._tcp" else n
            n = re.sub(r"\s*\[[0-9A-Fa-f:]{6,17}\]$", "", n)
            if not re.fullmatch(r"[0-9A-Fa-f:-]{12,}", n):
                return n
    return None

EVENT_GROUPS = {"new": ["new"], "people": ["arrive", "leave"], "devices": ["online", "offline"],
                "ip": ["ip"], "internet": ["outage", "restored"]}

def api_events(q):
    """Paged, filterable activity log. `before` is the id of the oldest event already shown."""
    where, args = [], []
    kinds = [k for g in (q.get("group", [""])[0] or "").split(",") for k in EVENT_GROUPS.get(g, [])]
    if kinds:
        where.append(f"e.kind IN ({','.join('?' * len(kinds))})"); args += kinds
    if q.get("mac", [""])[0]:
        where.append("e.mac=?"); args.append(q["mac"][0].lower())
    if q.get("q", [""])[0]:
        t = "%" + q["q"][0].strip().replace("%", "") + "%"
        where.append("(e.msg LIKE ? OR d.name LIKE ? OR d.owner LIKE ? OR d.location LIKE ? OR e.mac LIKE ?)"); args += [t] * 5
    if q.get("before", [""])[0]:
        where.append("e.id<?"); args.append(int(q["before"][0]))
    if q.get("days", [""])[0]:
        where.append("e.ts>?"); args.append(time.time() - int(q["days"][0]) * 86400)
    limit = min(200, max(1, int(q.get("limit", ["50"])[0] or 50)))
    sql = ("SELECT e.*, d.name, d.owner, d.location FROM events e LEFT JOIN devices d ON d.mac=e.mac"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY e.id DESC LIMIT ?")
    with db() as c:
        rows = [dict(r) for r in c.execute(sql, args + [limit + 1])]
        counts = {g: 0 for g in EVENT_GROUPS}
        for r in c.execute("SELECT kind, COUNT(*) n FROM events WHERE ts>? GROUP BY kind", (time.time() - 7 * 86400,)):
            for g, ks in EVENT_GROUPS.items():
                if r["kind"] in ks: counts[g] += r["n"]
    return {"events": rows[:limit], "more": len(rows) > limit, "week": counts}

# --- Brightspace calendar feed -------------------------------------------------
# The feed URL carries its own token, so the Pi can fetch it without a Brightspace
# login. It has the events but no grades, so "done" still comes from the last
# schedule.json import (matched by title).
feed = {"items": [], "synced": None, "error": None, "tried": 0}

def _norm_title(t):
    t = re.sub(r"\s+-\s+due$", "", (t or "").strip(), flags=re.I)
    return re.sub(r"[^a-z0-9.]+", " ", t.lower()).strip()

def parse_ics(text):
    lines = []
    for raw in text.splitlines():
        if raw[:1] in (" ", "\t") and lines:   # RFC 5545 line folding
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    evs, cur = [], None
    for ln in lines:
        if ln == "BEGIN:VEVENT":
            cur = {}
        elif ln == "END:VEVENT":
            if cur is not None:
                evs.append(cur)
            cur = None
        elif cur is not None and ":" in ln:
            k, v = ln.split(":", 1)
            name, _, params = k.partition(";")
            cur[name.upper()] = (v, params.upper())
    return evs

def _ics_text(v):
    return re.sub(r"\\([,;\\nN])", lambda m: "\n" if m.group(1) in "nN" else m.group(1), v)

def feed_items(evs):
    now, out = time.time(), []
    for e in evs:
        v, params = e.get("DTSTART", ("", ""))
        try:
            if "VALUE=DATE" in params and len(v) == 8:   # all-day: local midnight, no zone
                ts = time.mktime(time.strptime(v, "%Y%m%d"))
                when = f"{v[:4]}-{v[4:6]}-{v[6:]}T00:00:00"
            elif v.endswith("Z"):
                ts = calendar.timegm(time.strptime(v, "%Y%m%dT%H%M%SZ"))
                when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
            else:
                continue   # floating/TZID times: Brightspace doesn't send these
        except ValueError:
            continue
        if not now - 60 * 86400 <= ts <= now + 240 * 86400:   # drops last term's leftovers
            continue
        loc = _ics_text(e.get("LOCATION", ("", ""))[0])
        m = re.search(r"\b([A-Z]{3,4})\s?(\d{3})\b", loc)
        desc = _ics_text(e.get("DESCRIPTION", ("", ""))[0])
        links = re.findall(r"https://[a-z0-9.-]+\.brightspace\.com/[^\s\"<>]+", desc)
        view = re.search(r"View event - (https://[a-z0-9.-]+\.brightspace\.com/[^\s\"<>]+)", desc)
        title = re.sub(r"\s+-\s+Due$", "", _ics_text(e.get("SUMMARY", ("", ""))[0]).strip())
        out.append({"course": m.group(1) + m.group(2) if m else loc[:20], "kind": "Calendar", "title": title[:200],
                    "when": when, "link": (view.group(1) if view else links[0] if links else "")[:500],
                    "uid": e.get("UID", ("", ""))[0][:100]})
    return sorted(out, key=lambda i: i["when"])

def sync_school_feed(force=False):
    url = load_conf().get("school_feed")
    if not url or (force and time.time() - feed["tried"] < 15):
        return
    feed["tried"] = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HomeHub/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read(4_000_000).decode("utf-8", "replace")
        if "BEGIN:VCALENDAR" not in text:
            raise ValueError("Brightspace didn't send a calendar. Has the feed link been reset?")
        items = feed_items(parse_ics(text))
        feed.update(items=items, synced=time.time(), error=None)
        tmp = FEED_CACHE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"items": items, "synced": feed["synced"]}, f)
        os.replace(tmp, FEED_CACHE)
    except Exception as e:
        feed["error"] = re.sub(r"token=[^&\s]+", "token=…", str(e))[:200]

def load_feed_cache():
    try:
        with open(FEED_CACHE) as f:
            c = json.load(f)
        feed.update(items=c.get("items") or [], synced=c.get("synced"))
    except (OSError, ValueError):
        pass

def feed_loop():
    while True:
        sync_school_feed()
        time.sleep(FEED_EVERY)

def set_school_feed(url):
    conf = load_conf()
    if not url:
        conf.pop("school_feed", None)
        save_conf(conf)
        feed.update(items=[], synced=None, error=None)
        try:
            os.remove(FEED_CACHE)
        except OSError:
            pass
        return
    p = urlparse(url)
    if p.scheme != "https" or not (p.hostname or "").endswith(".brightspace.com") or not p.path.endswith(".ics"):
        raise ValueError("That isn't a Brightspace calendar feed link (https://…brightspace.com/…/feed.ics?token=…).")
    conf["school_feed"] = url
    save_conf(conf)
    feed.update(items=[], synced=None, error=None, tried=0)
    sync_school_feed()

def api_school():
    try:
        with open(SCHOOL) as f:
            d = json.load(f)
        d["saved"] = os.path.getmtime(SCHOOL)
    except (OSError, ValueError):
        d = {"items": [], "news": [], "notes": [], "generated": None, "saved": None}
    on = bool(load_conf().get("school_feed"))
    if on and feed["items"]:
        # Done = scored in Brightspace grades, as of the last schedule.json import.
        done = {_norm_title(i["title"]) for i in d["items"] if i.get("done")} | {_norm_title(n) for n in d.get("scored") or []}
        done.discard("")
        def is_done(title):
            n = _norm_title(title)
            return n in done or (len(n) >= 8 and any(len(x) >= 8 and (x in n or n in x) for x in done))
        have = {_norm_title(i["title"]) for i in feed["items"]}
        d["items"] = [dict(i, done=is_done(i["title"])) for i in feed["items"]] + \
                     [i for i in d["items"] if _norm_title(i["title"]) not in have]
    d.pop("scored", None)
    d["feed"] = {"set": on, "synced": feed["synced"], "error": feed["error"] if on else None, "count": len(feed["items"])}
    return d


def save_school(d):
    """Keep only the fields the School tab uses, trimmed, so a bad import can't bloat or break the page."""
    if not isinstance(d, dict) or not isinstance(d.get("items"), list):
        raise ValueError("That doesn't look like a schedule file (no items list).")
    s = lambda v, n: str(v if v is not None else "")[:n]
    items = []
    for i in d["items"][:500]:
        if isinstance(i, dict) and i.get("when") and i.get("title"):
            items.append({"course": s(i.get("course"), 20), "kind": s(i.get("kind"), 20), "title": s(i["title"], 200),
                          "when": s(i["when"], 40), "done": bool(i.get("done"))})
    news = [{"course": s(n.get("course"), 20), "when": s(n.get("when"), 40), "title": s(n.get("title"), 200), "body": s(n.get("body"), 400)}
            for n in (d.get("news") or [])[:30] if isinstance(n, dict)]
    notes = [s(n, 300) for n in (d.get("notes") or [])[:20]]
    scored = [s(n, 200) for n in (d.get("scored") or [])[:500] if n]
    out = {"generated": s(d.get("generated"), 40), "tz": s(d.get("tz"), 40), "items": items, "news": news, "notes": notes,
           "scored": scored}
    tmp = SCHOOL + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f)
    os.replace(tmp, SCHOOL)
    return len(items)


def api_alerts():
    a = alert_conf()
    tok = a.get("tg_token") or ""
    return {"ntfy_url": a.get("ntfy_url") or "", "ntfy_token_set": bool(a.get("ntfy_token")),
            "tg_token_set": bool(tok), "tg_token_hint": ("…" + tok[-4:]) if tok else "", "tg_chat": a.get("tg_chat") or "",
            "kinds": a["kinds"], "watch_after_min": a["watch_after_min"], "digest_hour": a["digest_hour"]}

def save_alerts(d):
    conf = load_conf()
    a = alert_conf()
    url = (d.get("ntfy_url") or "").strip()
    if url and not re.match(r"^https?://[^/\s]+/[A-Za-z0-9_-]{1,64}/?$", url):
        raise ValueError("The ntfy address should look like https://ntfy.sh/your-topic-name")
    a["ntfy_url"] = url
    for k in ("ntfy_token", "tg_token"):  # blank means "keep what's saved"; "-" clears it
        v = (d.get(k) or "").strip()
        if v == "-": a.pop(k, None)
        elif v: a[k] = v
    a["tg_chat"] = str(d.get("tg_chat") or "").strip()
    a["kinds"] = {k: bool((d.get("kinds") or {}).get(k)) for k in ALERT_KINDS}
    a["watch_after_min"] = min(120, max(2, int(d.get("watch_after_min") or 5)))
    h = d.get("digest_hour")
    a["digest_hour"] = None if h in (None, "", "off") else min(23, max(0, int(h)))
    conf["alerts"] = a
    save_conf(conf)

def api_presence(mac, days=14):
    """Home/away history for a device, built from its Wi-Fi sightings.
    Phones drop off Wi-Fi to save battery, so gaps shorter than AWAY_AFTER are
    treated as still home. A trip is the gap between two stays: it starts at the
    last sighting (when they left) and ends at the next first sighting (back home)."""
    now = time.time()
    since = now - days * 86400
    with db() as c:
        r = c.execute("SELECT is_person, last_seen FROM devices WHERE mac=?", (mac,)).fetchone()
        if not r:
            return None
        rows = c.execute("SELECT start, end FROM sessions WHERE mac=? AND end>? ORDER BY start",
                         (mac, since - 86400)).fetchall()
    stays = []
    for s0, s1 in rows:
        if stays and s0 - stays[-1][1] <= AWAY_AFTER:
            stays[-1][1] = max(stays[-1][1], s1)
        else:
            stays.append([s0, s1])
    home_now = bool(stays) and now - stays[-1][1] <= AWAY_AFTER
    if home_now:
        stays[-1][1] = now
    trips = [{"left": a[1], "back": b[0], "away": b[0] - a[1]} for a, b in zip(stays, stays[1:]) if b[0] > since]
    if stays and not home_now:
        trips.append({"left": stays[-1][1], "back": None, "away": now - stays[-1][1]})
    tracked_from = rows[0][0] if rows else None
    return {"now": now, "since": since, "home_now": home_now, "tracked_from": tracked_from,
            "stays": [{"start": a, "end": b} for a, b in stays if b > since],
            "trips": trips[::-1]}

def api_device(mac):
    now = time.time()
    with db() as c:
        r = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["info"] = json.loads(d["info"] or "{}")
        d["ports"] = json.loads(d["ports"]) if d["ports"] else None
        d["model"] = model_of(d["info"])
        d["dname"] = disc_name(d["info"])
        d["ident"] = ident.identify(d, d["info"], d["ports"], vendor)
        d["auto_name"] = ident.auto_name(d, d["info"])
        d["types"] = ident.TYPES
        d["online"] = now - (r["last_seen"] or 0) <= (AWAY_AFTER if r["is_person"] else OFFLINE_AFTER)
        d["private_mac"] = private_mac(mac)
        d["shared_mac"] = behind_extender(mac)
        d["scanning"] = mac in scanning
        d["sessions"] = [dict(x) for x in c.execute(
            "SELECT start,end FROM sessions WHERE mac=? AND end>? ORDER BY start", (mac, now - 7 * 86400))]
        d["events"] = [dict(x) for x in c.execute("SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT 30", (mac,))]
    d["now"] = now
    return d

LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="default">
<title>Sign in · Home Hub</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet"><style>
/* Styled after Cloudflare's sign-in page. Written for old Safari too (iPad 2 / iOS 9): no CSS variables, no grid */
*{-webkit-box-sizing:border-box;box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:#fff;color:#262626;font:14px/1.5 Inter,-apple-system,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{display:-webkit-box;display:-webkit-flex;display:flex;min-height:100%}
.l{-webkit-box-flex:1;-webkit-flex:1;flex:1;position:relative;padding:20px 24px 40px}
.mk{width:30px;height:30px;border-radius:8px;background:#f6821f;padding:6px}
.mk svg{width:18px;height:18px;display:block}
form{max-width:354px;margin:84px auto 0;text-align:center}
h1{font-size:22px;font-weight:500;letter-spacing:-.01em;margin:0 0 26px;color:#0a0a0a}
label{display:block;text-align:left;font-size:13px;font-weight:500;color:#0a0a0a;margin:0 0 6px}
input{width:100%;height:40px;padding:0 12px;border:1px solid #d4d4d4;border-radius:8px;background:#fff;color:#0a0a0a;font:inherit;font-size:16px;outline:0;-webkit-appearance:none}
input:focus{border-color:#f6821f;box-shadow:0 0 0 2px rgba(246,130,31,.18)}
button{margin-top:14px;width:100%;height:38px;border:0;border-radius:8px;background:#f0f0f0;color:#262626;font:inherit;font-weight:500;font-size:14px;cursor:pointer;-webkit-appearance:none}
button:hover{background:#e8e8e8}
.or{display:-webkit-box;display:-webkit-flex;display:flex;-webkit-align-items:center;align-items:center;color:#a3a3a3;font-size:13px;margin:22px 0 14px}
.or:before,.or:after{content:"";-webkit-flex:1;flex:1;height:1px;background:#e5e5e5}
.or:before{margin-right:14px}.or:after{margin-left:14px}
.err{color:#b91c1c;font-size:13.5px;margin:10px 0 0;text-align:left}
.ft{color:#737373;font-size:13px;line-height:1.6}
.r{width:42%;position:relative;overflow:hidden;background:#f6821f;background:-webkit-linear-gradient(0deg,#e5590c,#ff6b1a);background:linear-gradient(90deg,#e5590c,#ff6b1a);color:#fff;padding:0 64px;display:-webkit-box;display:-webkit-flex;display:flex;-webkit-box-orient:vertical;-webkit-flex-direction:column;flex-direction:column;-webkit-justify-content:center;justify-content:center}
.globe{position:absolute;width:780px;height:780px;border-radius:50%;right:-300px;top:50%;margin-top:-390px;opacity:.55;
 background:-webkit-repeating-linear-gradient(145deg,rgba(255,255,255,.5) 0,rgba(255,255,255,.5) 1.5px,transparent 1.5px,transparent 6px);
 background:repeating-linear-gradient(-55deg,rgba(255,255,255,.5) 0,rgba(255,255,255,.5) 1.5px,transparent 1.5px,transparent 6px)}
.r>div{position:relative;z-index:1}
.r .k{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;font-weight:600;color:#ffe2cc;margin-bottom:12px}
.r h2{font-size:30px;font-weight:600;line-height:1.2;letter-spacing:-.015em;margin:0 0 14px}
.r p{margin:0;font-size:15px;color:#fff3e8}
@media(max-width:900px){.r{display:none}form{margin-top:60px}}
</style></head><body><div class="wrap">
<div class="l"><div class="mk"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l-2 0l9 -9l9 9l-2 0"/><path d="M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-7"/><path d="M9 21v-6a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v6"/></svg></div>
<form method="post" action="/login"><h1>Sign in to Home Hub</h1>
<label for="p">Password</label><input id="p" name="password" type="password" autofocus autocomplete="current-password">%MSG%
<button>Sign in</button>
<div style="height:1px;background:#e5e5e5;margin:24px 0 14px"></div>
<div class="ft">Home Hub · Raspberry Pi</div></form></div>
<div class="r"><span class="globe"></span><div><div class="k">Home Hub · Raspberry Pi</div><h2>Your home network,<br>at a glance.</h2><p>Every device, outage and arrival, in one place.</p></div></div>
</div></body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, code, body, ctype="application/json", headers=()):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def authed(self):
        m = re.search(r"(?:^|;\s*)hub=([^;]+)", self.headers.get("Cookie", ""))
        ok = bool(m and valid_token(m.group(1)))
        # sliding session: refresh the cookie once it is a day old so an always-on display never gets signed out
        self.renew = ok and int(m.group(1).split(".")[0]) < time.time() + (COOKIE_DAYS - 1) * 86400
        return ok

    def cookie(self):
        return ("Set-Cookie", f"hub={make_token()}; Path=/; Max-Age={COOKIE_DAYS*86400}; HttpOnly; SameSite=Strict")

    def body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(min(n, 65536))

    def login_page(self, msg="", code=200):
        self.send(code, LOGIN_HTML.replace("%MSG%", f'<p class="err">{msg}</p>' if msg else ""), "text/html; charset=utf-8")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            return self.login_page()
        if u.path == "/logout":
            return self.send(303, "", "text/plain", [("Location", "/login"), ("Set-Cookie", "hub=; Path=/; Max-Age=0")])
        if not self.authed():
            if u.path.startswith("/api/"):
                return self.send(401, '{"error":"auth"}')
            return self.send(303, "", "text/plain", [("Location", "/login")])
        if u.path == "/api/state":
            self.send(200, json.dumps(api_state()), headers=[self.cookie()] if self.renew else ())
        elif u.path == "/api/presence":
            q = parse_qs(u.query)
            d = api_presence(q.get("mac", [""])[0].lower(), min(90, max(1, int(q.get("days", ["14"])[0] or 14))))
            self.send(200 if d else 404, json.dumps(d or {"error": "not found"}))
        elif u.path == "/api/events":
            self.send(200, json.dumps(api_events(parse_qs(u.query))))
        elif u.path == "/api/history":
            self.send(200, json.dumps(api_history(parse_qs(u.query).get("range", ["24h"])[0])))
        elif u.path == "/api/speed":
            self.send(200, json.dumps(api_speed()))
        elif u.path == "/api/capture":
            self.send(200, json.dumps(api_capture(int(parse_qs(u.query).get("since", ["0"])[0] or 0))))
        elif u.path == "/api/capture/llm":
            q = parse_qs(u.query)
            cid = q.get("id", [""])[0]
            if not re.fullmatch(r"\d{8}-\d{6}", cid) or not os.path.exists(os.path.join(CAPDIR, cid + ".json")):
                return self.send(404, '{"error":"Capture not found, or still running."}')
            text = capture_llm_text(cid, "brief" if q.get("detail", [""])[0] == "brief" else "full")
            hdr = [("Content-Disposition", f'attachment; filename="homehub-{cid}-for-llm.txt"')] if q.get("dl") else []
            self.send(200, text, "text/plain; charset=utf-8", hdr)
        elif u.path == "/api/capture/file":
            cid = parse_qs(u.query).get("id", [""])[0]
            path = os.path.join(CAPDIR, cid + ".pcap")
            if not re.fullmatch(r"\d{8}-\d{6}", cid) or not os.path.exists(path):
                return self.send(404, '{"error":"not found"}')
            self.send(200, open(path, "rb").read(), "application/vnd.tcpdump.pcap",
                      [("Content-Disposition", f'attachment; filename="homehub-{cid}.pcap"')])
        elif u.path == "/api/alerts":
            self.send(200, json.dumps(api_alerts()))
        elif u.path == "/api/school":
            self.send(200, json.dumps(api_school()))
        elif u.path == "/api/device":
            d = api_device(parse_qs(u.query).get("mac", [""])[0].lower())
            self.send(200 if d else 404, json.dumps(d or {"error": "not found"}))
        elif u.path in ("/", "/index.html"):
            self.send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html; charset=utf-8")
        elif u.path == "/display":
            self.send(200, open(os.path.join(HERE, "display.html"), "rb").read(), "text/html; charset=utf-8")
        else:
            self.send(404, "{}")

    def do_POST(self):
        u = urlparse(self.path)
        ip = self.client_address[0]
        if u.path == "/login":
            n, last = failures.get(ip, (0, 0))
            if n >= 5 and time.time() - last < 60:
                return self.login_page("Too many attempts. Wait a minute and try again.", 429)
            pw = parse_qs(self.body().decode(errors="ignore")).get("password", [""])[0]
            if check_password(pw):
                failures.pop(ip, None)
                return self.send(303, "", "text/plain", [("Location", "/"),
                    ("Set-Cookie", f"hub={make_token()}; Path=/; Max-Age={COOKIE_DAYS*86400}; HttpOnly; SameSite=Strict")])
            failures[ip] = (n + 1 if time.time() - last < 600 else 1, time.time())
            time.sleep(1)
            return self.login_page("Wrong password.", 401)
        if not self.authed():
            return self.send(401, '{"error":"auth"}')
        try:
            d = json.loads(self.body() or b"{}")
            mac = str(d.get("mac", "")).lower()
            if u.path == "/api/school":
                return self.send(200, json.dumps({"ok": True, "count": save_school(d)}))
            if u.path == "/api/school/feed":
                set_school_feed(str(d.get("url", "")).strip())
                return self.send(200, json.dumps(api_school()["feed"]))
            if u.path == "/api/school/sync":
                sync_school_feed(force=True)
                return self.send(200, json.dumps(api_school()["feed"]))
            if u.path == "/api/password":
                if not check_password(d.get("current", "")):
                    return self.send(403, '{"error":"Current password is wrong."}')
                if len(d.get("new", "")) < 8:
                    return self.send(400, '{"error":"Use at least 8 characters."}')
                set_password(d["new"])
                return self.send(200, "{}", headers=[("Set-Cookie",
                    f"hub={make_token()}; Path=/; Max-Age={COOKIE_DAYS*86400}; HttpOnly; SameSite=Strict")])
            if u.path == "/api/alerts":
                save_alerts(d)
                return self.send(200, json.dumps(api_alerts()))
            if u.path == "/api/alerts/test":
                try:
                    n = push("test", "Notifications from your Home Hub are working.")
                except Exception as e:
                    return self.send(502, json.dumps({"error": str(e)[:300]}))
                return self.send(200 if n else 400, json.dumps({"sent": n} if n else {"error": "Set up ntfy or Telegram first, then save."}))
            if u.path == "/api/speed/run":
                if claim_speed_test():
                    threading.Thread(target=speed_test, daemon=True).start()
                return self.send(200, json.dumps(api_speed()))
            if u.path == "/api/speed/settings":
                conf = load_conf()
                conf["speed"] = {"every_h": int(d.get("every_h", SPEED_EVERY)) if int(d.get("every_h", SPEED_EVERY)) in (0, 1, 3, 6, 12, 24) else SPEED_EVERY}
                save_conf(conf)
                return self.send(200, json.dumps(api_speed()))
            if u.path == "/api/capture/start":
                try:
                    start_capture(d)
                except ValueError as e:
                    return self.send(400, json.dumps({"error": str(e)}))
                return self.send(200, json.dumps(api_capture()))
            if u.path == "/api/capture/stop":
                stop_capture()
                return self.send(200, "{}")
            if u.path == "/api/capture/delete":
                cid = str(d.get("id", ""))
                if re.fullmatch(r"\d{8}-\d{6}", cid) and cid != (CAP["id"] if CAP["running"] else None):
                    print(f"capture {cid} deleted (request from {ip})", flush=True)
                    for ext in (".pcap", ".json"):
                        try: os.remove(os.path.join(CAPDIR, cid + ext))
                        except FileNotFoundError: pass
                return self.send(200, json.dumps({"files": list_captures()}))
            if u.path == "/api/approve_all":
                with lock, db() as c:
                    n = c.execute("UPDATE devices SET known=1 WHERE known=0").rowcount
                return self.send(200, json.dumps({"approved": n}))
            with db() as c:
                row = c.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
            if not row:
                return self.send(404, '{"error":"unknown device"}')
            if u.path == "/api/device":
                with lock, db() as c:
                    if "type_override" in d and d["type_override"] not in ident.TYPES:
                        d["type_override"] = None
                    for k in ("name", "is_person", "known", "notes", "type_override", "owner", "location", "watch"):
                        if k in d:
                            c.execute(f"UPDATE devices SET {k}=? WHERE mac=?", (d[k], mac))
                self.send(200, "{}")
            elif u.path == "/api/scan":
                if mac not in scanning:
                    scanning.add(mac)
                    threading.Thread(target=port_scan, args=(mac, row["ip"]), daemon=True).start()
                self.send(200, "{}")
            elif u.path == "/api/ping":
                self.send(200, json.dumps(ping_device(row["ip"])))
            elif u.path == "/api/wake":
                wake(mac); self.send(200, "{}")
            elif u.path == "/api/forget":
                with lock, db() as c:
                    c.execute("DELETE FROM devices WHERE mac=?", (mac,))
                    c.execute("DELETE FROM sessions WHERE mac=?", (mac,))
                self.send(200, "{}")
            else:
                self.send(404, "{}")
        except Exception as e:
            self.send(400, json.dumps({"error": str(e)}))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--set-password":
        import getpass
        pw = getpass.getpass("New password: ")
        if len(pw) < 8 or pw != getpass.getpass("Again: "):
            sys.exit("Passwords must match and be at least 8 characters.")
        set_password(pw); print("Password set. Everyone has been signed out.")
        sys.exit()
    if "hash" not in load_conf():
        pw = secrets.token_urlsafe(9)
        set_password(pw)
        print(f"No password configured. Generated one: {pw}", flush=True)
    load_oui()
    init()
    with db() as c:  # backfill vendors for devices seen before vendor lookup existed
        for r in c.execute("SELECT mac FROM devices WHERE vendor IS NULL").fetchall():
            c.execute("UPDATE devices SET vendor=? WHERE mac=?", (vendor(r["mac"]), r["mac"]))
    with db() as c:
        aggregate_pings(c, since=0)
    load_extender_state()
    migrate_extender_records()
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=ping_loop, daemon=True).start()
    threading.Thread(target=discover_loop, daemon=True).start()
    threading.Thread(target=fingerprint_loop, daemon=True).start()
    threading.Thread(target=notify_loop, daemon=True).start()
    threading.Thread(target=speed_loop, daemon=True).start()
    load_feed_cache()
    threading.Thread(target=feed_loop, daemon=True).start()
    threading.Thread(target=ident.dhcp_listener, args=(on_dhcp,), daemon=True).start()
    print(f"Home hub on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()

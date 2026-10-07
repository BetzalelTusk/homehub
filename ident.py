"""Device identification for the home hub.

Collects evidence about each device from several independent sources and combines
it into a best guess of what the device is (type), who made it, its model and OS,
with a confidence level and a human-readable list of reasons.

Evidence sources (strongest first):
  * the user's own choice (type_override) - always wins
  * UPnP device descriptions (manufacturer / model, gateway / media renderer roles)
  * mDNS / Bonjour service types and TXT records (printers, Cast, AirPlay, Apple model codes)
  * DHCP requests overheard on the LAN (hostname, vendor class like "android-dhcp-14" / "MSFT 5.0",
    parameter-request list, which also reveals the real MAC of devices behind a MAC-rewriting extender)
  * nmap OS fingerprint + service versions + TLS certificate subjects
  * NetBIOS name (Windows / Samba)
  * hostnames
  * MAC vendor (OUI) and the IP TTL of ping replies (weak hints)
"""
import json, re, socket, struct, subprocess, time
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------- DHCP listener
def parse_dhcp(data):
    """Parse a BOOTP/DHCP client request. Returns None for anything else."""
    if len(data) < 240 or data[0] != 1 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    hlen = data[2]
    mac = ":".join(f"{b:02x}" for b in data[28:28 + min(hlen, 16)])
    ciaddr = socket.inet_ntoa(data[12:16])
    opts, i = {}, 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1; continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        opts[code] = data[i + 2:i + 2 + ln]
        i += 2 + ln
    def txt(b):
        return b.decode("utf-8", "replace").strip("\x00 ") if b else None
    out = {"mac": mac, "msg": opts.get(53, b"\x00")[0] if opts.get(53) else None, "seen": time.time()}
    if 12 in opts: out["hostname"] = txt(opts[12])
    if 60 in opts: out["vendor_class"] = txt(opts[60])
    if 55 in opts: out["prl"] = ",".join(str(b) for b in opts[55])
    if 81 in opts and len(opts[81]) > 3: out["fqdn"] = txt(opts[81][3:])
    if 50 in opts and len(opts[50]) == 4: out["requested_ip"] = socket.inet_ntoa(opts[50])
    if ciaddr != "0.0.0.0": out["ip"] = ciaddr
    return out

def dhcp_listener(callback):
    """Passively listen for DHCP client broadcasts (never replies). Needs CAP_NET_BIND_SERVICE for port 67."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind(("0.0.0.0", 67))
            print("DHCP listener running", flush=True)
            while True:
                data, _ = s.recvfrom(4096)
                d = parse_dhcp(data)
                if d and d["msg"] in (1, 3, 8):   # DISCOVER, REQUEST, INFORM
                    callback(d)
        except Exception as e:
            print("dhcp listener error:", e, flush=True)
            time.sleep(60)

# ---------------------------------------------------------------- small probes
def netbios_name(ip, timeout=1.5):
    """NetBIOS node-status query (what `nmblookup -A` does). Returns (name, workgroup) or None."""
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 15)]) for c in b"*" + b"\x00" * 15)
    pkt = struct.pack(">HHHHHH", 0x1337, 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
    except Exception:
        return None
    finally:
        s.close()
    try:
        n = data[56]
        name = group = None
        for k in range(n):
            e = data[57 + k * 18:57 + (k + 1) * 18]
            nm, suffix, flags = e[:15].decode("ascii", "replace").strip(), e[15], struct.unpack(">H", e[16:18])[0]
            if suffix == 0 and not flags & 0x8000 and not name: name = nm
            if suffix == 0 and flags & 0x8000 and not group: group = nm
        return (name, group) if name else None
    except Exception:
        return None

def ttl_of(ip):
    try:
        out = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"ttl=(\d+)", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None

# ---------------------------------------------------------------- nmap fingerprint
def fingerprint(ip, privileged=True):
    """Port/service scan plus OS detection. OS detection needs raw sockets (CAP_NET_RAW)."""
    cmd = ["nice", "-n", "10", "nmap", "-Pn", "-sV", "--version-light", "--top-ports", "200", "-T4",
           "--max-retries", "2", "--host-timeout", "240s",
           "--script", "http-title,ssl-cert,nbstat", "-oX", "-", ip]
    if privileged:
        cmd[4:4] = ["--privileged", "-O", "--osscan-guess"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=400).stdout
    root = ET.fromstring(out)
    res = {"ports": [], "os": None, "certs": [], "nbname": None}
    for p in root.iter("port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        sv = p.find("service")
        title = cert = None
        for sc in p.iter("script"):
            if sc.get("id") == "http-title":
                title = (sc.get("output") or "").strip()[:120]
            if sc.get("id") == "ssl-cert":
                subj = next((t for t in sc.iter("table") if t.get("key") == "subject"), None)
                if subj is not None:
                    cert = {e.get("key"): (e.text or "")[:120] for e in subj.iter("elem") if e.get("key") in ("commonName", "organizationName")}
                    if cert: res["certs"].append(cert)
        res["ports"].append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                             "service": sv.get("name") if sv is not None else None,
                             "product": " ".join(filter(None, [sv.get(k) for k in ("product", "version", "extrainfo")])) if sv is not None else None,
                             "devicetype": sv.get("devicetype") if sv is not None else None,
                             "ostype": sv.get("ostype") if sv is not None else None,
                             "title": title})
    best = None
    for m in root.iter("osmatch"):
        acc = int(m.get("accuracy", "0"))
        if not best or acc > best["accuracy"]:
            cls = m.find("osclass")
            best = {"name": m.get("name"), "accuracy": acc,
                    "type": cls.get("type") if cls is not None else None,
                    "vendor": cls.get("vendor") if cls is not None else None,
                    "family": cls.get("osfamily") if cls is not None else None}
    res["os"] = best
    for sc in root.iter("script"):
        if sc.get("id") == "nbstat":
            m = re.search(r"NetBIOS name: ([^,\s]+)", sc.get("output") or "")
            if m: res["nbname"] = m.group(1)
    return res

# ---------------------------------------------------------------- knowledge tables
TYPES = ["Phone", "Tablet", "Laptop", "Computer", "Server", "NAS", "TV / streamer", "Smart speaker", "Speaker",
         "Camera", "Printer", "Router", "Wi-Fi extender", "Smart plug", "Air conditioner", "Smart home",
         "Game console", "Wearable", "Unknown"]

APPLE_MODELS = {
    "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro", "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2nd gen)",
    "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12", "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13", "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,6": "iPhone SE (3rd gen)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max", "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus", "iPhone17,5": "iPhone 16e",
    "iPad2,1": "iPad 2", "iPad2,2": "iPad 2", "iPad2,3": "iPad 2", "iPad2,4": "iPad 2",
}
APPLE_PREFIX = [("iPhone", "Phone", "iPhone"), ("iPad", "Tablet", "iPad"), ("iPod", "Tablet", "iPod touch"),
                ("MacBookPro", "Laptop", "MacBook Pro"), ("MacBookAir", "Laptop", "MacBook Air"), ("MacBook", "Laptop", "MacBook"),
                ("iMac", "Computer", "iMac"), ("Macmini", "Computer", "Mac mini"), ("MacPro", "Computer", "Mac Pro"),
                ("Mac", "Computer", "Mac"), ("AppleTV", "TV / streamer", "Apple TV"), ("AudioAccessory", "Smart speaker", "HomePod"),
                ("Watch", "Wearable", "Apple Watch")]

def apple_model(code):
    if not code:
        return None
    for pre, typ, nice in APPLE_PREFIX:
        if code.startswith(pre):
            return typ, APPLE_MODELS.get(code, nice)
    return None

# (regex on hostname-like names, type, points, reason)
NAME_RULES = [
    (r"iphone", "Phone", 8, "name contains “iPhone”"),
    (r"\bipad|ipad", "Tablet", 8, "name contains “iPad”"),
    (r"ipod", "Tablet", 7, "name contains “iPod”"),
    (r"macbook", "Laptop", 8, "name contains “MacBook”"),
    (r"imac|mac-?mini|mac-?pro\b", "Computer", 7, "name looks like a Mac desktop"),
    (r"galaxy-?tab|\btab-?s\d|kindle|fire-?hd", "Tablet", 7, "name looks like a tablet"),
    (r"galaxy|^sm-[a-z]\d|pixel|oneplus|moto|android|redmi|xiaomi|s2\d-?ultra|-s2\d\b|huawei|oppo", "Phone", 7, "name looks like a phone"),
    (r"^desktop-|^win-|-pc$|^pc-", "Computer", 6, "Windows-style computer name"),
    (r"^laptop-|laptop|notebook|thinkpad|chromebook|surface", "Laptop", 7, "name looks like a laptop"),
    (r"raspberrypi|^rpi|raspberry", "Computer", 8, "Raspberry Pi hostname"),
    (r"server|^srv|proxmox|ubuntu|debian|unraid", "Server", 6, "name looks like a server"),
    (r"synology|diskstation|qnap|\bnas\b|-nas|nas-|truenas", "NAS", 9, "name looks like network storage"),
    (r"echo|alexa|amazon-[0-9a-f]{6,}", "Smart speaker", 6, "name looks like an Amazon Echo"),
    (r"fire-?tv|firetv|^aft[a-z]", "TV / streamer", 8, "name looks like a Fire TV"),
    (r"roku|chromecast|appletv|apple-tv|shield|webos|lgwebostv|bravia|vizio|samsung-?tv|\btv\b|-tv$|^tv-|smart-?tv|\btv$", "TV / streamer", 7, "name looks like a TV"),
    (r"xbox|playstation|ps[345]\b|nintendo|switch-?\d", "Game console", 9, "name looks like a game console"),
    (r"arlo|vmc\d|vml\d|ring-?cam|wyze|blink|eufy|camera|-cam\b|ipcam|reolink|hikvision|dahua", "Camera", 8, "name looks like a camera"),
    (r"plug|kasa|hs1\d\d|ep\d\d|smartplug|wemo|outlet|tasmota", "Smart plug", 8, "name looks like a smart plug"),
    (r"lge_ac|aircon|\bhvac|mini-?split|_ac\d?_", "Air conditioner", 9, "name looks like an air conditioner"),
    (r"thermostat|ecobee|nest|hue|bulb|lifx|switch|esp_|esp32|esp8266|espressif|tuya|shelly|sonoff|meross|govee|wiz", "Smart home", 6, "name looks like a smart-home gadget"),
    (r"printer|envy|laserjet|officejet|deskjet|^hp[0-9a-f]{6}|epson|brother|canon|^npi[0-9a-f]", "Printer", 7, "name looks like a printer"),
    (r"extender|repeater|ex\d{4}|re\d{3}|mesh|satellite|deco|eero|orbi|access-?point|\bap\d*\b", "Wi-Fi extender", 9, "name looks like a Wi-Fi extender / access point"),
    (r"router|gateway|cr1000|fios|xfinity|archer|asus-?rt|^rt-|unifi|ubnt|edgerouter|openwrt", "Router", 9, "name looks like a router"),
    (r"watch", "Wearable", 6, "name contains “watch”"),
    (r"sonos|homepod|bose|speaker|soundbar", "Speaker", 7, "name looks like a speaker"),
]

# (regex on MAC vendor, type, points, reason)
VENDOR_RULES = [
    (r"arlo", "Camera", 8, "made by Arlo (cameras)"),
    (r"ring\b|wyze|blink", "Camera", 6, "camera maker"),
    (r"sonos", "Speaker", 9, "made by Sonos"),
    (r"roku|vizio|tcl|hisense", "TV / streamer", 7, "TV / streaming maker"),
    (r"nintendo|sony interactive|valve", "Game console", 8, "game console maker"),
    (r"raspberry", "Computer", 6, "Raspberry Pi board"),
    (r"espressif|tuya|shelly|itead|lumi|signify|philips lighting|lifx|ecobee|nest|ikea|leedarson", "Smart home", 6, "smart-home chip / gadget maker"),
    (r"synology|qnap|western digital", "NAS", 7, "storage maker"),
    (r"amazon", "Smart speaker", 2, "made by Amazon (Echo, Fire TV, Ring, plugs…)"),
    (r"netgear|tp-?link|ubiquiti|eero|linksys|d-link|asustek|zyxel|mikrotik|cisco|aruba|ruckus", "Router", 2, "networking-gear maker"),
    (r"wnc|arcadyan|sagemcom|askey|technicolor|actiontec|humax|commscope|arris", "Router", 4, "makes ISP routers"),
    (r"hp inc|hewlett|epson|brother|canon|lexmark|xerox|kyocera|ricoh", "Printer", 3, "printer maker"),
    (r"intel|azurewave|liteon|hon hai|wistron|quanta|compal|realtek|rivet|cyx|chicony|dell|lenovo|asus|micro-star|gigabyte", "Computer", 3, "makes PC / laptop Wi-Fi hardware"),
    (r"samsung|motorola|oneplus|xiaomi|huawei|oppo|vivo|google", "Phone", 2, "phone maker"),
    (r"lg innotek", "Smart home", 3, "LG Innotek makes Wi-Fi modules for LG appliances"),
    (r"apple", "Phone", 1, "made by Apple"),
]

MDNS_RULES = {
    "_ipp._tcp": ("Printer", 10, "advertises printing (IPP)"), "_ipps._tcp": ("Printer", 10, "advertises printing (IPPS)"),
    "_printer._tcp": ("Printer", 9, "advertises printing (LPD)"), "_pdl-datastream._tcp": ("Printer", 9, "advertises raw printing"),
    "_uscan._tcp": ("Printer", 6, "advertises scanning"),
    "_googlecast._tcp": ("TV / streamer", 7, "advertises Google Cast"),
    "_amzn-wplay._tcp": ("TV / streamer", 9, "advertises Fire TV casting"),
    "_airplay._tcp": ("TV / streamer", 3, "advertises AirPlay"), "_raop._tcp": ("Speaker", 3, "advertises AirPlay audio"),
    "_sonos._tcp": ("Speaker", 10, "advertises Sonos"),
    "_spotify-connect._tcp": ("Speaker", 3, "advertises Spotify Connect"),
    "_hap._tcp": ("Smart home", 7, "advertises HomeKit"), "_hap._udp": ("Smart home", 7, "advertises HomeKit"),
    "_matter._tcp": ("Smart home", 2, "speaks Matter"), "_matterc._udp": ("Smart home", 4, "Matter device waiting for setup"),
    "_hue._tcp": ("Smart home", 9, "Philips Hue bridge"),
    "_smb._tcp": ("Computer", 3, "shares files (SMB)"), "_afpovertcp._tcp": ("Computer", 4, "shares files (Mac AFP)"),
    "_adisk._tcp": ("NAS", 5, "Time Machine disk"),
    "_ssh._tcp": ("Server", 3, "allows remote login (SSH)"), "_sftp-ssh._tcp": ("Server", 3, "allows file transfer (SFTP)"),
    "_workstation._tcp": ("Computer", 4, "announces itself as a workstation"),
    "_dosvc._tcp": ("Computer", 7, "Windows Delivery Optimization (Windows PC)"),
    "_companion-link._tcp": ("Phone", 3, "Apple companion link"), "_apple-mobdev2._tcp": ("Phone", 4, "Apple device sync (iPhone/iPad)"),
    "_apple-mobdev._tcp": ("Phone", 4, "Apple device sync (iPhone/iPad)"), "_remotepairing._tcp": ("Phone", 4, "Apple remote pairing (iPhone/iPad)"),
    "_rfb._tcp": ("Computer", 4, "screen sharing (VNC)"),
    "_occam._udp": ("Smart speaker", 3, "Amazon device service"),
}

PORT_RULES = {
    9100: ("Printer", 6, "raw printing port 9100 open"), 631: ("Printer", 5, "IPP printing port open"), 515: ("Printer", 5, "LPD printing port open"),
    62078: ("Phone", 7, "iPhone/iPad sync port 62078 open"),
    3389: ("Computer", 6, "Windows Remote Desktop open"), 445: ("Computer", 3, "Windows file sharing open"),
    8008: ("TV / streamer", 4, "Google Cast port open"), 8009: ("TV / streamer", 5, "Google Cast port open"),
    554: ("Camera", 4, "video-stream (RTSP) port open"), 53: ("Router", 4, "runs DNS (typical for routers)"),
    5000: ("NAS", 2, "port 5000 open (NAS / UPnP)"), 5001: ("NAS", 3, "port 5001 open (NAS)"), 32400: ("Server", 5, "Plex media server"),
    22: ("Server", 2, "SSH open"), 548: ("Computer", 3, "Mac file sharing open"),
}

NMAP_TYPES = {"phone": "Phone", "general purpose": "Computer", "router": "Router", "broadband router": "Router",
              "wap": "Wi-Fi extender", "printer": "Printer", "media device": "TV / streamer", "webcam": "Camera",
              "storage-misc": "NAS", "game console": "Game console", "switch": "Router", "firewall": "Router",
              "power-device": "Smart plug", "specialized": None, "terminal": None, "PDA": "Phone"}

# ---------------------------------------------------------------- the classifier
def identify(d, info, ports, vendor_of=None):
    """d: device row (dict); info: discovery info; ports: list or None. Returns the identity dict."""
    score, why = {}, []
    def add(t, pts, reason, src):
        if not t or pts <= 0:
            return
        score[t] = score.get(t, 0) + pts
        why.append({"type": t, "points": pts, "reason": reason, "source": src})

    up, md, dh = info.get("upnp") or {}, info.get("mdns") or {}, info.get("dhcp") or {}
    txt, svcs = md.get("txt") or {}, (md.get("services") or {})
    os_ = info.get("os") or {}
    maker = model = osname = None

    # --- UPnP
    dt = (up.get("deviceType") or "").lower()
    if "internetgatewaydevice" in dt: add("Router", 12, "describes itself as an internet gateway (UPnP)", "UPnP")
    if "wlanaccesspoint" in dt or "wfadevice" in dt: add("Wi-Fi extender", 8, "describes itself as a Wi-Fi access point (UPnP)", "UPnP")
    if "mediarenderer" in dt: add("TV / streamer", 4, "UPnP media renderer (plays video/music)", "UPnP")
    if "printer" in dt: add("Printer", 9, "describes itself as a printer (UPnP)", "UPnP")
    if up.get("manufacturer"): maker = up["manufacturer"]
    if up.get("modelName"): model = " ".join(dict.fromkeys(filter(None, [up.get("modelName"), up.get("modelNumber")])))

    # --- mDNS services & TXT
    for s in svcs:
        r = MDNS_RULES.get(s)
        if r: add(r[0], r[1], r[2], "Bonjour")
    if any("spotify desktop" in (v.get("name") or "").lower() for v in svcs.values()):
        add("Computer", 7, "runs the Spotify desktop app", "Bonjour")
    am = apple_model(txt.get("model") or txt.get("rpmd") or txt.get("am"))
    if am:
        add(am[0], 12, f"Apple model code {txt.get('model') or txt.get('rpmd') or txt.get('am')} = {am[1]}", "Bonjour")
        maker, model, osname = "Apple", am[1], {"Phone": "iOS", "Tablet": "iPadOS", "Laptop": "macOS", "Computer": "macOS",
                                                "TV / streamer": "tvOS", "Smart speaker": "HomePod software", "Wearable": "watchOS"}.get(am[0])
    if txt.get("md") and "_googlecast._tcp" in svcs:
        model = model or txt["md"]
        if re.search(r"google home|nest (mini|audio|hub)|home mini", txt["md"], re.I): add("Smart speaker", 8, f"Cast model “{txt['md']}”", "Bonjour")
        elif re.search(r"chromecast|tv", txt["md"], re.I): add("TV / streamer", 6, f"Cast model “{txt['md']}”", "Bonjour")
    if txt.get("usb_mfg"): maker = maker or txt["usb_mfg"]
    if txt.get("ty") and not model: model = txt["ty"]

    # --- DHCP
    vc = (dh.get("vendor_class") or "")
    if vc.lower().startswith("android-dhcp"):
        v = vc.split("-")[-1]; osname = osname or (f"Android {v}" if v.isdigit() else "Android")
        add("Phone", 6, f"DHCP says “{vc}” (Android)", "DHCP")
    elif vc.startswith("MSFT"):
        osname = osname or "Windows"; add("Computer", 7, f"DHCP says “{vc}” (Windows)", "DHCP")
    elif vc.lower().startswith("dhcpcd"):
        osname = osname or "Linux"; add("Computer", 2, f"DHCP client “{vc.split(':')[0]}” (Linux)", "DHCP")
    elif vc.lower().startswith("udhcp"):
        osname = osname or "Embedded Linux"; add("Smart home", 2, f"DHCP client “{vc}” (embedded Linux, typical for gadgets)", "DHCP")
    prl = dh.get("prl") or ""
    if not vc and prl.startswith("1,121,3,6,15,") and "252" in prl.split(","):
        osname = osname or "iOS / macOS"; add("Phone", 2, "DHCP request pattern matches Apple iOS/macOS", "DHCP")
    real_mac = dh.get("mac") if dh.get("mac") and dh.get("mac") != d["mac"].split("@")[0] else None

    # --- nmap
    if os_.get("name") and os_.get("accuracy", 0) >= 90:
        t = NMAP_TYPES.get(os_.get("type") or "")
        add(t, 5 if os_["accuracy"] >= 96 else 3, f"OS fingerprint: {os_['name']} ({os_['accuracy']}% match, {os_.get('type')})", "OS scan")
        # only trust the OS *name* for mainstream families; guesses for gadgets are often a random similar device
        fam = os_.get("family") or ""
        if fam in ("Windows", "Linux", "Mac OS X", "macOS", "iOS", "Android", "FreeBSD", "OpenBSD"):
            osname = osname or (os_["name"] if os_["accuracy"] >= 96 else fam)
    for p in ports or []:
        r = PORT_RULES.get(p.get("port"))
        if r: add(r[0], r[1], r[2], "Port scan")
        if p.get("devicetype"):
            t = NMAP_TYPES.get(p["devicetype"].lower())
            add(t, 4, f"service on port {p['port']} identifies as a {p['devicetype']}", "Port scan")
        if p.get("ostype") and not osname: osname = p["ostype"]
    for cert in info.get("certs") or []:
        if cert.get("organizationName") and not maker: maker = cert["organizationName"]

    # --- names
    names = [n for n in [d.get("name"), d.get("hostname"), dh.get("hostname"), dh.get("fqdn"), md.get("hostname"), info.get("nbname"),
                         up.get("friendlyName"), txt.get("n"), txt.get("fn"), up.get("modelName")] if n]
    seen = set()
    for n in names:
        low = n.lower()
        for rx, t, pts, reason in NAME_RULES:
            if (t, reason) not in seen and re.search(rx, low):
                seen.add((t, reason)); add(t, pts, f"{reason} ({n})", "Name")

    # --- MAC vendor (skip randomized and extender-rewritten addresses, but use the real MAC from DHCP if we have one)
    ven = d.get("vendor")
    if not ven and real_mac and vendor_of:
        ven = vendor_of(real_mac)
    if ven:
        for rx, t, pts, reason in VENDOR_RULES:
            if re.search(rx, ven, re.I):
                add(t, pts, f"{reason} — {ven}", "MAC vendor"); break
        maker = maker or ven

    # --- TTL
    ttl = info.get("ttl")
    if ttl:
        if 64 < ttl <= 128:
            osname = osname or "Windows"; add("Computer", 3, "network replies look like Windows (TTL 128)", "Ping")
        elif ttl > 128:
            add("Router", 1, "network replies look like network gear / embedded OS (TTL 255)", "Ping")

    # --- decide
    override = d.get("type_override")
    ranked = sorted(score.items(), key=lambda kv: -kv[1])
    if override:
        typ, conf = override, "set"
    elif not ranked or ranked[0][1] < 3:
        typ, conf = "Unknown", "low"
    else:
        typ, top = ranked[0]
        margin = top - (ranked[1][1] if len(ranked) > 1 else 0)
        conf = "high" if top >= 9 and margin >= 4 else "medium" if top >= 5 and margin >= 2 else "low"
    return {"type": typ, "confidence": conf, "maker": clean_maker(maker), "model": model, "os": osname,
            "evidence": sorted(why, key=lambda w: -w["points"]),
            "alternatives": [t for t, _ in ranked[1:3] if t != typ],
            "real_mac": real_mac}

def clean_maker(m):
    if not m:
        return None
    m = re.sub(r",? (Inc|Ltd|LLC|Co|Corp|Corporation|GmbH|S\.A|AG)\.?$", "", m.strip(), flags=re.I)
    return re.sub(r" (Technologies|Technology)$", "", m)

def auto_name(d, info):
    """Best automatic display name when the user hasn't named the device."""
    dh, md, up = info.get("dhcp") or {}, info.get("mdns") or {}, info.get("upnp") or {}
    for n in [d.get("dname"), (d.get("hostname") or "").replace(".local", ""), dh.get("hostname"), info.get("nbname"),
              (md.get("hostname") or "").replace(".local", "")]:
        if n and not re.fullmatch(r"[0-9A-Fa-f]{12}|[0-9-]+|localhost|none(-\d+)?|linux|android-[0-9a-f]{12,}", n):
            return n
    return None

# Home Hub

A home network dashboard for a Raspberry Pi: device inventory and identification, presence ("who's home"),
internet monitoring, alerts (ntfy / Telegram) and a wall display for an old iPad. Python standard library only.

- `hub.py` – server, scanners, API (port 8080)
- `ident.py` – device identification (DHCP, NetBIOS, nmap fingerprinting)
- `index.html` – main dashboard
- `display.html` – wall display (ES5, for iOS 9 Safari)
- `manuf` – Wireshark's MAC vendor list
- `homehub.service` – systemd unit (copy to `/etc/systemd/system/`)

Not in git: `hub.db` (history) and `config.json` (password hash, alert tokens).
Set a password with `python3 hub.py --set-password`.

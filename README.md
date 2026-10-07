# Home Hub

A home network dashboard for a Raspberry Pi. It keeps an inventory of every device on your network and works out
what each one is, shows who's home, watches your internet connection, captures packets, and drives a wall display
on an old iPad. It also has a School tab: a Google Calendar–style calendar fed by Brightspace, where you can add
your own events and, optionally, sync two ways with Google Calendar.

It's one Python file using only the standard library. There is nothing to `pip install`.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Run it as a service](#run-it-as-a-service)
- [HTTPS with Tailscale](#https-with-tailscale)
- [School calendar](#school-calendar)
- [Google Calendar sync](#google-calendar-sync)
- [Data and security](#data-and-security)
- [Files](#files)
- [Troubleshooting](#troubleshooting)

## Features

| Tab | What it does |
|---|---|
| **Overview** | Analytics, who's home, recently active devices, recent events. |
| **Devices** | Every device seen on the LAN, identified by DHCP fingerprint, mDNS/SSDP, NetBIOS and nmap OS detection, with the vendor from Wireshark's MAC list. Port scans, ping, Wake-on-LAN, notes, owners and locations. |
| **Internet** | Pings 1.1.1.1 and 8.8.8.8 every 10 seconds, records outages, and runs Cloudflare speed tests. |
| **Packets** | Wireshark-style capture with tcpdump, saved as .pcap, with an export you can paste into an LLM. |
| **Activity** | Devices coming and going, new devices, outages. |
| **School** | Month, Week (hour grid) and Schedule views. Brightspace deadlines, your own events, and optionally all your Google calendars. |
| **Settings** | Alerts through [ntfy](https://ntfy.sh) or Telegram, the Brightspace feed, the Google Calendar connection, and the password. |
| **Wall display** | `/display`, written in ES5 so it runs on iOS 9 Safari. |

## Requirements

- A Raspberry Pi or any Debian-like Linux box on your home network. Developed on a Pi 4 with Raspberry Pi OS
  (bookworm, 64-bit) and Python 3.11.
- `nmap`, `avahi-utils` and `tcpdump`, plus the usual `ip` and `ping` tools.
- Optional: [Tailscale](https://tailscale.com), for HTTPS and access away from home. You need it for Google
  Calendar sync.

## Install

```bash
sudo apt install -y nmap avahi-utils tcpdump git
git clone https://github.com/BetzalelTusk/homehub.git ~/homehub
cd ~/homehub
```

Open `hub.py` and check the settings at the top. `SUBNET` must match your network (the default is
`192.168.1.0/24`), and `PORT` is the web port (8080).

Set a password of at least 8 characters:

```bash
python3 hub.py --set-password
```

If you skip this, the first start generates a password and prints it to the log.

To try it out, run `python3 hub.py` and open `http://<the-pi's-ip>:8080`. Run by hand, it can't listen for DHCP
or use some nmap features. The service below has the permissions for those.

## Run it as a service

`homehub.service` is a systemd unit. Edit `User`, `WorkingDirectory` and `ExecStart` to match your username and
where you cloned the repo, then:

```bash
sudo cp homehub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now homehub
journalctl -u homehub -f        # watch the log
```

The hub runs as your normal user, not root. The unit grants only `CAP_NET_RAW`, `CAP_NET_ADMIN` and
`CAP_NET_BIND_SERVICE`, for raw pings, nmap and hearing DHCP on UDP 67. `UMask=0077` keeps every file it writes
private to your user.

## HTTPS with Tailscale

Recommended: it encrypts the connection, lets you reach the hub away from home, and Google sign-in requires it.

1. In the Tailscale admin console, open **DNS** and turn on **HTTPS Certificates**.
2. On the Pi, run:
   ```bash
   sudo tailscale serve --bg --https=443 http://127.0.0.1:8080
   ```
3. Open `https://<machine-name>.<your-tailnet>.ts.net`. The first visit takes up to half a minute while the
   certificate is issued.

This address works only for devices on your tailnet. **Don't** use `tailscale funnel`, which puts it on the public
internet. The plain `http://<pi-ip>:8080` address keeps working on your home network, for the wall display.

## School calendar

The School tab combines up to three sources.

### 1. Brightspace calendar feed (automatic)

1. In Brightspace, open **Calendar → ⋯ → Subscribe**, choose **All Calendars and Tasks**, and copy the link.
2. In the hub, open **Settings → School calendar**, paste the link and save.

The hub fetches it every 30 minutes, so new quizzes and due dates show up without you doing anything. The link
contains a token that works without a login, so treat it like a password. The hub stores it in `config.json` and
never shows it again.

### 2. Done ticks and announcements (optional)

The feed has no grades, so it can't tell what you've finished. For that, use `tools/thisweek.js`:

1. Sign in to Brightspace in your browser and open any page.
2. Press F12, open **Console**, paste the whole file and press Enter, then run `await thisweek()`.
3. It downloads `schedule.json`. In the School tab, click the import icon and pick that file.

The script only reads, using your existing browser session, and stores no credentials. Any item that has a score
in Brightspace gets ticked as done. Re-run it whenever you want the ticks refreshed.

### 3. Your own events

Click **Create** (or press `c`), click a day in Month view, or click or drag an empty slot in the Week grid. Click
an event to see details, edit it or delete it.

| Key | Action |
|---|---|
| `c` | Create an event |
| `t` | Jump to today |
| `j` / `k` | Next / previous |
| `m` / `w` / `a` | Month / Week / Schedule view |
| `Esc` | Close a popup |

Without Google these events stay on the hub. Connect Google and they upload automatically.

## Google Calendar sync

Two-way and optional. The hub creates its own **Home Hub** calendar in your Google account and writes **only**
there. Your other calendars show on the School tab read-only. If you subscribed to the Brightspace feed in Google
too, the hub skips that calendar so nothing appears twice.

Set up HTTPS with Tailscale first, then:

1. In the [Google Cloud console](https://console.cloud.google.com), create a project, or use an existing one.
2. **APIs & Services → Library**: enable **Google Calendar API**.
3. **Google Auth Platform → Branding / Audience**: user type **External**, add your email, then **Publish app** to
   **In production**. If you leave it in Testing, Google expires the sign-in every 7 days.
4. **Clients → Create client**, type **Web application**, with this authorized redirect URI:
   `https://<machine-name>.<your-tailnet>.ts.net/oauth/google/callback`
   (Settings in the hub shows the exact URI). Copy the client secret straight away; Google only shows it once.
5. In the hub, open **Settings → Google Calendar**, paste the client ID and secret, click **Save client**, then
   **Connect Google**. Google warns that the app is unverified, which is normal for your own app. Click
   **Advanced → Go to …** and allow both calendar permissions.

The hub asks only for `calendar.readonly` (read your calendars) and `calendar.app.created` (manage calendars this
app created). It can't change or delete anything in your other calendars.

How fast changes appear:

| Change | Shows up |
|---|---|
| Made on the hub | In Google within seconds |
| Made in Google's Home Hub calendar | On the hub within 5 minutes |
| Made in your other Google calendars | On the hub within 10 minutes |

**Settings → Google Calendar → Sync now** forces an immediate refresh.

## Data and security

Nothing private is in git. These files are created next to `hub.py`, readable only by your user, and listed in
`.gitignore`:

| File | Holds |
|---|---|
| `config.json` | Password hash and session secret, alert tokens, the Brightspace feed link, the Google client secret and sign-in |
| `hub.db` | Device history, events, pings, speed tests, your calendar events |
| `school.json` | The last `schedule.json` import |
| `school_feed.json` | The last good copy of the Brightspace feed |
| `captures/` | Saved packet captures |

Back them up somewhere private. Never commit them.

- **Login:** the password is stored as PBKDF2-SHA256 with 200,000 rounds. Sessions last 30 days in an `HttpOnly`,
  `SameSite=Strict` cookie, plus `Secure` on the HTTPS address. Five wrong passwords lock that client out for a
  minute. `python3 hub.py --set-password` changes the password and signs everyone out.
- **Every page and API needs the password**, except the login page and the Google sign-in return, which only
  accepts a single-use code from a sign-in you started.
- **Don't open port 8080 on your router.** Use Tailscale to reach the hub from outside.
- Responses send `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.

## Files

| File | Purpose |
|---|---|
| `hub.py` | Server, scanners, API, Brightspace feed and Google Calendar sync (port 8080) |
| `ident.py` | Device identification: DHCP, NetBIOS, nmap fingerprints |
| `index.html` | The dashboard |
| `display.html` | Wall display (ES5, for iOS 9 Safari) |
| `manuf` | Wireshark's MAC vendor list |
| `homehub.service` | systemd unit |
| `tools/thisweek.js` | Browser-console exporter for Brightspace done ticks and announcements |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `redirect_uri_mismatch` when connecting Google | The redirect URI must match Settings exactly. New OAuth clients can take a few minutes to start working. |
| "Google sign-in expired or was revoked" | Publish the consent screen to **In production**, then click **Connect Google** in Settings. |
| School tab says **Brightspace sync failed** | The feed link was probably reset. Copy a new one from Brightspace into Settings. |
| `dhcp listener error: Permission denied` | You're running `hub.py` by hand. Run it as the service, which has the right permissions. |
| Settings says to turn on HTTPS | Enable HTTPS Certificates in Tailscale and run the `tailscale serve` command above. |

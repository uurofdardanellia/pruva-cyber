#!/usr/bin/env python3
"""
Pruva Cyber - on-board network monitor
=====================================

Watches the ship's network traffic, raises alerts when something looks wrong,
and saves a recording every 15 minutes that you can load into the Pruva Cyber
app (Network monitor page) for a full check.

Before you start
  * Get permission from the Master and company IT.
  * Use a computer (Linux or macOS) connected to the switch "mirror" / "SPAN"
    port, so it can see the traffic of the other devices.
  * tcpdump and Python 3 must be installed (most Linux computers have both).

Start
    sudo python3 pruva_monitor.py --iface eth0

Optional
    --known 10.0.10.1=00:11:22:33:44:55   gateway MAC from your inventory (repeatable)
    --mail-to eto@ship.com --smtp smtp.company.com:587 --mail-from monitor@ship.com
        (password from the PRUVA_SMTP_PASS environment variable)
    --rotate 15     minutes per recording file
    --learn 10      minutes to learn what is normal before rate alerts start

Stop with Ctrl+C. Alerts are printed, beep, and are written to alerts.log.
"""
import argparse, collections, csv, datetime as dt, ipaddress, os, re, smtplib, subprocess, sys, time
from email.message import EmailMessage

ETH = re.compile(r'^(?P<t>\d+\.\d+)\s+(?:(?P<smac>[0-9a-f:]{17}) > (?P<dmac>[0-9a-f:]{17}|Broadcast|ff:ff:ff:ff:ff:ff)[^:]*?length \d+:\s+)?(?P<rest>.*)$')
IPL = re.compile(r'^(?:IP6?\s+)?(?:\(.*?\)\s+)?(?P<src>[0-9A-Fa-f.:]+) > (?P<dst>[0-9A-Fa-f.:]+): (?P<info>.*)$')
ARP_REPLY = re.compile(r'(?:ARP, )?Reply (?P<ip>[\d.]+) is-at (?P<mac>[0-9a-f:]{17})')
REMOTE_PORTS = {3389: "RDP", 5900: "VNC", 5800: "VNC", 5938: "TeamViewer", 7070: "AnyDesk", 22: "SSH", 23: "Telnet"}
OT_PORTS = {502: "Modbus", 102: "S7", 47808: "BACnet", 20000: "DNP3", 44818: "EtherNet/IP"}

def split_hp(s):
    s = s.rstrip(':,')
    parts = s.split('.')
    if len(parts) == 5 and all(p.isdigit() for p in parts[:4]):
        return '.'.join(parts[:4]), (int(parts[4]) if parts[4].isdigit() else None)
    return s, None

def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or ip.startswith("100.")
    except ValueError:
        return True

def is_external(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_link_local or a.is_multicast or a.is_loopback or ip.endswith(".255") or ip.startswith("100."))
    except ValueError:
        return False

def parse(line):
    m = ETH.match(line)
    if not m:
        return None
    t = float(m.group('t')); rest = m.group('rest'); smac = m.group('smac') or ""
    p = {"time": t, "src": "", "dst": "", "proto": "", "sport": "", "dport": "", "flags": "", "length": 0, "smac": smac, "info": ""}
    lm = re.findall(r'length (\d+)', line)
    p["length"] = int(lm[-1]) if lm else 0
    if rest.startswith(("ARP", "Request who-has", "Reply ")):
        p["proto"] = "ARP"; p["info"] = rest[:120]
        r = ARP_REPLY.search(rest)
        if r:
            p["src"] = r.group('ip'); p["dst"] = "Broadcast"
        else:
            w = re.search(r'who-has ([\d.]+) tell ([\d.]+)', rest)
            if w:
                p["src"] = w.group(2); p["dst"] = "Broadcast"
        return p
    i = IPL.match(rest)
    if not i:
        return None
    src, sport = split_hp(i.group('src')); dst, dport = split_hp(i.group('dst')); info = i.group('info')
    p.update(src=src, dst=dst, sport=sport or "", dport=dport or "", info=info[:160])
    if info.startswith("Flags"):
        p["proto"] = "TCP"; f = re.search(r'Flags \[([^\]]+)\]', info); p["flags"] = f.group(1) if f else ""
    elif info.startswith("ICMP"):
        p["proto"] = "ICMP"
    elif dport == 53 or sport == 53:
        p["proto"] = "DNS"
    else:
        p["proto"] = "UDP" if ("UDP" in info or dport) else "IP"
    return p

class Monitor:
    def __init__(a, args):
        a.args = args; a.known = dict(k.split("=", 1) for k in (args.known or []))
        a.arp = {}; a.window = []; a.learn_until = time.time() + args.learn * 60; a.learned = []; a.base = None
        a.last_alert = {}; a.out = None; a.rows = 0; a.file_start = 0
        os.makedirs(args.out, exist_ok=True)
        a.reset()

    def reset(a):
        a.w_start = time.time(); a.total = 0; a.by_src = collections.Counter(); a.syn = collections.Counter(); a.synack = collections.Counter()
        a.echo = collections.Counter(); a.bcast = 0; a.dns_unreach = 0; a.smb = collections.defaultdict(set); a.ports = collections.defaultdict(set)

    def alert(a, key, sev, text, todo):
        now = time.time()
        if now - a.last_alert.get(key, 0) < 600:
            return
        a.last_alert[key] = now
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        msg = f"[{stamp}] {sev}: {text}\n    What to do: {todo}"
        colour = "\033[91m" if sev == "ALERT" else "\033[93m"
        print(f"\a{colour}{msg}\033[0m", flush=True)
        with open(os.path.join(a.args.out, "alerts.log"), "a", encoding="utf-8") as f:
            f.write(msg + "\n")
        if a.args.mail_to and a.args.smtp:
            try:
                host, _, port = a.args.smtp.partition(":"); port = int(port or 587)
                em = EmailMessage(); em["Subject"] = f"Pruva Cyber {sev}: {text[:70]}"; em["From"] = a.args.mail_from or a.args.mail_to; em["To"] = a.args.mail_to
                em.set_content(msg)
                with smtplib.SMTP(host, port, timeout=20) as s:
                    if port == 587:
                        s.starttls()
                    if os.environ.get("PRUVA_SMTP_PASS"):
                        s.login(a.args.mail_from or a.args.mail_to, os.environ["PRUVA_SMTP_PASS"])
                    s.send_message(em)
            except Exception as e:
                print(f"    (could not send e-mail: {e})")

    def record(a, p):
        now = time.time()
        if a.out is None or now - a.file_start > a.args.rotate * 60:
            if a.out:
                a.out.close()
                print(f"Saved recording: {a.path}  -> load it in the app (Network monitor)")
            a.path = os.path.join(a.args.out, dt.datetime.now().strftime("pruva_%Y%m%d_%H%M.csv"))
            a.out = open(a.path, "w", newline="", encoding="utf-8"); a.csv = csv.DictWriter(a.out, fieldnames=list(p.keys())); a.csv.writeheader()
            a.rows = 0; a.file_start = now
        if a.rows < 200000:
            a.csv.writerow(p); a.rows += 1

    def feed(a, p):
        a.record(p); a.total += 1; a.by_src[p["src"]] += 1
        dst, dport, src = p["dst"], p["dport"], p["src"]
        if p["proto"] == "ARP":
            a.bcast += 1
            r = ARP_REPLY.search(p["info"])
            if r:
                ip, mac = r.group('ip'), r.group('mac')
                good = a.known.get(ip) or a.arp.get(ip)
                if good and good.lower() != mac.lower():
                    a.alert("arp" + ip, "ALERT", f"{ip} is now answering from a different device ({mac}, before {good}). Possible man-in-the-middle.",
                            "Look for an unknown device in the network cabinets. Open the emergency guide: 'Someone may be secretly reading our traffic'.")
                a.arp.setdefault(ip, mac)
            return
        if dst.endswith(".255") or dst == "255.255.255.255":
            a.bcast += 1
        if p["proto"] == "TCP":
            f = p["flags"]
            if f == "S":
                a.syn[dst] += 1
                if dport in (445, 139) and is_private(src) and is_private(dst):
                    a.smb[src].add(dst)
            elif f.startswith("S."):
                a.synack[src] += 1
            if dport:
                a.ports[src].add((dst, dport))
            if dport in REMOTE_PORTS and is_external(src) and is_private(dst):
                a.alert("rem" + src + dst, "ALERT", f"Remote login attempt ({REMOTE_PORTS[dport]}) from the internet {src} to {dst}.",
                        "Check the remote access box is switched off and the firewall blocks it. Tell company IT.")
            if dport in OT_PORTS and is_external(src):
                a.alert("ot" + src, "ALERT", f"Ship control protocol {OT_PORTS[dport]} reached from the internet ({src} -> {dst}).",
                        "Disconnect the engine/bridge network from the internet link. Tell company IT immediately.")
        if p["proto"] == "ICMP":
            if "echo request" in p["info"]:
                a.echo[dst] += 1
            if "udp port 53 unreachable" in p["info"]:
                a.dns_unreach += 1

    def check(a):
        secs = max(1.0, time.time() - a.w_start); pps = a.total / secs
        if time.time() < a.learn_until:
            a.learned.append(pps)
        elif a.base is None and a.learned:
            s = sorted(a.learned); a.base = s[int(len(s) * .95) - 1 if len(s) > 1 else 0]
            print(f"Learned normal traffic: about {a.base:.0f} packets per second at busy times. Rate alerts are now active.")
        if a.base and pps > max(200, a.base * 5):
            top, n = a.by_src.most_common(1)[0]
            a.alert("rate", "ALERT", f"Traffic is {pps:.0f} packets/second, {pps / a.base:.0f}x more than normal. Biggest sender: {top} ({n * 100 // a.total}%).",
                    "Open the emergency guide: 'The whole network is flooded'. Check for a looped cable first.")
        for d, n in a.syn.items():
            if n / secs > 20 and a.synack[d] < n * .2:
                a.alert("syn" + d, "ALERT", f"SYN flood: {n} connection attempts to {d} in {secs:.0f} s without answers.",
                        "Open the emergency guide: DoS / Flooding. Ask IT support to block the source.")
        for d, n in a.echo.items():
            if n / secs > 50:
                a.alert("icmp" + d, "ALERT", f"Ping flood: {n} pings to {d} in {secs:.0f} s.", "Ask IT support to rate-limit ICMP and find the source.")
        if a.total and a.bcast / a.total > .4 and a.bcast / secs > 100:
            a.alert("bcast", "ALERT", f"Broadcast storm: {a.bcast * 100 // a.total}% of traffic is broadcast.",
                    "Look for a cable with both ends in the same switch (a loop) and unplug it.")
        if a.dns_unreach >= 5:
            a.alert("dns", "WARNING", f"The DNS server did not answer {a.dns_unreach} times (ICMP 'udp port 53 unreachable').",
                    "Check the DNS server / router is running. Many failures at once can mean an attack or a broken device.")
        for s, hosts in a.smb.items():
            if len(hosts) >= 6:
                a.alert("smb" + s, "ALERT", f"{s} is trying file sharing (SMB) on {len(hosts)} computers - this is how ransomware spreads.",
                        f"Take {s} off the network now (pull the cable). Open the emergency guide: Ransomware.")
        for s, pairs in a.ports.items():
            if len(pairs) > 100 and is_private(s):
                a.alert("scan" + s, "ALERT", f"{s} is scanning the network ({len(pairs)} different targets).",
                        f"Find device {s} and take it off the network. Tell company IT.")
        a.reset()

    def run(a):
        cmd = ["tcpdump", "-l", "-n", "-e", "-tt", "-i", a.args.iface]
        print("Starting:", " ".join(cmd)); print(f"Learning normal traffic for {a.args.learn} minutes. Recordings go to: {os.path.abspath(a.args.out)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        try:
            for line in proc.stdout:
                p = parse(line.strip())
                if p:
                    a.feed(p)
                if time.time() - a.w_start >= 60:
                    a.check()
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()
            if a.out:
                a.out.close(); print(f"Saved recording: {a.path}")
            print("Monitor stopped.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Pruva Cyber on-board network monitor")
    ap.add_argument("--iface", required=True, help="network interface connected to the mirror port, e.g. eth0")
    ap.add_argument("--out", default="pruva_recordings"); ap.add_argument("--rotate", type=int, default=15); ap.add_argument("--learn", type=int, default=10)
    ap.add_argument("--known", action="append", help="IP=MAC of an important device, e.g. the gateway")
    ap.add_argument("--mail-to"); ap.add_argument("--mail-from"); ap.add_argument("--smtp", help="host:port")
    args = ap.parse_args()
    if os.name != "nt" and os.geteuid() != 0:
        print("Please start with sudo (needed to read network traffic)."); sys.exit(1)
    Monitor(args).run()

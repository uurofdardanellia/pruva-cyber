# Pruva Cyber

A simple, step-by-step cyber emergency guide for seafarers.

**Open the app:** https://YOUR-USERNAME.github.io/pruva-cyber/

## What it does

- **Emergency guide** – choose what you see (ransom message, GPS position wrong, network very slow…) and follow numbered steps in plain language. Covers ransomware, GPS spoofing/jamming, DoS, DDoS, MITM, IP spoofing and flooding.
- **Incident reports** – every step you tick is written into the report with the time (UTC).
- **Ship checklist** – the yes/no questions inspectors ask about cyber security.
- **Ships & equipment** – the list of computers and computer-controlled systems on board.
- **Network monitor** – load a traffic recording (Wireshark CSV, tcpdump text, firewall CSV log) and the app finds floods, DoS/DDoS, ARP spoofing (man-in-the-middle), fake addresses, ransomware spreading and networks talking that should not, and raises alerts.
- **Routine checks**, **network diagram** with firewall and proxy recommendations, **software update history**, **photos** on checklists.
- **PDF** – print the guide for the bridge or engine control room.

## Based on

IACS UR E26 · IMO MSC-FAL.1/Circ.3/Rev.4 · IMO MSC.428(98) · EMSA MARSEC Doc. 9209 · EU NIS2 Directive (2022/2555) · NIST CSF 2.0 · CISA Incident Response Playbook

## Automatic monitoring on board (`pruva_monitor.py`)

The web page cannot listen to the ship's network by itself. For non-stop monitoring, run `pruva_monitor.py` on a Linux or Mac computer connected to the switch mirror (SPAN) port, with permission from the Master and company IT:

```
sudo python3 pruva_monitor.py --iface eth0
```

It learns normal traffic for 10 minutes, then prints and beeps alerts (optionally sends e-mail), writes `alerts.log`, and saves a recording every 15 minutes in `pruva_recordings/` that you can load in the app's Network monitor.

## Example ship

On first visit the app shows an example ship (**EXAMPLE – MV Marmara Star**) with a filled equipment list and a few checklist answers, so you can try every page. Delete it under *Ships & equipment* when you add your own ship.

## Important

- In this public version, data is saved **only in the browser** of the person using it. Nothing is sent to a server and records are not shared between people.
- The commands shown under "Information for IT support" are templates. Check them against the equipment maker's and systems integrator's instructions before using them on ship networks.
- This app is a guide. It does not replace the Ship Security Plan, the Safety Management System, or instructions from the flag State and class society.

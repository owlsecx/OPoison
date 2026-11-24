#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                                                                          ║
# ║   ██████╗ ██████╗  ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗              ║
# ║  ██╔═══██╗██╔══██╗██╔═══██╗██║██╔════╝██╔═══██╗████╗  ██║              ║
# ║  ██║   ██║██████╔╝██║   ██║██║███████╗██║   ██║██╔██╗ ██║              ║
# ║  ██║   ██║██╔═══╝ ██║   ██║██║╚════██║██║   ██║██║╚██╗██║              ║
# ║  ╚██████╔╝██║     ╚██████╔╝██║███████║╚██████╔╝██║ ╚████║              ║
# ║   ╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝              ║
# ║                                                                          ║
# ║   ARP Spoof & MITM Detection Engine                                      ║
# ║   Monitor | Detect | Scan | Alert | Forensics | Report                  ║
# ║                                                                          ║
# ║   Author   : khaled.s.haddad                                             ║
# ║   Website  : owlsec.org                                                  ║
# ║   Version  : 1.0                                                         ║
# ║   License  : MIT                                                         ║
# ║   Platform : Debian Linux / OwlOS                                        ║
# ║                                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import os, sys, json, time, socket, struct, threading, csv, gzip, hashlib
import re, signal, ipaddress, subprocess, shutil, textwrap, argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Optional, Dict, List, Tuple

# ─── PYTHON VERSION CHECK ─────────────────────────────────────────────────
if sys.version_info < (3, 8):
    sys.exit("[✘] OPoison requires Python 3.8 or higher.")

# ─── SCAPY ────────────────────────────────────────────────────────────────
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    from scapy.all import (
        get_if_list, get_if_hwaddr, sniff,
        ARP, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw,
        srp, sr1, conf, get_if_addr
    )
    conf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

# ─── OPTIONAL: NOTIFY / SOUND ─────────────────────────────────────────────
try:
    import subprocess as _sp
    def _beep():
        _sp.run(["paplay", "/usr/share/sounds/freedesktop/stereo/bell.oga"],
                capture_output=True)
except: 
    def _beep(): pass

# ══════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIG
# ══════════════════════════════════════════════════════════════════════════
VERSION       = "1.0"
TOOL_NAME     = "OPoison"
AUTHOR        = "khaled.s.haddad"
WEBSITE       = "owlsec.org"

# Storage paths (XDG-aware)
_BASE_DIR     = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "opoison"
_BASE_DIR.mkdir(parents=True, exist_ok=True)

HISTORY_FILE  = _BASE_DIR / "history.json"
ALERTS_FILE   = _BASE_DIR / "alerts.json"
CONFIG_FILE   = _BASE_DIR / "config.json"
BASELINE_FILE = _BASE_DIR / "baseline.json"
LOG_DIR       = _BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

MAX_ALERTS    = 1000
MAX_HISTORY   = 200
MAX_LOG_ROWS  = 50000

# ══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════
_DEFAULT_CONFIG = {
    "default_interface"   : "",
    "default_gateway"     : "",
    "default_timeout"     : 2.0,
    "default_interval"    : 5.0,
    "alert_sound"         : False,
    "auto_export"         : False,
    "export_format"       : "json",   # json | csv | both
    "export_path"         : str(LOG_DIR),
    "risk_threshold_alert": 30,
    "risk_threshold_crit" : 60,
    "color_scheme"        : "default",
    "show_vendor"         : True,
    "resolve_hostnames"   : False,
    "max_scan_hosts"      : 1024,
}

def _load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            stored = json.loads(CONFIG_FILE.read_text())
            cfg = dict(_DEFAULT_CONFIG)
            cfg.update(stored)
            return cfg
    except: pass
    return dict(_DEFAULT_CONFIG)

def _save_config(cfg: dict):
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    except: pass

CFG = _load_config()

# ══════════════════════════════════════════════════════════════════════════
# COLORS & THEMES
# ══════════════════════════════════════════════════════════════════════════
_NO_COLOR = os.environ.get("NO_COLOR") or not sys.stdout.isatty()

class C:
    RED     = "" if _NO_COLOR else "\033[91m"
    GREEN   = "" if _NO_COLOR else "\033[92m"
    YELLOW  = "" if _NO_COLOR else "\033[93m"
    CYAN    = "" if _NO_COLOR else "\033[96m"
    WHITE   = "" if _NO_COLOR else "\033[97m"
    BOLD    = "" if _NO_COLOR else "\033[1m"
    RESET   = "" if _NO_COLOR else "\033[0m"
    MAGENTA = "" if _NO_COLOR else "\033[95m"
    BLUE    = "" if _NO_COLOR else "\033[94m"
    DIM     = "" if _NO_COLOR else "\033[2m"
    ORANGE  = "" if _NO_COLOR else "\033[38;5;214m"
    BGRED   = "" if _NO_COLOR else "\033[41m"
    BGYELLOW= "" if _NO_COLOR else "\033[43m"
    UNDER   = "" if _NO_COLOR else "\033[4m"

def color(text, clr):
    return f"{clr}{text}{C.RESET}" if not _NO_COLOR else str(text)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input(color("\n  [↩] Press Enter to return to main menu...", C.YELLOW))

def stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def tstamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def datestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ══════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════
_TW = shutil.get_terminal_size((80, 24)).columns

def _line(char="─", clr=C.CYAN, width=None):
    w = width or min(_TW - 2, 72)
    print(color(char * w, clr))

def banner():
    w = min(_TW, 74)
    print()
    print(color(r"""
  ██████╗ ██████╗  ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗
 ██╔═══██╗██╔══██╗██╔═══██╗██║██╔════╝██╔═══██╗████╗  ██║
 ██║   ██║██████╔╝██║   ██║██║███████╗██║   ██║██╔██╗ ██║
 ██║   ██║██╔═══╝ ██║   ██║██║╚════██║██║   ██║██║╚██╗██║
 ╚██████╔╝██║     ╚██████╔╝██║███████║╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝""", C.CYAN))
    print()
    print(color(f"  {'ARP Spoof & MITM Detection Engine':^56}  v{VERSION}", C.MAGENTA + C.BOLD))
    print(color(f"  {'Monitor · Detect · Scan · Alert · Forensics':^56}", C.WHITE))
    print()
    scapy_s = color("Scapy ✔", C.GREEN) if HAVE_SCAPY else color("Scapy ✘  (pip install scapy)", C.RED)
    root_s  = color("root ✔", C.GREEN) if os.geteuid() == 0 else color("root ✘  (limited)", C.YELLOW)
    print(color("  Author  : ", C.DIM) + color(AUTHOR, C.CYAN) +
          color("   |   Website : ", C.DIM) + color(WEBSITE, C.CYAN))
    print(color("  Engine  : ", C.DIM) + scapy_s + color("   |   ", C.DIM) + root_s)
    _line()
    print()

def print_header(title: str):
    print()
    _line()
    pad = max(0, (min(_TW-2, 72) - len(title) - 2) // 2)
    print(color(" " * pad + "◈  " + title + "  ◈", C.BOLD + C.CYAN))
    _line()

def section(title: str):
    print()
    print(color(f"  ┌─ {title}", C.YELLOW + C.BOLD))

def ok(msg):     print(f"  {color('[✔]', C.GREEN)} {color(msg, C.WHITE)}")
def err(msg):    print(f"  {color('[✘]', C.RED)} {color(msg, C.WHITE)}")
def info(msg):   print(f"  {color('[*]', C.CYAN)} {color(msg, C.DIM)}")
def warn(msg):   print(f"  {color('[!]', C.ORANGE)} {color(msg, C.WHITE)}")

def alert(msg, sub=""):
    ts = tstamp()
    print(f"\r  {color('['+ts+']', C.DIM)} {color('[ ALERT ]', C.ORANGE + C.BOLD)} "
          f"{color(msg, C.ORANGE + C.BOLD)}")
    if sub: print(f"           {color(sub, C.DIM)}")

def critical(msg, sub=""):
    ts = tstamp()
    print(f"\r  {color('['+ts+']', C.DIM)} {color('[CRITICAL]', C.RED + C.BOLD)} "
          f"{color(msg, C.RED + C.BOLD)}")
    if sub: print(f"           {color(sub, C.DIM)}")
    if CFG.get("alert_sound"):
        _beep()

def _print_alert(level: str, msg: str, sub: str = ""):
    if level == "CRITICAL":
        critical(msg, sub)
    elif level == "ALERT":
        alert(msg, sub)
    else:
        ts = tstamp()
        print(f"\r  {color('['+ts+']', C.DIM)} {color('[  INFO  ]', C.DIM)} {color(msg, C.DIM)}")
        if sub: print(f"           {color(sub, C.DIM)}")

def progress_bar(current: int, total: int, width: int = 30, label: str = "") -> str:
    pct    = current / max(total, 1)
    filled = int(pct * width)
    bar    = color("█" * filled, C.CYAN) + color("░" * (width - filled), C.DIM)
    pct_s  = color(f" {pct*100:>5.1f}%", C.WHITE)
    lbl    = color(f" {label}", C.DIM) if label else ""
    return f"  [{bar}]{pct_s}{lbl}"

def risk_bar(score: int) -> str:
    filled = int(score / 100 * 20)
    clr = C.GREEN if score < 30 else C.ORANGE if score < 60 else C.RED
    return color("█" * filled, clr) + color("░" * (20 - filled), C.DIM)

def risk_label(score: int) -> str:
    if score < 30:  return color("LOW",      C.GREEN)
    if score < 60:  return color("MEDIUM",   C.YELLOW)
    if score < 90:  return color("HIGH",     C.ORANGE)
    return color("CRITICAL", C.RED + C.BOLD)

# ══════════════════════════════════════════════════════════════════════════
# OUI / VENDOR DATABASE
# ══════════════════════════════════════════════════════════════════════════
OUI_DB: Dict[str, str] = {
    "00:50:56": "VMware",           "00:0c:29": "VMware-Guest",
    "08:00:27": "VirtualBox",       "52:54:00": "QEMU/KVM",
    "00:1c:42": "Parallels",        "00:16:3e": "Xen",
    "02:42:"  : "Docker",           "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi 4",   "e4:5f:01": "Raspberry Pi 5",
    "00:1a:2b": "Cisco",            "00:1b:17": "Cisco-AP",
    "00:23:04": "Cisco",            "fc:fb:fb": "Cisco",
    "00:50:f2": "Microsoft",        "28:18:78": "Microsoft",
    "3c:5a:b4": "Google",           "f4:f5:d8": "Google Home",
    "a4:77:33": "Google Chromecast","00:1a:11": "Google",
    "18:65:90": "Apple",            "3c:d0:f8": "Apple",
    "a4:c3:f0": "Apple",            "ac:de:48": "Apple",
    "00:17:f2": "Apple",            "34:08:bc": "Apple",
    "ac:37:43": "HTC",              "00:bb:3a": "Amazon Echo",
    "fc:a1:83": "Amazon",           "74:c2:46": "Amazon Fire",
    "b0:7d:64": "Netgear",          "c0:3f:0e": "Netgear",
    "00:14:6c": "Netgear",          "20:e5:2a": "Belkin",
    "00:17:3f": "Belkin",           "00:1c:df": "Belkin",
    "d8:eb:97": "TP-Link",          "50:c7:bf": "TP-Link",
    "74:ea:3a": "TP-Link",          "14:cc:20": "TP-Link",
    "00:0f:66": "Linksys",          "00:18:f8": "D-Link",
    "1c:7e:e5": "D-Link",           "28:10:7b": "D-Link",
    "00:25:9c": "Cisco Meraki",     "88:15:44": "Cisco Meraki",
    "00:0e:8e": "Aruba",            "94:b4:0f": "Aruba",
    "00:1a:1e": "Fortinet",         "90:6c:ac": "Fortinet",
    "00:50:c2": "IEEE 802.3",       "ff:ff:ff": "Broadcast",
}

VM_PREFIXES = {"00:0c:29", "08:00:27", "52:54:00", "00:1c:42", "00:16:3e", "02:42:"}

def lookup_oui(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    prefix = ":".join(mac.lower().split(":")[:3])
    if prefix in OUI_DB:
        return OUI_DB[prefix]
    # Try partial match for Docker-style
    short = mac.lower()[:5]
    for oui, vendor in OUI_DB.items():
        if oui.endswith(":") and short.startswith(oui[:-1].lower()):
            return vendor
    return ""

def is_vm_mac(mac: str) -> bool:
    prefix = ":".join(mac.lower().split(":")[:3])
    return prefix in VM_PREFIXES

def resolve_hostname(ip: str) -> str:
    if not CFG.get("resolve_hostnames"):
        return ""
    try:
        return socket.gethostbyaddr(ip)[0]
    except: return ""

# ══════════════════════════════════════════════════════════════════════════
# PERSISTENCE: ALERTS & HISTORY
# ══════════════════════════════════════════════════════════════════════════
def log_alert(atype: str, detail: str, src_ip: str = "", src_mac: str = "",
              score: int = 0, extra: dict = None):
    try:
        alerts = []
        if ALERTS_FILE.exists():
            try: alerts = json.loads(ALERTS_FILE.read_text())
            except: alerts = []
        entry = {
            "timestamp" : stamp(),
            "type"      : atype,
            "detail"    : detail,
            "src_ip"    : src_ip,
            "src_mac"   : src_mac,
            "risk_score": score,
        }
        if extra: entry.update(extra)
        alerts.append(entry)
        ALERTS_FILE.write_text(json.dumps(alerts[-MAX_ALERTS:], indent=2))
    except: pass

def log_session(mode: str, iface: str, duration: float,
                packets: int, alerts_found: int, extra: dict = None):
    try:
        history = []
        if HISTORY_FILE.exists():
            try: history = json.loads(HISTORY_FILE.read_text())
            except: history = []
        entry = {
            "timestamp" : stamp(),
            "mode"      : mode,
            "interface" : iface,
            "duration"  : round(duration, 1),
            "packets"   : packets,
            "alerts"    : alerts_found,
        }
        if extra: entry.update(extra)
        history.append(entry)
        HISTORY_FILE.write_text(json.dumps(history[-MAX_HISTORY:], indent=2))
    except: pass

# ══════════════════════════════════════════════════════════════════════════
# RISK SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════
def arp_risk_score(ip_mac_map: dict, src_ip: str, src_mac: str,
                   gateway_ip: str) -> Tuple[int, List[str]]:
    score   = 0
    reasons = []

    # Rule 1: MAC changed for known IP
    known_mac = ip_mac_map.get(src_ip)
    if known_mac and known_mac.lower() != src_mac.lower():
        score += 45
        reasons.append(f"MAC changed: {known_mac} → {src_mac}")

    # Rule 2: Gateway claimed by different MAC
    if src_ip == gateway_ip:
        gw_mac = ip_mac_map.get(gateway_ip)
        if gw_mac and gw_mac.lower() != src_mac.lower():
            score += 50
            reasons.append(f"Gateway IP claimed by unexpected MAC")

    # Rule 3: VM/Tool MAC prefix
    if is_vm_mac(src_mac):
        vendor = lookup_oui(src_mac)
        score += 15
        reasons.append(f"VM/Tool MAC detected ({vendor or 'unknown'})")

    # Rule 4: Gratuitous ARP (unsolicited reply)
    score += 5
    reasons.append("Gratuitous ARP / broadcast reply")

    # Rule 5: One MAC claiming many IPs
    ips_for_mac = [ip for ip, mac in ip_mac_map.items()
                   if mac.lower() == src_mac.lower()]
    if len(ips_for_mac) > 2:
        score += 10
        reasons.append(f"MAC maps to {len(ips_for_mac)} IPs (possible MITM pivot)")

    return min(score, 100), reasons

# ══════════════════════════════════════════════════════════════════════════
# INTERFACE & NETWORK HELPERS
# ══════════════════════════════════════════════════════════════════════════
def list_interfaces() -> List[str]:
    if HAVE_SCAPY:
        return [i for i in get_if_list()
                if "lo" not in i.lower() and i != "any"]
    try:
        out   = subprocess.check_output(["ip", "-o", "link"], text=True)
        ifaces = re.findall(r"\d+: (\S+?)[@:]", out)
        return [i for i in ifaces if i != "lo"]
    except: return []

def get_iface_info(iface: str) -> dict:
    """Return IP, MAC, speed for an interface."""
    result = {"ip": "", "mac": "", "speed": "", "state": ""}
    try:
        if HAVE_SCAPY:
            result["mac"] = get_if_hwaddr(iface)
            result["ip"]  = get_if_addr(iface)
        # State & speed via sysfs
        sp_f = Path(f"/sys/class/net/{iface}/speed")
        st_f = Path(f"/sys/class/net/{iface}/operstate")
        if sp_f.exists():
            try: result["speed"] = sp_f.read_text().strip() + " Mbps"
            except: pass
        if st_f.exists():
            result["state"] = st_f.read_text().strip()
    except: pass
    return result

def pick_interface(prompt: str = "Choose interface") -> Optional[str]:
    ifaces = list_interfaces()
    if not ifaces:
        err("No network interfaces found."); return None
    if len(ifaces) == 1:
        info(f"Auto-selected interface: {color(ifaces[0], C.WHITE)}")
        return ifaces[0]

    section("Available Interfaces")
    print(color(f"    {'#':<4} {'Interface':<14} {'IP':<18} {'MAC':<20} State", C.DIM))
    print(color("  " + "─" * 60, C.DIM))
    for i, iface in enumerate(ifaces):
        nfo    = get_iface_info(iface)
        state  = nfo.get("state", "")
        st_clr = C.GREEN if state == "up" else C.DIM
        nfo_ip  = nfo["ip"]
        nfo_mac = nfo["mac"]
        print(f"  {color('['+str(i+1)+']', C.GREEN)}  "
              f"{color(f'{iface:<14}', C.WHITE)}"
              f"{color(f'{nfo_ip:<18}', C.CYAN)}"
              f"{color(f'{nfo_mac:<20}', C.DIM)}"
              f"{color(state, st_clr)}")
    print()

    default = CFG.get("default_interface") or ifaces[0]
    raw = input(color(f"  [»] {prompt} [default: {default}]: ", C.CYAN)).strip()
    if not raw:
        return default
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
    except: pass
    if raw in ifaces:
        return raw
    warn(f"Unknown interface '{raw}', using {ifaces[0]}")
    return ifaces[0]

def get_local_ip(iface: str = None) -> str:
    if HAVE_SCAPY and iface:
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                return ip
        except: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "0.0.0.0"

def detect_gateway(local_ip: str = None) -> str:
    """Try to detect the default gateway."""
    if CFG.get("default_gateway"):
        return CFG["default_gateway"]
    # Try ip route
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"],
                                      text=True, stderr=subprocess.DEVNULL)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m: return m.group(1)
    except: pass
    # Fallback: assume .1
    if local_ip:
        parts = local_ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".1"
    return ""

def seed_arp_table(ip_mac_map: dict):
    """Pre-populate from system ARP cache."""
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True,
                                      stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            # Format: IP dev IFACE lladdr MAC state STATE
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                ip  = parts[0]
                mac = parts[idx + 1]
                if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                    ip_mac_map[ip] = mac
    except:
        # Fallback: arp -n
        try:
            out = subprocess.check_output(["arp", "-n"], text=True,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    ip, mac = parts[0], parts[2]
                    if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                        ip_mac_map[ip] = mac
        except: pass

# ══════════════════════════════════════════════════════════════════════════
# EXPORT ENGINE
# ══════════════════════════════════════════════════════════════════════════
def _ask_export_path(default_name: str) -> Optional[Path]:
    """Interactively ask user where to save results."""
    section("Export Results")
    print(f"  {color('[1]', C.GREEN)} Save to default logs dir    {color(str(LOG_DIR), C.DIM)}")
    print(f"  {color('[2]', C.GREEN)} Save to current directory   {color(str(Path.cwd()), C.DIM)}")
    print(f"  {color('[3]', C.GREEN)} Enter custom path")
    print(f"  {color('[N]', C.RED)}   Skip export")
    print()
    choice = input(color("  [»] Choice: ", C.CYAN)).strip().upper()

    if choice == "N" or choice == "":
        return None
    elif choice == "1":
        return LOG_DIR / default_name
    elif choice == "2":
        return Path.cwd() / default_name
    elif choice == "3":
        raw = input(color("  [»] Enter full path (dir or file): ", C.CYAN)).strip()
        if not raw:
            return None
        p = Path(raw).expanduser()
        if p.is_dir():
            return p / default_name
        return p
    return None

def _ask_export_format() -> str:
    """Ask user which format(s) to export."""
    fmt = CFG.get("export_format", "json")
    print()
    print(f"  {color('[1]', C.GREEN)} JSON    — structured, machine-readable")
    print(f"  {color('[2]', C.GREEN)} CSV     — spreadsheet-compatible")
    print(f"  {color('[3]', C.GREEN)} Both    — JSON + CSV")
    print(f"  {color('[4]', C.GREEN)} Gzipped JSON — compressed archive")
    print()
    choice = input(color(f"  [»] Format [default: {fmt}]: ", C.CYAN)).strip()
    mapping = {"1": "json", "2": "csv", "3": "both", "4": "gzip"}
    return mapping.get(choice, fmt)

def export_json(data: dict, path: Path, compress: bool = False):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(data, indent=2, default=str)
        if compress:
            gz_path = path.with_suffix(".json.gz")
            with gzip.open(gz_path, "wt", encoding="utf-8") as f:
                f.write(content)
            ok(f"JSON (gzip) saved: {gz_path}")
            return gz_path
        else:
            path.write_text(content)
            ok(f"JSON saved: {path}")
            return path
    except Exception as e:
        err(f"JSON export failed: {e}")
        return None

def export_csv(rows: List[dict], path: Path, fieldnames: List[str] = None):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not rows:
            err("No rows to export."); return None
        fields = fieldnames or list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        ok(f"CSV saved: {path}")
        return path
    except Exception as e:
        err(f"CSV export failed: {e}")
        return None

def do_export(data: dict, rows: List[dict], stem: str,
              csv_fields: List[str] = None):
    """Full interactive export flow."""
    fmt  = _ask_export_format()
    path = _ask_export_path(stem)
    if path is None:
        info("Export skipped.")
        return

    if fmt in ("json", "both"):
        export_json(data, path.with_suffix(".json"))
    if fmt == "gzip":
        export_json(data, path.with_suffix(".json"), compress=True)
    if fmt in ("csv", "both") and rows:
        export_csv(rows, path.with_suffix(".csv"), csv_fields)

# ══════════════════════════════════════════════════════════════════════════
# BASELINE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════
def load_baseline() -> dict:
    try:
        if BASELINE_FILE.exists():
            return json.loads(BASELINE_FILE.read_text())
    except: pass
    return {}

def save_baseline(ip_mac_map: dict):
    try:
        bl = {
            "timestamp": stamp(),
            "devices"  : ip_mac_map,
            "hash"     : hashlib.sha256(
                json.dumps(ip_mac_map, sort_keys=True).encode()
            ).hexdigest()[:12],
        }
        BASELINE_FILE.write_text(json.dumps(bl, indent=2))
        ok(f"Baseline saved: {len(ip_mac_map)} devices  [{bl['hash']}]")
    except Exception as e:
        err(f"Baseline save failed: {e}")

def compare_with_baseline(ip_mac_map: dict) -> List[dict]:
    """Return list of anomalies vs stored baseline."""
    bl   = load_baseline()
    devs = bl.get("devices", {})
    if not devs:
        return []
    issues = []
    for ip, mac in ip_mac_map.items():
        if ip in devs and devs[ip].lower() != mac.lower():
            issues.append({"ip": ip, "baseline_mac": devs[ip], "current_mac": mac})
    for ip in devs:
        if ip not in ip_mac_map:
            issues.append({"ip": ip, "baseline_mac": devs[ip], "current_mac": "ABSENT"})
    return issues

# ══════════════════════════════════════════════════════════════════════════
# MODULE 1 — LIVE MONITOR
# ══════════════════════════════════════════════════════════════════════════
class MonitorState:
    def __init__(self):
        self.ip_mac_map   : Dict[str, str] = {}
        self.lock         = threading.Lock()
        self.alerts       : List[dict]     = []
        self.packet_count : int            = 0
        self.arp_count    : int            = 0
        self.start_time   : float          = time.time()
        self.running      : bool           = True
        self.gateway_ip   : str            = ""
        self.log_rows     : List[dict]     = []
        self.dns_map      : Dict[str, str] = {}   # ip → hostname
        self.rate_window  : List[float]    = []   # timestamps for rate calc

def _process_pkt(pkt, state: MonitorState):
    with state.lock:
        state.packet_count += 1
        now = time.time()
        state.rate_window.append(now)
        # Keep only last 5 seconds for rate
        state.rate_window = [t for t in state.rate_window if now - t <= 5]

    if not (HAVE_SCAPY and pkt.haslayer(ARP)):
        return

    arp_l   = pkt[ARP]
    src_ip  = arp_l.psrc
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
    dst_ip  = arp_l.pdst
    op      = arp_l.op  # 1=request 2=reply

    if not src_ip or not src_mac:
        return

    # Skip self/link-local
    if src_ip.startswith("169.254") or src_ip == "0.0.0.0":
        return

    with state.lock:
        state.arp_count += 1
        known_mac = state.ip_mac_map.get(src_ip)

        row = {
            "time"   : tstamp(),
            "src_ip" : src_ip,
            "src_mac": src_mac,
            "dst_ip" : dst_ip,
            "op"     : "reply" if op == 2 else "request",
            "alert"  : "",
            "score"  : 0,
        }

        if known_mac is None:
            state.ip_mac_map[src_ip] = src_mac
            vendor = lookup_oui(src_mac)
            vendor_s = f" ({vendor})" if vendor else ""
            _print_alert("INFO",
                f"New device: {src_ip} → {src_mac}{vendor_s}")

        elif known_mac.lower() != src_mac.lower():
            score, reasons = arp_risk_score(
                state.ip_mac_map, src_ip, src_mac, state.gateway_ip)

            if src_ip == state.gateway_ip:
                level = "CRITICAL"
                msg   = f"GATEWAY ARP SPOOFING — {src_ip}"
                sub   = (f"Was: {known_mac}  →  Now: {src_mac}  "
                         f"| Risk: {score}/100")
                log_alert("CRITICAL/Gateway-Spoof", sub, src_ip, src_mac, score)
            else:
                level = "ALERT"
                msg   = f"ARP Spoof detected: {src_ip}"
                sub   = (f"Was: {known_mac}  →  Now: {src_mac}  "
                         f"| Risk: {score}/100")
                log_alert("ALERT/IP-MAC-Mismatch", sub, src_ip, src_mac, score)

            _print_alert(level, msg, sub)
            state.alerts.append({
                "time"    : stamp(), "level": level,
                "ip"      : src_ip, "old_mac": known_mac,
                "new_mac" : src_mac, "score": score, "reasons": reasons,
            })
            row["alert"] = level
            row["score"] = score

        if len(state.log_rows) < MAX_LOG_ROWS:
            state.log_rows.append(row)

def _status_thread(state: MonitorState):
    while state.running:
        elapsed  = time.time() - state.start_time
        n_pkts   = state.packet_count
        n_arp    = state.arp_count
        n_devs   = len(state.ip_mac_map)
        n_alts   = len(state.alerts)
        rate     = len(state.rate_window) / 5.0  # pkts/sec over last 5s
        a_clr    = C.RED + C.BOLD if n_alts > 0 else C.DIM
        sys.stdout.write(
            f"\r  {color('[»]', C.CYAN)} "
            f"Pkts:{color(str(n_pkts), C.WHITE)}  "
            f"ARP:{color(str(n_arp), C.YELLOW)}  "
            f"Hosts:{color(str(n_devs), C.CYAN)}  "
            f"Alerts:{color(str(n_alts), a_clr)}  "
            f"Rate:{color(f'{rate:.1f}/s', C.DIM)}  "
            f"Up:{color(f'{elapsed:.0f}s', C.DIM)}  "
            f"{color('Ctrl+C stop', C.DIM)}   "
        )
        sys.stdout.flush()
        time.sleep(0.5)

def module_monitor():
    print_header("Live ARP Monitor — MITM / Spoof Detection")
    if not HAVE_SCAPY:
        err("Scapy is required.  →  pip install scapy"); return
    if os.geteuid() != 0:
        err("Root privileges required.  →  sudo ./OPoison"); return

    print()
    iface = pick_interface("Select monitoring interface")
    if not iface: return

    local_ip   = get_local_ip(iface)
    default_gw = detect_gateway(local_ip)

    gw_r = input(color(
        f"  [»] Gateway IP [detected: {default_gw or 'none'}]: ", C.CYAN)).strip()
    gateway_ip = gw_r if gw_r else default_gw

    bpf_r = input(color("  [»] BPF filter [default: arp]: ", C.CYAN)).strip()
    bpf   = bpf_r if bpf_r else "arp"

    use_bl = input(color("  [»] Load & compare with saved baseline? [y/N]: ",
                          C.CYAN)).strip().lower() == "y"

    state = MonitorState()
    state.gateway_ip = gateway_ip
    seed_arp_table(state.ip_mac_map)

    if use_bl:
        bl_issues = compare_with_baseline(state.ip_mac_map)
        if bl_issues:
            section("Baseline Anomalies at Start")
            for iss in bl_issues:
                warn(f"{iss['ip']}: baseline={iss['baseline_mac']}  "
                     f"current={iss['current_mac']}")

    section("Monitor Configuration")
    print(f"    {color('Interface  :', C.CYAN)} {color(iface, C.WHITE + C.BOLD)}")
    print(f"    {color('Local IP   :', C.CYAN)} {color(local_ip, C.WHITE)}")
    print(f"    {color('Gateway    :', C.CYAN)} {color(gateway_ip or 'unset', C.WHITE)}")
    print(f"    {color('BPF filter :', C.CYAN)} {color(bpf, C.DIM)}")
    print(f"    {color('Baseline   :', C.CYAN)} {color(str(len(state.ip_mac_map))+' devices seeded', C.DIM)}")
    print()
    warn("Monitoring active — press Ctrl+C to stop.")
    print()

    stat_t = threading.Thread(target=_status_thread, args=(state,), daemon=True)
    stat_t.start()

    t0 = time.time()
    try:
        sniff(iface=iface, filter=bpf,
              prn=lambda p: _process_pkt(p, state),
              store=False,
              stop_filter=lambda p: not state.running)
    except KeyboardInterrupt:
        pass
    finally:
        state.running = False

    duration = time.time() - t0
    print(); print()

    section("Session Report")
    print(f"    {color('Duration  :', C.CYAN)} {color(f'{duration:.1f}s', C.WHITE)}")
    print(f"    {color('Packets   :', C.CYAN)} {color(str(state.packet_count), C.WHITE)}")
    print(f"    {color('ARP pkts  :', C.CYAN)} {color(str(state.arp_count), C.YELLOW)}")
    print(f"    {color('Devices   :', C.CYAN)} {color(str(len(state.ip_mac_map)), C.WHITE)}")
    n_alts = len(state.alerts)
    a_clr  = C.RED + C.BOLD if n_alts else C.DIM
    print(f"    {color('Alerts    :', C.CYAN)} {color(str(n_alts), a_clr)}")

    if state.alerts:
        section("Alerts Summary")
        for a in state.alerts:
            lvl_clr = C.RED + C.BOLD if a["level"] == "CRITICAL" else C.ORANGE
            bar     = risk_bar(a["score"])
            lbl     = risk_label(a["score"])
            print(f"  {color('[!]', lvl_clr)} {color(a['ip'], C.WHITE)}  "
                  f"{color(a['old_mac'], C.DIM)} → {color(a['new_mac'], C.RED+C.BOLD)}"
                  f"  [{bar}] {lbl} {color(str(a['score'])+'/100', C.DIM)}")

    if state.ip_mac_map:
        section("Discovered Devices")
        print(color(f"    {'IP Address':<20} {'MAC Address':<20} {'Vendor':<18} Note", C.DIM))
        print(color("  " + "─" * 64, C.DIM))
        for ip, mac in sorted(state.ip_mac_map.items(),
                               key=lambda x: socket.inet_aton(x[0])):
            gw_tag = color(" ← GATEWAY", C.YELLOW + C.BOLD) if ip == gateway_ip else ""
            vendor = lookup_oui(mac)
            vm_tag = color(" [VM]", C.ORANGE) if is_vm_mac(mac) else ""
            print(f"    {color(f'{ip:<20}', C.CYAN)}"
                  f"{color(f'{mac:<20}', C.WHITE)}"
                  f"{color(f'{vendor:<18}', C.DIM)}"
                  f"{gw_tag}{vm_tag}")

    log_session("Monitor", iface, duration, state.packet_count, n_alts,
                {"devices": len(state.ip_mac_map), "gateway": gateway_ip})

    # Save baseline option
    print()
    if input(color("  [»] Save current device table as baseline? [y/N]: ",
                   C.CYAN)).strip().lower() == "y":
        save_baseline(state.ip_mac_map)

    # Export
    print()
    if input(color("  [»] Export session results? [y/N]: ",
                   C.YELLOW)).strip().lower() == "y":
        stem = f"monitor_{iface}_{datestamp()}"
        report = {
            "timestamp"  : stamp(), "interface": iface,
            "gateway"    : gateway_ip, "duration": round(duration, 1),
            "packet_count": state.packet_count, "arp_count": state.arp_count,
            "alerts"     : state.alerts,
            "devices"    : state.ip_mac_map,
        }
        csv_fields = ["time","src_ip","src_mac","dst_ip","op","alert","score"]
        do_export(report, state.log_rows, stem, csv_fields)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 2 — ARP NETWORK SCAN
# ══════════════════════════════════════════════════════════════════════════
def module_arp_scan():
    print_header("ARP Network Scan — Discover Live Hosts")
    if not HAVE_SCAPY:
        err("Scapy required."); return
    if os.geteuid() != 0:
        err("Root privileges required."); return

    print()
    iface      = pick_interface("Select scan interface")
    if not iface: return

    local_ip      = get_local_ip(iface)
    default_cidr  = ".".join(local_ip.split(".")[:3]) + ".0/24"

    cidr_r = input(color(f"  [»] Target CIDR [{default_cidr}]: ", C.CYAN)).strip()
    cidr   = cidr_r if cidr_r else default_cidr

    timeout_r = input(color("  [»] Timeout seconds [default: 2]: ", C.CYAN)).strip()
    try: timeout = float(timeout_r) if timeout_r else 2.0
    except: timeout = 2.0

    retry_r = input(color("  [»] Retries [default: 1]: ", C.CYAN)).strip()
    try: retries = int(retry_r) if retry_r else 1
    except: retries = 1

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        err(f"Invalid CIDR: {e}"); return

    total = sum(1 for _ in net.hosts())
    if total > CFG.get("max_scan_hosts", 1024):
        warn(f"Large scan: {total} hosts. This may take a while.")
        if input(color("  [»] Continue? [y/N]: ", C.CYAN)).strip().lower() != "y":
            return

    section("Scan Configuration")
    print(f"    {color('Interface :', C.CYAN)} {color(iface, C.WHITE)}")
    print(f"    {color('Target    :', C.CYAN)} {color(cidr, C.WHITE + C.BOLD)}")
    print(f"    {color('Hosts     :', C.CYAN)} {color(str(total), C.DIM)}")
    print(f"    {color('Timeout   :', C.CYAN)} {color(f'{timeout}s', C.DIM)}")
    print(f"    {color('Retries   :', C.CYAN)} {color(str(retries), C.DIM)}")
    print()

    info(f"Sending ARP broadcasts to {cidr}…")
    print()

    arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(cidr))
    t0 = time.time()
    try:
        answered, _ = srp(arp_pkt, iface=iface,
                          timeout=timeout, retry=retries, verbose=False)
    except Exception as e:
        err(f"Scan failed: {e}"); return

    duration = time.time() - t0

    section(f"Scan Results — {color(str(len(answered)), C.WHITE)} hosts found  "
            f"in {color(f'{duration:.2f}s', C.DIM)}")

    if not answered:
        info("No hosts responded."); return

    print(color(f"    {'IP Address':<20} {'MAC Address':<20} {'Vendor':<18} {'Risk':<8} Notes",
                C.DIM))
    print(color("  " + "─" * 70, C.DIM))

    devices: List[dict] = []
    mac_to_ips: Dict[str, List[str]] = defaultdict(list)

    for _, recv in sorted(answered, key=lambda x: socket.inet_aton(x[1].psrc)):
        ip     = recv.psrc
        mac    = recv.hwsrc
        vendor = lookup_oui(mac) or "Unknown"
        vm_f   = is_vm_mac(mac)
        risk_s = color("VM/Tool", C.ORANGE) if vm_f else color("—", C.DIM)
        mac_to_ips[mac].append(ip)
        host   = resolve_hostname(ip)
        note   = color(f"  {host}", C.DIM) if host else ""

        print(f"    {color(f'{ip:<20}', C.CYAN)}"
              f"{color(f'{mac:<20}', C.WHITE)}"
              f"{color(f'{vendor:<18}', C.DIM)}"
              f"{risk_s:<8}{note}")
        devices.append({"ip": ip, "mac": mac, "vendor": vendor,
                         "vm": vm_f, "hostname": host})

    # Duplicate MAC detection
    dupes = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    if dupes:
        section("⚠  Duplicate MAC Warning — Possible MITM")
        for mac, ips in dupes.items():
            warn(f"MAC {color(mac, C.WHITE)} claims {len(ips)} IPs: "
                 f"{color(', '.join(ips), C.RED + C.BOLD)}")
            log_alert("SCAN/Duplicate-MAC",
                      f"{mac} → {', '.join(ips)}", ips[0], mac)
    else:
        print()
        ok("No duplicate MACs detected.")

    log_session("ARP-Scan", iface, duration, len(answered), len(dupes),
                {"cidr": cidr, "total_hosts": total})

    # Export
    print()
    if input(color("  [»] Export scan results? [y/N]: ",
                   C.YELLOW)).strip().lower() == "y":
        stem   = f"scan_{datestamp()}"
        report = {
            "timestamp"     : stamp(), "interface": iface,
            "cidr"          : cidr, "duration": round(duration, 2),
            "hosts_found"   : len(answered),
            "devices"       : devices,
            "duplicate_macs": {k: v for k, v in dupes.items()},
        }
        csv_fields = ["ip", "mac", "vendor", "vm", "hostname"]
        do_export(report, devices, stem, csv_fields)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 3 — ARP TABLE INSPECTOR
# ══════════════════════════════════════════════════════════════════════════
def module_arp_table():
    print_header("ARP Table Inspector & Cross-Checker")

    section("System ARP Cache  (ip neigh)")
    entries: List[dict] = []

    # Primary: ip neigh
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True,
                                      stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                ip  = parts[0]
                mac = parts[idx + 1]
                dev = parts[2] if len(parts) > 2 else ""
                state_idx = idx + 2
                nstate = parts[state_idx] if len(parts) > state_idx else ""
                if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                    entries.append({"ip": ip, "mac": mac,
                                    "iface": dev, "state": nstate})
    except:
        # Fallback: arp -n
        try:
            out = subprocess.check_output(["arp", "-n"], text=True,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    ip, mac = parts[0], parts[2]
                    if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                        entries.append({"ip": ip, "mac": mac,
                                        "iface": "", "state": ""})
        except Exception as e:
            err(f"Could not read ARP table: {e}"); return

    if not entries:
        info("ARP table is empty."); return

    mac_to_ips: Dict[str, List[str]] = defaultdict(list)
    for e in entries:
        mac_to_ips[e["mac"]].append(e["ip"])

    print(color(f"    {'IP Address':<20} {'MAC Address':<20} {'Vendor':<18} "
                f"{'Iface':<8} State", C.DIM))
    print(color("  " + "─" * 70, C.DIM))

    for e in entries:
        ip     = e["ip"]
        mac    = e["mac"]
        vendor = lookup_oui(mac) or ""
        iface  = e.get("iface", "")
        state  = e.get("state", "")
        is_dup = len(mac_to_ips[mac]) > 1
        mac_clr = C.RED + C.BOLD if is_dup else C.WHITE
        st_clr  = C.GREEN if state == "REACHABLE" else C.DIM
        dup_tag = color(" ← DUP", C.RED + C.BOLD) if is_dup else ""

        print(f"    {color(f'{ip:<20}', C.CYAN)}"
              f"{color(f'{mac:<20}', mac_clr)}"
              f"{color(f'{vendor:<18}', C.DIM)}"
              f"{color(f'{iface:<8}', C.DIM)}"
              f"{color(state, st_clr)}{dup_tag}")

    dupes = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    if dupes:
        print()
        section("⚠  Duplicate MAC Addresses Detected")
        for mac, ips in dupes.items():
            warn(f"MAC {color(mac, C.WHITE)} is claimed by: "
                 f"{color(', '.join(ips), C.RED + C.BOLD)}")
            log_alert("ARP-TABLE/Duplicate-MAC",
                      f"{mac} → {', '.join(ips)}", ips[0], mac)
    else:
        print(); ok("No duplicate MACs found in ARP table.")

    # Baseline comparison
    print()
    if input(color("  [»] Compare against saved baseline? [y/N]: ",
                   C.CYAN)).strip().lower() == "y":
        current_map = {e["ip"]: e["mac"] for e in entries}
        issues = compare_with_baseline(current_map)
        if issues:
            section("Baseline Comparison Anomalies")
            for iss in issues:
                warn(f"{iss['ip']}: baseline={iss['baseline_mac']}  "
                     f"current={iss['current_mac']}")
        else:
            ok("ARP table matches baseline.")

    # Live cross-check
    print()
    if (HAVE_SCAPY and os.geteuid() == 0 and
            input(color("  [»] Cross-check with live ARP scan? [y/N]: ",
                        C.CYAN)).strip().lower() == "y"):
        iface    = pick_interface()
        local_ip = get_local_ip(iface)
        cidr     = ".".join(local_ip.split(".")[:3]) + ".0/24"
        info(f"Live scanning {cidr}…")
        try:
            pkt      = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
            answered, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
            live_map = {recv.psrc: recv.hwsrc for _, recv in answered}
            section("Cross-Check: ARP Cache vs Live Scan")
            mismatches = 0
            for ip, mac in live_map.items():
                cached = next((e["mac"] for e in entries if e["ip"] == ip), None)
                if cached and cached.lower() != mac.lower():
                    warn(f"Mismatch  {ip}: cache={cached}  live={mac}")
                    log_alert("ARP-TABLE/Live-Mismatch",
                              f"{ip}: cache={cached}, live={mac}", ip, mac)
                    mismatches += 1
            if mismatches == 0:
                ok("ARP cache matches live scan perfectly.")
        except Exception as e:
            err(f"Live scan error: {e}")

    # Export
    print()
    if input(color("  [»] Export ARP table? [y/N]: ",
                   C.YELLOW)).strip().lower() == "y":
        stem   = f"arptable_{datestamp()}"
        report = {"timestamp": stamp(), "entries": entries,
                  "duplicate_macs": {k: v for k, v in dupes.items()}}
        csv_fields = ["ip", "mac", "vendor", "iface", "state"]
        do_export(report, entries, stem, csv_fields)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 4 — PASSIVE TRAFFIC SNIFFER
# ══════════════════════════════════════════════════════════════════════════
def module_sniffer():
    print_header("Passive Traffic Sniffer — Multi-Protocol Capture")
    if not HAVE_SCAPY:
        err("Scapy required."); return
    if os.geteuid() != 0:
        err("Root privileges required."); return

    print()
    iface = pick_interface("Select capture interface")
    if not iface: return

    print()
    print(color("  BPF Filter Examples:", C.DIM))
    examples = [
        ("ARP only",          "arp"),
        ("HTTP traffic",      "tcp port 80 or tcp port 443"),
        ("DNS queries",       "udp port 53"),
        ("Specific host",     "host 192.168.1.1"),
        ("All common",        "arp or tcp or udp"),
        ("ICMP (ping)",       "icmp"),
        ("Non-local only",    "not broadcast and not multicast"),
    ]
    for name, filt in examples:
        print(f"    {color(f'{name:<20}', C.DIM)} {color(filt, C.WHITE)}")
    print()

    bpf_r = input(color("  [»] BPF filter [default: arp or tcp or udp]: ",
                        C.CYAN)).strip()
    bpf   = bpf_r if bpf_r else "arp or tcp or udp"

    count_r = input(color("  [»] Packet limit [0 = infinite, default: 200]: ",
                          C.CYAN)).strip()
    try: count = int(count_r) if count_r else 200
    except: count = 200

    ring_r = input(color("  [»] Ring-buffer max lines [default: 1000]: ",
                         C.CYAN)).strip()
    try: max_ring = int(ring_r) if ring_r else 1000
    except: max_ring = 1000

    section("Sniffer Configuration")
    print(f"    {color('Interface:', C.CYAN)} {color(iface, C.WHITE)}")
    print(f"    {color('Filter   :', C.CYAN)} {color(bpf, C.DIM)}")
    print(f"    {color('Limit    :', C.CYAN)} {color(str(count) if count else 'Infinite', C.WHITE)}")
    print()
    warn("Sniffing — press Ctrl+C to stop.")
    print()
    print(color(f"  {'#':>4}  {'Time':<14} {'Proto':<6} {'Source':<18} "
                f"{'Destination':<18} {'Size':>5}  Info", C.DIM))
    print(color("  " + "─" * 76, C.DIM))

    pkt_log : List[dict] = []
    counter = [0]
    lock    = threading.Lock()
    stats: Dict[str, int] = defaultdict(int)

    def handle_pkt(pkt):
        with lock:
            counter[0] += 1
            n = counter[0]

        ts     = tstamp()
        proto  = "???"
        src = dst = info_s = ""
        p_clr  = C.DIM

        if pkt.haslayer(ARP):
            arp_l  = pkt[ARP]
            proto  = "ARP"
            src    = arp_l.psrc
            dst    = arp_l.pdst
            op_s   = "Reply" if arp_l.op == 2 else "Request"
            hw     = pkt[Ether].src if pkt.haslayer(Ether) else "?"
            info_s = f"{op_s}  {src} @ {hw}"
            p_clr  = C.YELLOW + C.BOLD

        elif pkt.haslayer(IP):
            ip_l = pkt[IP]
            src  = ip_l.src
            dst  = ip_l.dst
            if pkt.haslayer(TCP):
                proto  = "TCP"
                flags  = str(pkt[TCP].flags)
                info_s = f":{pkt[TCP].sport}→:{pkt[TCP].dport} [{flags}]"
                p_clr  = C.CYAN
            elif pkt.haslayer(UDP):
                proto  = "UDP"
                sport  = pkt[UDP].sport
                dport  = pkt[UDP].dport
                info_s = f":{sport}→:{dport}"
                if dport == 53 or sport == 53:
                    proto  = "DNS"
                    p_clr  = C.MAGENTA
                    if pkt.haslayer(DNSQR):
                        try: info_s += f"  Q:{pkt[DNSQR].qname.decode()}"
                        except: pass
                else:
                    p_clr = C.BLUE
            elif pkt.haslayer(ICMP):
                proto  = "ICMP"
                t      = pkt[ICMP].type
                codes  = {0: "Echo-Reply", 8: "Echo-Req", 3: "Dst-Unreach",
                          11: "TTL-Exceed"}
                info_s = codes.get(t, f"type={t}")
                p_clr  = C.MAGENTA
            else:
                proto  = f"IP/{ip_l.proto}"
                p_clr  = C.DIM
        else:
            return

        stats[proto] += 1
        size_s = f"{len(pkt)}B"
        print(f"\r  {color(f'{n:>4}', C.DIM)}  {color(ts, C.DIM)}"
              f"  {color(f'{proto:<6}', p_clr)}"
              f"  {color(f'{src:<18}', C.WHITE)}"
              f"  {color(f'{dst:<18}', C.CYAN)}"
              f"  {color(f'{size_s:>5}', C.DIM)}"
              f"  {color(info_s, C.DIM)}")

        if len(pkt_log) < max_ring:
            pkt_log.append({
                "time": ts, "proto": proto, "src": src,
                "dst": dst, "size": len(pkt), "info": info_s,
            })

    t0 = time.time()
    try:
        kwargs = {"iface": iface, "filter": bpf,
                  "prn": handle_pkt, "store": False}
        if count > 0:
            kwargs["count"] = count
        sniff(**kwargs)
    except KeyboardInterrupt:
        pass

    duration = time.time() - t0
    print()
    section("Capture Summary")
    print(f"    {color('Packets  :', C.CYAN)} {color(str(counter[0]), C.WHITE)}")
    print(f"    {color('Duration :', C.CYAN)} {color(f'{duration:.1f}s', C.DIM)}")
    if stats:
        print(f"    {color('Breakdown:', C.CYAN)} " +
              "  ".join(f"{color(p, C.WHITE)}:{color(str(c), C.DIM)}"
                        for p, c in sorted(stats.items(),
                                           key=lambda x: -x[1])))

    log_session("Sniffer", iface, duration, counter[0], 0,
                {"bpf": bpf, "protocols": dict(stats)})

    # Export
    print()
    if input(color("  [»] Export capture log? [y/N]: ",
                   C.YELLOW)).strip().lower() == "y":
        stem   = f"sniff_{iface}_{datestamp()}"
        report = {
            "timestamp": stamp(), "interface": iface,
            "bpf_filter": bpf, "duration": round(duration, 1),
            "packet_count": counter[0], "protocols": dict(stats),
            "packets": pkt_log,
        }
        csv_fields = ["time", "proto", "src", "dst", "size", "info"]
        do_export(report, pkt_log, stem, csv_fields)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 5 — GATEWAY GUARDIAN
# ══════════════════════════════════════════════════════════════════════════
def module_gateway_guardian():
    print_header("Gateway Guardian — Continuous ARP Watch")
    if not HAVE_SCAPY:
        err("Scapy required."); return
    if os.geteuid() != 0:
        err("Root privileges required."); return

    print()
    local_ip   = get_local_ip()
    default_gw = detect_gateway(local_ip)

    gw_r = input(color(f"  [»] Gateway IP [detected: {default_gw or 'none'}]: ",
                       C.CYAN)).strip()
    gw_ip = gw_r if gw_r else default_gw
    if not gw_ip:
        err("No gateway IP provided."); return

    iface = pick_interface()
    if not iface: return

    interval_r = input(color("  [»] Check interval seconds [default: 5]: ",
                             C.CYAN)).strip()
    try: interval = float(interval_r) if interval_r else 5.0
    except: interval = 5.0

    multi_r = input(color("  [»] Watch additional IPs? (comma-separated, blank=none): ",
                          C.CYAN)).strip()
    extra_ips = [ip.strip() for ip in multi_r.split(",") if ip.strip()] if multi_r else []
    watch_ips = [gw_ip] + extra_ips

    # Probe gateway MAC
    info(f"Probing {gw_ip} for MAC address…")
    try:
        ans = sr1(ARP(pdst=gw_ip), iface=iface, timeout=3, verbose=False)
        if not ans:
            err(f"No ARP response from {gw_ip}. Verify IP."); return
        real_macs = {gw_ip: ans.hwsrc}
        ok(f"Gateway {gw_ip}  →  {color(ans.hwsrc, C.GREEN + C.BOLD)}")
    except Exception as e:
        err(f"ARP probe failed: {e}"); return

    # Probe extra IPs
    for extra_ip in extra_ips:
        try:
            ans2 = sr1(ARP(pdst=extra_ip), iface=iface, timeout=2, verbose=False)
            if ans2:
                real_macs[extra_ip] = ans2.hwsrc
                ok(f"Extra watch {extra_ip}  →  {ans2.hwsrc}")
            else:
                warn(f"No response from {extra_ip}")
        except: pass

    section("Guardian Configuration")
    for watch_ip, mac in real_macs.items():
        gw_tag = color("  [GATEWAY]", C.YELLOW + C.BOLD) if watch_ip == gw_ip else ""
        print(f"    {color(watch_ip, C.WHITE + C.BOLD)}  "
              f"→  {color(mac, C.GREEN + C.BOLD)}{gw_tag}")
    print(f"    {color('Interface :', C.CYAN)} {color(iface, C.WHITE)}")
    print(f"    {color('Interval  :', C.CYAN)} {color(f'{interval}s', C.DIM)}")
    print()
    warn("Guardian active — Ctrl+C to stop.")
    print()

    alerts_found = 0
    check_count  = [0]
    stop_flag    = threading.Event()
    event_log    : List[dict] = []

    def watch(pkt):
        nonlocal alerts_found
        if not (pkt.haslayer(ARP) and pkt[ARP].op == 2):
            return
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        if src_ip not in real_macs:
            return
        expected = real_macs[src_ip]
        if src_mac.lower() != expected.lower():
            alerts_found += 1
            label = "GATEWAY" if src_ip == gw_ip else f"HOST {src_ip}"
            critical(f"{label} MAC CHANGED — POSSIBLE ATTACK",
                     f"Expected: {expected}  |  Received: {src_mac}")
            log_alert("CRITICAL/Guardian-MAC-Changed",
                      f"Expected {expected}, got {src_mac}", src_ip, src_mac)
            event_log.append({
                "time": stamp(), "ip": src_ip,
                "expected_mac": expected, "received_mac": src_mac,
            })

    def status_loop():
        while not stop_flag.is_set():
            check_count[0] += 1
            a_clr = C.RED + C.BOLD if alerts_found > 0 else C.GREEN
            sys.stdout.write(
                f"\r  {color('[»]', C.CYAN)} "
                f"Watching {color(', '.join(watch_ips), C.WHITE)}  |  "
                f"Checks:{color(str(check_count[0]), C.DIM)}  "
                f"Alerts:{color(str(alerts_found), a_clr)}  "
                f"{color('Ctrl+C stop', C.DIM)}   "
            )
            sys.stdout.flush()
            time.sleep(interval)

    stat_t = threading.Thread(target=status_loop, daemon=True)
    stat_t.start()

    t0 = time.time()
    try:
        sniff(iface=iface, filter="arp", prn=watch, store=False,
              stop_filter=lambda p: stop_flag.is_set())
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()

    duration = time.time() - t0
    print()
    section("Guardian Summary")
    print(f"    {color('Duration :', C.CYAN)} {color(f'{duration:.1f}s', C.WHITE)}")
    print(f"    {color('Checks   :', C.CYAN)} {color(str(check_count[0]), C.WHITE)}")
    if alerts_found == 0:
        ok("No MAC changes detected. Network looks clean.")
    else:
        critical(f"{alerts_found} MAC spoofing event(s) detected!")

    log_session("GW-Guardian", iface, duration, check_count[0], alerts_found,
                {"gateway": gw_ip, "watched_hosts": len(real_macs)})

    # Export
    if event_log:
        print()
        if input(color("  [»] Export guardian events? [y/N]: ",
                       C.YELLOW)).strip().lower() == "y":
            stem   = f"guardian_{datestamp()}"
            report = {
                "timestamp": stamp(), "gateway": gw_ip,
                "interface": iface, "duration": round(duration, 1),
                "alerts": alerts_found, "events": event_log,
            }
            csv_fields = ["time", "ip", "expected_mac", "received_mac"]
            do_export(report, event_log, stem, csv_fields)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 6 — FORENSICS & BASELINE
# ══════════════════════════════════════════════════════════════════════════
def module_forensics():
    print_header("Forensics & Baseline Manager")

    while True:
        print()
        print(f"  {color('[1]', C.GREEN)}  View saved baseline")
        print(f"  {color('[2]', C.GREEN)}  Build baseline from current ARP table")
        print(f"  {color('[3]', C.GREEN)}  Compare ARP table with baseline")
        print(f"  {color('[4]', C.GREEN)}  View full alert log  ({ALERTS_FILE})")
        print(f"  {color('[5]', C.GREEN)}  View session history ({HISTORY_FILE})")
        print(f"  {color('[6]', C.GREEN)}  Export all alerts to file")
        print(f"  {color('[7]', C.GREEN)}  Clear alert log")
        print(f"  {color('[8]', C.GREEN)}  Clear session history")
        print(f"  {color('[B]', C.YELLOW)} Back to main menu")
        print()
        choice = input(color("  [»] Option: ", C.CYAN)).strip().upper()

        if choice == "B":
            return

        elif choice == "1":
            bl = load_baseline()
            if not bl:
                err("No baseline saved."); continue
            section(f"Baseline — saved {bl.get('timestamp','?')}  "
                    f"[hash: {bl.get('hash','?')}]")
            devs = bl.get("devices", {})
            print(color(f"    {'IP Address':<20} {'MAC Address':<20} Vendor", C.DIM))
            print(color("  " + "─" * 55, C.DIM))
            for ip, mac in sorted(devs.items()):
                vendor = lookup_oui(mac)
                print(f"    {color(f'{ip:<20}', C.CYAN)}"
                      f"{color(f'{mac:<20}', C.WHITE)}"
                      f"{color(vendor, C.DIM)}")
            print(f"\n  {color(str(len(devs)), C.WHITE)} devices in baseline.")

        elif choice == "2":
            current: dict = {}
            seed_arp_table(current)
            if not current:
                err("ARP table empty — run a scan first."); continue
            save_baseline(current)

        elif choice == "3":
            current: dict = {}
            seed_arp_table(current)
            issues = compare_with_baseline(current)
            if not issues:
                ok("No differences from baseline.")
            else:
                section("Anomalies vs Baseline")
                for iss in issues:
                    warn(f"{iss['ip']}  baseline={iss['baseline_mac']}"
                         f"  current={iss['current_mac']}")

        elif choice == "4":
            _show_alerts()

        elif choice == "5":
            _show_history()

        elif choice == "6":
            if not ALERTS_FILE.exists():
                err("No alerts file."); continue
            try:
                alerts = json.loads(ALERTS_FILE.read_text())
            except: err("Could not read alerts."); continue
            stem   = f"alerts_export_{datestamp()}"
            rows   = alerts
            fields = ["timestamp","type","detail","src_ip","src_mac","risk_score"]
            do_export({"alerts": alerts}, rows, stem, fields)

        elif choice == "7":
            if input(color("  [»] Confirm clear alert log? [yes/N]: ",
                           C.RED)).strip().lower() == "yes":
                try: ALERTS_FILE.unlink()
                except: pass
                ok("Alert log cleared.")

        elif choice == "8":
            if input(color("  [»] Confirm clear history? [yes/N]: ",
                           C.RED)).strip().lower() == "yes":
                try: HISTORY_FILE.unlink()
                except: pass
                ok("Session history cleared.")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 7 — SETTINGS
# ══════════════════════════════════════════════════════════════════════════
def module_settings():
    print_header("Settings & Configuration")
    global CFG

    while True:
        print()
        print(color(f"    {'Key':<28} {'Value'}", C.DIM))
        print(color("  " + "─" * 55, C.DIM))
        keys = list(_DEFAULT_CONFIG.keys())
        for i, k in enumerate(keys):
            val = CFG.get(k, _DEFAULT_CONFIG[k])
            print(f"  {color('['+str(i+1)+']', C.GREEN)}  "
                  f"{color(f'{k:<28}', C.WHITE)}"
                  f"{color(str(val), C.CYAN)}")
        print(f"\n  {color('[S]', C.YELLOW)}  Save   "
              f"{color('[R]', C.ORANGE)}  Reset to defaults   "
              f"{color('[B]', C.RED)}  Back")
        print()
        raw = input(color("  [»] Edit setting # (or S/R/B): ", C.CYAN)).strip().upper()

        if raw == "B":
            return
        elif raw == "S":
            _save_config(CFG)
            ok("Configuration saved.")
        elif raw == "R":
            CFG = dict(_DEFAULT_CONFIG)
            _save_config(CFG)
            ok("Reset to defaults.")
        else:
            try:
                idx = int(raw) - 1
                if 0 <= idx < len(keys):
                    key = keys[idx]
                    cur = CFG.get(key)
                    new_raw = input(color(
                        f"  [»] New value for {key} [{cur}]: ", C.CYAN)).strip()
                    if new_raw:
                        # Type coercion
                        if isinstance(cur, bool):
                            CFG[key] = new_raw.lower() in ("true", "1", "yes")
                        elif isinstance(cur, int):
                            try: CFG[key] = int(new_raw)
                            except: err("Expected integer.")
                        elif isinstance(cur, float):
                            try: CFG[key] = float(new_raw)
                            except: err("Expected float.")
                        else:
                            CFG[key] = new_raw
                        ok(f"{key} = {CFG[key]}")
            except: pass

# ══════════════════════════════════════════════════════════════════════════
# ALERT / HISTORY VIEWERS
# ══════════════════════════════════════════════════════════════════════════
def _show_alerts():
    print_header("Alert History")
    if not ALERTS_FILE.exists():
        err("No alerts recorded."); return
    try:
        alerts = json.loads(ALERTS_FILE.read_text())
    except:
        err("Could not read alerts."); return

    section(f"Alerts — {len(alerts)} total  (showing last 50)")
    print(color(f"    {'Timestamp':<21} {'Type':<32} {'IP':<18} Risk", C.DIM))
    print(color("  " + "─" * 72, C.DIM))
    for e in alerts[-50:]:
        t_clr  = C.RED + C.BOLD if "CRITICAL" in e.get("type", "") else C.ORANGE
        ts     = e.get("timestamp","")[:19]
        typ    = e.get("type","")[:30]
        ip_s   = e.get("src_ip","")[:16]
        score  = e.get("risk_score", 0)
        bar    = risk_bar(score)
        print(f"    {color(ts, C.WHITE)}  {color(f'{typ:<32}', t_clr)}"
              f"{color(f'{ip_s:<18}', C.DIM)}[{bar}]")
    print()

def _show_history():
    print_header("Session History")
    if not HISTORY_FILE.exists():
        err("No history found."); return
    try:
        history = json.loads(HISTORY_FILE.read_text())
    except:
        err("Could not read history."); return

    section(f"Sessions — {len(history)} total  (showing last 25)")
    print(color(f"    {'Timestamp':<21} {'Mode':<16} {'Iface':<10} "
                f"{'Pkts':<8} Alerts", C.DIM))
    print(color("  " + "─" * 64, C.DIM))
    for e in history[-25:]:
        a_clr = C.RED + C.BOLD if e.get("alerts", 0) > 0 else C.DIM
        ts    = e.get("timestamp","")[:19]
        mode  = e.get("mode","")[:14]
        iface = e.get("interface","")[:8]
        pkts  = str(e.get("packets", 0))
        alts  = str(e.get("alerts", 0))
        print(f"    {color(ts, C.WHITE)}  {color(f'{mode:<16}', C.CYAN)}"
              f"{color(f'{iface:<10}', C.DIM)}"
              f"{color(f'{pkts:<8}', C.DIM)}"
              f"{color(alts, a_clr)}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# HELP
# ══════════════════════════════════════════════════════════════════════════
def show_help():
    W = min(_TW, 76)
    B = "║"

    def hline(char="═"):
        print(color("╠" + char * (W-2) + "╣", C.CYAN))

    def row(text="", clr=C.WHITE, indent=2):
        inner  = " " * indent + text
        pad    = max(0, W - 2 - len(inner))
        print(color(B, C.CYAN) + color(inner, clr) + " " * pad + color(B, C.CYAN))

    def section_hdr(title):
        hline("─")
        row(f"  ◈  {title}", C.YELLOW + C.BOLD)
        hline("─")

    print()
    print(color("╔" + "═" * (W-2) + "╗", C.CYAN))
    title_text = f" {TOOL_NAME}  v{VERSION}  —  Help & Usage Guide "
    pad = max(0, W - 2 - len(title_text))
    print(color(B, C.CYAN) +
          color(title_text, C.BOLD + C.WHITE) +
          " " * pad +
          color(B, C.CYAN))
    sub_text  = f"   {WEBSITE}   |   Author: {AUTHOR} "
    pad2 = max(0, W - 2 - len(sub_text))
    print(color(B, C.CYAN) + color(sub_text, C.DIM) + " " * pad2 + color(B, C.CYAN))
    hline()

    section_hdr("DESCRIPTION")
    row("OPoison is a professional ARP spoof & MITM detection toolkit", C.WHITE)
    row("designed for Debian-based systems and OwlOS. It monitors,", C.WHITE)
    row("scans, and forensically analyses Layer 2 network threats.", C.WHITE)
    row()
    row("Requires: root / sudo  +  pip install scapy", C.DIM)

    section_hdr("MODULES")
    modules = [
        ("[1]", "Live Monitor",     "Real-time ARP spoof & MITM detection"),
        ("[2]", "ARP Network Scan", "Discover live hosts, find duplicate MACs"),
        ("[3]", "ARP Table",        "Inspect cache, cross-check, compare baseline"),
        ("[4]", "Traffic Sniffer",  "Passive multi-protocol packet capture"),
        ("[5]", "Gateway Guardian", "Continuous gateway (& host) MAC watch"),
        ("[6]", "Forensics",        "Baseline management, alerts, history"),
        ("[7]", "Settings",         "Tune defaults, paths, intervals, formats"),
    ]
    for num, name, desc in modules:
        row(f"  {num:<5} {name:<22} {desc}", C.WHITE)

    section_hdr("DETECTION ENGINES")
    detections = [
        ("IP-MAC Mismatch",       "Same IP replied by different MAC → ARP spoof"),
        ("Duplicate MAC",         "One MAC claiming multiple IPs → MITM pivot"),
        ("Gateway MAC Change",    "Gateway IP served by rogue MAC → poisoning"),
        ("VM / Tool MAC Prefix",  "Attacker using virtualised or tooled NIC"),
        ("Gratuitous ARP",        "Unsolicited ARP reply → spoof indicator"),
        ("Multi-IP MAC",          "MAC appears for 3+ IPs → proxy / redirector"),
        ("Baseline Deviation",    "Device fingerprint changed vs known-good state"),
    ]
    for name, desc in detections:
        row(f"  • {name:<26} {desc}", C.WHITE)

    section_hdr("RISK SCORE SCALE")
    bands = [
        ("0  – 29",  "LOW",      "Normal traffic — informational only"),
        ("30 – 59",  "MEDIUM",   "Suspicious — investigate immediately"),
        ("60 – 89",  "HIGH",     "Likely attack — isolate host"),
        ("90 – 100", "CRITICAL", "Active attack — act now"),
    ]
    for rng, label, desc in bands:
        lclr = C.GREEN if "LOW" in label else C.YELLOW if "MED" in label \
               else C.ORANGE if "HIGH" in label else C.RED + C.BOLD
        row(f"  {rng:<10}  {label:<10}  {desc}", lclr)

    section_hdr("EXPORT FORMATS")
    formats = [
        ("JSON",          "Structured, human-readable, machine-parseable"),
        ("CSV",           "Spreadsheet-compatible flat table"),
        ("Both",          "JSON + CSV in one operation"),
        ("Gzipped JSON",  "Compressed archive for long-term storage"),
    ]
    for fmt, desc in formats:
        row(f"  {fmt:<16} {desc}", C.WHITE)
    row()
    row(f"  Logs stored in: {str(LOG_DIR)}", C.DIM)
    row(f"  Config file   : {str(CONFIG_FILE)}", C.DIM)
    row(f"  Baseline file : {str(BASELINE_FILE)}", C.DIM)

    section_hdr("COMMAND-LINE FLAGS")
    flags = [
        ("--help",       "Show this help message and exit"),
        ("--version",    "Print version and exit"),
        ("--no-color",   "Disable ANSI colour output"),
        ("--monitor",    "Jump directly to Live Monitor"),
        ("--scan",       "Jump directly to ARP Scan"),
        ("--guardian",   "Jump directly to Gateway Guardian"),
        ("--sniffer",    "Jump directly to Traffic Sniffer"),
    ]
    for flag, desc in flags:
        row(f"  {flag:<18} {desc}", C.WHITE)

    section_hdr("USAGE EXAMPLES")
    examples = [
        ("sudo ./OPoison",           "Launch interactive menu"),
        ("sudo ./OPoison --monitor", "Start monitor directly"),
        ("sudo ./OPoison --scan",    "Start ARP scan directly"),
        ("sudo ./OPoison --no-color","Pipe-friendly mode"),
    ]
    for cmd, desc in examples:
        row(f"  {cmd:<38} {desc}", C.CYAN)

    hline()
    row(f"  OPoison {VERSION}  •  {WEBSITE}  •  MIT License", C.DIM)
    print(color("╚" + "═" * (W-2) + "╝", C.CYAN))
    print()

# ══════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════════════════════════════════
def main_menu():
    while True:
        clear()
        banner()
        print(color("  [1]", C.GREEN)  + color("  Live Monitor       ", C.WHITE) +
              color("─ Real-time ARP spoof & MITM detection",         C.DIM))
        print(color("  [2]", C.GREEN)  + color("  ARP Network Scan   ", C.WHITE) +
              color("─ Discover hosts, detect duplicate MACs",         C.DIM))
        print(color("  [3]", C.GREEN)  + color("  ARP Table          ", C.WHITE) +
              color("─ Inspect & cross-check system ARP cache",        C.DIM))
        print(color("  [4]", C.GREEN)  + color("  Traffic Sniffer    ", C.WHITE) +
              color("─ Passive multi-protocol packet capture",         C.DIM))
        print(color("  [5]", C.GREEN)  + color("  Gateway Guardian   ", C.WHITE) +
              color("─ Continuous watch on gateway & host MACs",       C.DIM))
        print(color("  [6]", C.CYAN)   + color("  Forensics          ", C.WHITE) +
              color("─ Baseline · Alerts · History · Export",          C.DIM))
        print(color("  [7]", C.CYAN)   + color("  Settings           ", C.WHITE) +
              color("─ Configure defaults and preferences",            C.DIM))
        print()
        print(color("  [H]", C.YELLOW) + color("  Help               ", C.WHITE) +
              color("─ Full usage guide with all features",            C.DIM))
        print(color("  [X]", C.RED)    + color("  Exit", C.WHITE))
        print()
        _line()
        print()
        choice = input(color("  [»] Select option: ", C.YELLOW)).strip().upper()

        dispatch = {
            "1": module_monitor,
            "2": module_arp_scan,
            "3": module_arp_table,
            "4": module_sniffer,
            "5": module_gateway_guardian,
            "6": module_forensics,
            "7": module_settings,
        }

        if choice == "X":
            print(color(f"\n  [✔] Goodbye! — {WEBSITE}\n", C.GREEN))
            sys.exit(0)
        elif choice == "H":
            clear(); banner(); show_help(); pause()
        elif choice in dispatch:
            clear()
            fn = dispatch[choice]
            # Forensics & Settings have their own sub-loops
            if choice in ("6", "7"):
                fn()
            else:
                fn(); pause()
        else:
            err("Invalid option. Type H for help.")
            time.sleep(1)


# ══════════════════════════════════════════════════════════════════════════
# SELF-TEST  (offline, sandboxed — no network, no root required)
# ══════════════════════════════════════════════════════════════════════════
def run_self_test() -> int:
    """Validate the detection engine fully offline in a /tmp sandbox.
    Returns process exit code (0 = all passed)."""
    import tempfile
    banner()
    print_header("OPoison Self-Test  (offline / sandboxed)")
    passed = failed = 0
    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; ok(name)
        else:
            failed += 1; err(name)

    # 1) OUI vendor lookup
    check("OUI lookup: VMware prefix", lookup_oui("00:50:56:aa:bb:cc") == "VMware")
    check("OUI lookup: unknown prefix returns ''", lookup_oui("de:ad:be:ef:00:01") == "")
    check("VM MAC detection", is_vm_mac("08:00:27:00:00:01") is True)

    # 2) Risk engine — gateway impersonation should score high
    ipmap = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
    score, reasons = arp_risk_score(ipmap, "192.168.1.1",
                                    "11:22:33:44:55:66", "192.168.1.1")
    check(f"Gateway-spoof risk high (score={score})", score >= 60)
    check("Risk engine returns reasons", len(reasons) > 0)

    # 3) Baseline save/load round-trip in an isolated temp dir
    sandbox = Path(tempfile.mkdtemp(prefix="opoison_selftest_"))
    global BASELINE_FILE
    _orig = BASELINE_FILE
    try:
        BASELINE_FILE = sandbox / "baseline.json"
        devices = {"10.0.0.5": "aa:aa:aa:bb:bb:bb"}
        save_baseline(devices)
        loaded = load_baseline().get("devices", {})
        check("Baseline save/load round-trip", loaded == devices)
        issues = compare_with_baseline({"10.0.0.5": "ff:ff:ff:ff:ff:ff"})
        check("Baseline deviation detected", len(issues) == 1)
    finally:
        BASELINE_FILE = _orig
        try: shutil.rmtree(sandbox, ignore_errors=True)
        except Exception: pass

    print()
    _line()
    if failed == 0:
        ok(f"ALL {passed} CHECKS PASSED — detection engine healthy.")
        return 0
    err(f"{failed} FAILED, {passed} passed.")
    return 1

# ══════════════════════════════════════════════════════════════════════════
# CLI ARGUMENT HANDLING
# ══════════════════════════════════════════════════════════════════════════
def _parse_args():
    ap = argparse.ArgumentParser(
        prog="OPoison",
        description=f"OPoison v{VERSION} — ARP Spoof & MITM Detection Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  Website : {WEBSITE}\n  Author  : {AUTHOR}",
        add_help=False,
    )
    ap.add_argument("--help",     "-h",  action="store_true",
                    help="Show help and exit")
    ap.add_argument("--version",  "-v",  action="store_true",
                    help="Print version and exit")
    ap.add_argument("--no-color",        action="store_true",
                    help="Disable colour output")
    ap.add_argument("--monitor",         action="store_true",
                    help="Launch Live Monitor directly")
    ap.add_argument("--scan",            action="store_true",
                    help="Launch ARP Scan directly")
    ap.add_argument("--sniffer",         action="store_true",
                    help="Launch Traffic Sniffer directly")
    ap.add_argument("--guardian",        action="store_true",
                    help="Launch Gateway Guardian directly")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="Run offline sandboxed self-test and exit")
    return ap.parse_args()

# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════
def main():
    global _NO_COLOR, C

    args = _parse_args()

    if args.no_color:
        # Re-blank all color codes
        for attr in vars(C):
            if not attr.startswith("_"):
                setattr(C, attr, "")

    if args.version:
        print(f"OPoison v{VERSION}  —  {WEBSITE}")
        sys.exit(0)

    if args.help:
        banner()
        show_help()
        sys.exit(0)

    if args.self_test:
        sys.exit(run_self_test())

    # Direct module launch
    if args.monitor:
        clear(); banner(); module_monitor()
        sys.exit(0)
    if args.scan:
        clear(); banner(); module_arp_scan()
        sys.exit(0)
    if args.sniffer:
        clear(); banner(); module_sniffer()
        sys.exit(0)
    if args.guardian:
        clear(); banner(); module_gateway_guardian()
        sys.exit(0)

    # Interactive menu
    main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(color("\n\n  [!] Interrupted — goodbye!\n", C.YELLOW))
        sys.exit(0)
    except PermissionError:
        print(color("\n  [✘] Permission denied — try: sudo ./OPoison\n", C.RED))
        sys.exit(1)
    except Exception as exc:
        print(color(f"\n  [✘] Fatal error: {exc}\n", C.RED))
        import traceback; traceback.print_exc()
        sys.exit(1)

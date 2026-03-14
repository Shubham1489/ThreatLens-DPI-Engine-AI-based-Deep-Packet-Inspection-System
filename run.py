#!/usr/bin/env python3
"""
ThreatLens – Startup Script

Usage:
    python run.py                             # demo mode (works everywhere, no root)
    python run.py --pcap ./capture.pcap       # analyse a PCAP file
    python run.py --interface "Wi-Fi"         # live capture (Windows, run as Admin)
    python run.py --interface eth0            # live capture (Linux/Mac, use sudo)
    python run.py --list-interfaces           # show all available interfaces
    python run.py --port 8080                 # custom port
"""

import argparse
import os
import sys
from pathlib import Path



def list_interfaces():
    """Print all available network interfaces Scapy can see."""
    try:
        npcap_path = r"C:\Windows\System32\Npcap"
        if npcap_path not in os.environ["PATH"]:
            os.environ["PATH"] = npcap_path + ";" + os.environ["PATH"]
        
        from scapy.interfaces import get_if_list, get_working_ifaces
        print("\nAvailable network interfaces:")
        print("─" * 50)
        try:
            working = get_working_ifaces()
            for iface in working:
                name = getattr(iface, "name", str(iface))
                desc = getattr(iface, "description", "")
                ip   = getattr(iface, "ip", "")
                print(f"  {name}")
                if desc and desc != name:
                    print(f"    Description : {desc}")
                if ip:
                    print(f"    IP          : {ip}")
        except Exception:
            for iface in get_if_list():
                print(f"  {iface}")
        print("─" * 50)
        print("\nUse with:  python run.py --interface \"<name above>\"")
        print("Windows:   Run as Administrator for live capture")
        print("Linux/Mac: Use  sudo python run.py --interface <name>")
    except ImportError:
        print("[Error] Scapy not installed. Run: pip install scapy")


def main():
    parser = argparse.ArgumentParser(
        description="ThreatLens – AI Network Threat Detection Platform"
    )
    parser.add_argument("--host",             default="127.0.0.1")
    parser.add_argument("--port",             default=8000, type=int)
    parser.add_argument("--pcap",             default=None,  help="PCAP file to analyse")
    parser.add_argument("--interface",        default=None,  help="Network interface for live capture")
    parser.add_argument("--reload",           action="store_true", help="Dev auto-reload")
    parser.add_argument("--list-interfaces",  action="store_true", help="List interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Pass capture config to FastAPI via env vars
    if args.pcap:
        if not Path(args.pcap).exists():
            print(f"[Error] PCAP file not found: {args.pcap}")
            sys.exit(1)
        os.environ["PCAP_FILE"] = args.pcap
    if args.interface:
        os.environ["CAPTURE_INTERFACE"] = args.interface

    # Determine mode label for banner
    if args.pcap:
        mode = f"PCAP file: {args.pcap}"
    elif args.interface:
        mode = f"Live capture: {args.interface}"
    else:
        mode = "Demo mode (synthetic traffic)"

    print(f"""
╔══════════════════════════════════════════════════════════╗
║         ThreatLens v1.1  –  AI Threat Detection         ║
╠══════════════════════════════════════════════════════════╣
║  Dashboard  :  http://{args.host}:{args.port}
║  API Docs   :  http://{args.host}:{args.port}/docs
║  ML Training:  http://{args.host}:{args.port}/ml-training
║  Mode       :  {mode}
╚══════════════════════════════════════════════════════════╝

  Tip: run  python run.py --list-interfaces  to see capture interfaces
  Press CTRL+C to stop
""")

    import uvicorn
    uvicorn.run(
        "threatlens.api.main:app",
        host      = args.host,
        port      = args.port,
        reload    = args.reload,
        log_level = "info",
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
ThreatLens – Windows Setup Helper
===================================
Run this ONCE on Windows to install all required system dependencies
for live packet capture.

Usage:
    python scripts/windows_setup.py

What it does:
  1. Checks Python version
  2. Installs pip dependencies (requirements.txt)
  3. Detects if Npcap is installed (required for live capture on Windows)
  4. Downloads and launches the Npcap installer if missing
  5. Lists available network interfaces
  6. Tests that ThreatLens can import correctly
"""

import sys
import os
import subprocess
import platform
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def banner(text):
    print(f"\n{'='*55}")
    print(f"  {text}")
    print(f"{'='*55}")

def check(label, ok, hint=""):
    icon = "✓" if ok else "✗"
    print(f"  {icon}  {label}")
    if not ok and hint:
        print(f"       → {hint}")
    return ok

def main():
    print("""
╔══════════════════════════════════════════════════════╗
║       ThreatLens – Windows Setup Helper             ║
╚══════════════════════════════════════════════════════╝
""")

    # ── 1. Python version ─────────────────────────────────────────────────
    banner("Step 1: Python Version")
    major, minor = sys.version_info[:2]
    ok = major == 3 and minor >= 10
    check(
        f"Python {major}.{minor} (need 3.10+)",
        ok,
        hint="Download from https://www.python.org/downloads/"
    )
    if not ok:
        print("\n[!] Please install Python 3.10 or newer, then re-run this script.")
        sys.exit(1)

    # ── 2. Pip dependencies ───────────────────────────────────────────────
    banner("Step 2: Python Packages")
    req_path = PROJECT_ROOT / "requirements.txt"
    print(f"  Installing from {req_path} …")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_path)],
        capture_output=False
    )
    check("pip install completed", result.returncode == 0,
          hint="Check the error output above")

    # ── 3. Npcap / WinPcap ───────────────────────────────────────────────
    banner("Step 3: Npcap (required for live capture)")

    npcap_dll = Path("C:/Windows/System32/Npcap/wpcap.dll")
    winpcap   = Path("C:/Windows/System32/wpcap.dll")
    has_npcap = npcap_dll.exists() or winpcap.exists()

    check(
        "Npcap installed",
        has_npcap,
        hint="Live capture won't work without Npcap"
    )

    if not has_npcap:
        print("""
  Npcap is a free library that allows packet capture on Windows.
  Without it, ThreatLens runs in DEMO MODE only (still works!).

  To enable live capture:
    1. Download Npcap from: https://npcap.com/#download
    2. Run the installer
    3. IMPORTANT: tick "Install Npcap in WinPcap API-compatible Mode"
    4. Restart your computer
    5. Re-run this setup script
""")
        ans = input("  Open the Npcap download page now? [y/N]: ").strip().lower()
        if ans == "y":
            import webbrowser
            webbrowser.open("https://npcap.com/#download")
            print("  Browser opened. Install Npcap, restart PC, then run ThreatLens again.")
    else:
        print("  Npcap found — live capture is available.")

    # ── 4. List interfaces ────────────────────────────────────────────────
    banner("Step 4: Network Interfaces")
    try:
        from scapy.interfaces import get_if_list, get_working_ifaces
        try:
            ifaces = get_working_ifaces()
            print("  Available interfaces for capture:")
            for i, iface in enumerate(ifaces):
                name  = getattr(iface, "name", str(iface))
                desc  = getattr(iface, "description", "")
                ip    = getattr(iface, "ip", "")
                print(f"  [{i+1}] {name}")
                if desc and desc.lower() != name.lower():
                    print(f"       {desc}")
                if ip:
                    print(f"       IP: {ip}")
        except Exception:
            ifaces = get_if_list()
            print("  Interfaces found:")
            for iface in ifaces:
                print(f"    {iface}")
        print()
        print("  To use live capture, run as Administrator:")
        print('    python run.py --interface "Wi-Fi"')
        print('    python run.py --interface "Ethernet"')
    except Exception as e:
        print(f"  Could not list interfaces: {e}")
        if not has_npcap:
            print("  (Install Npcap first, then retry)")

    # ── 5. Import test ────────────────────────────────────────────────────
    banner("Step 5: ThreatLens Import Test")
    sys.path.insert(0, str(PROJECT_ROOT))
    tests = [
        ("threatlens.engine.models",    "ParsedPacket"),
        ("threatlens.engine.sni_extractor", "extract_sni"),
        ("threatlens.engine.rule_manager",  "RuleManager"),
        ("threatlens.ml.classifier",    "MLClassifier"),
        ("threatlens.ml.auto_train",    "AutoTrainEngine"),
        ("fastapi",                     "FastAPI"),
        ("uvicorn",                     None),
        ("scapy.layers.l2",             "Ether"),
    ]
    all_ok = True
    for module, attr in tests:
        try:
            m = __import__(module, fromlist=[attr] if attr else [])
            if attr:
                getattr(m, attr)
            check(f"import {module}", True)
        except Exception as e:
            check(f"import {module}", False, hint=str(e))
            all_ok = False

    # ── Summary ───────────────────────────────────────────────────────────
    banner("Summary")
    if all_ok:
        print("""  ✓ All checks passed!

  Start ThreatLens:
    python run.py

  Open dashboard:
    http://127.0.0.1:8000

  For live capture (run CMD / PowerShell as Administrator):
    python run.py --list-interfaces
    python run.py --interface "Wi-Fi"
""")
    else:
        print("""  Some checks failed. Fix the errors above, then re-run:
    python scripts/windows_setup.py
""")


if __name__ == "__main__":
    main()

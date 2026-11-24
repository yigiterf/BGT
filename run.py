#!/usr/bin/env python3
"""MiniFirewall Lab giris noktasi.

    python3 run.py                 # web arayuzu (http://localhost:8080)
    python3 run.py demo            # terminal demosu
    python3 run.py pcap demo/capture.pcap
    python3 run.py trace --src 198.51.100.66 --dst 10.0.0.20 --dport 22
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from minifirewall.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

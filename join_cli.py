#!/usr/bin/env python3
"""
Zero-Trust P2P Network — Client Node Launcher
Connects an independent terminal node directly to an active host or swarm.
"""

import sys
import os
import argparse

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from start_node import main as start_main

if __name__ == "__main__":
    start_main()

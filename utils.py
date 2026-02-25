#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modulo condiviso: utilities per gli script di analisi NethServer 8 / NethVoice
"""

import os
import sys
import re
import subprocess
from datetime import datetime

# --- Colors (ANSI) ---
class Colors:
    HEADER = '\033[1;34m' # Blue
    OKGREEN = '\033[1;32m' # Green
    WARNING = '\033[1;33m' # Yellow
    FAIL = '\033[1;31m' # Red
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Regex to strip ANSI codes when writing to log file
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Global log file path (set by each script)
_log_file = None

def init_log(filename):
    """Imposta il file di log globale."""
    global _log_file
    _log_file = filename

def log(text, color=None, skip_newline=False):
    """Prints to console with color and saves plain text to log file."""
    plain_text = ansi_escape.sub('', text)
    if _log_file:
        with open(_log_file, 'a', encoding='utf-8') as f:
            f.write(plain_text + ('' if skip_newline else '\n'))

    if color:
        print(f"{color}{text}{Colors.ENDC}", end='' if skip_newline else '\n')
    else:
        print(text, end='' if skip_newline else '\n')

def run_cmd(cmd, shell=False):
    """Runs a shell command and returns output as string, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.stdout.strip()
    except Exception:
        return ""

def create_bar(percentage, length=20):
    """Creates a visually appealing progress bar."""
    filled = int(percentage * length / 100)
    bar = "█" * filled + "░" * (length - filled)

    color = Colors.OKGREEN
    if percentage > 75:
        color = Colors.WARNING
    if percentage > 90:
        color = Colors.FAIL

    return f"{bar} {color}{percentage}%{Colors.ENDC}"

def print_section(title):
    log("\n" + "═" * 80, Colors.HEADER)
    log(f" ⯈ {title}", Colors.HEADER)
    log("═" * 80 + "\n", Colors.HEADER)

def dp(key, val, color=Colors.OKGREEN, extra=""):
    """Displays a key-value property prominently."""
    log(f"{Colors.WARNING}{key}: {color}{val} {Colors.ENDC}{extra}")

def check_root():
    if os.geteuid() != 0:
        log("Root required to execute this script.", Colors.FAIL)
        sys.exit(1)

def get_nethvoice_instances():
    """Recupera la lista delle istanze NethVoice attive (esclusi i proxy)."""
    raw = run_cmd("loginctl list-users | grep nethvoice | awk '{print $2}'", shell=True)
    return [i for i in raw.split('\n') if i and not i.startswith("nethvoice-proxy")]

def get_proxy_instances():
    """Recupera la lista dei moduli proxy attivi."""
    raw = run_cmd("loginctl list-users | grep nethvoice-proxy | awk '{print $2}'", shell=True)
    return [p for p in raw.split('\n') if p]

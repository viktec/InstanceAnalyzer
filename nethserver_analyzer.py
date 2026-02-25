#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nethesis Analyzer NS8 + NethVoice - Python Edition
Advanced analyzer script for NethServer 8 + NethVoice
"""

import os
import sys
import time
import subprocess
import re
from datetime import datetime
import json

# --- Config & Setup ---

SCRIPTNAME = "Nethesis Analyzer NS8 + NethVoice"
VERSION = "4.0 (Python Edition)"
ADV = (
    "This script should be used for analisys on NethServer 8 installations purposes only. "
    "Any misuse of this software will not be the responsibility of the author or of any other collaborator. "
    "Use it at your own computers and/or with the computer owner's permission."
)

OUTPUT_FILE = f"analisi_avanzata_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# --- Colors (ANSI) ---
class Colors:
    HEADER = '\033[1;34m' # Blue
    OKGREEN = '\033[1;32m' # Green
    WARNING = '\033[1;33m' # Yellow
    FAIL = '\033[1;31m' # Red
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- Helpers ---

# Regex to strip ANSI codes when writing to log file
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def log(text, color=None, skip_newline=False):
    """Prints to console with color and saves plain text to log file."""
    # Write to file without colors
    plain_text = ansi_escape.sub('', text)
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        f.write(plain_text + ('' if skip_newline else '\n'))
    
    # Print to console with colors
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
    except Exception as e:
        return ""

def create_bar(percentage, length=20):
    """Creates a visually appealing progress bar."""
    filled = int(percentage * length / 100)
    bar = "█" * filled + "░" * (length - filled)
    
    # Color logic for the percentage text
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

# --- Requirement Checks ---

def check_root():
    if os.geteuid() != 0:
        log("Root required to execute this script.", Colors.FAIL)
        sys.exit(1)

check_root()

# --- 0. Header & Init ---

log(f"{Colors.HEADER}======================================================{Colors.ENDC}")
log(f"{Colors.HEADER}{SCRIPTNAME} {VERSION}{Colors.ENDC}")
log(f"{Colors.WARNING}ADVISORY: {ADV}{Colors.ENDC}")
log(f"{Colors.HEADER}======================================================{Colors.ENDC}")
log(f"Analisi di Primo Livello - {datetime.now()}")
log(f"Log salvati in: {OUTPUT_FILE}\n")

# --- 1. General System Info ---
print_section("General Data")

hostname = run_cmd("hostname -f", shell=True)
ips = run_cmd("hostname -I", shell=True)
dns = run_cmd("cat /etc/resolv.conf | grep nameserver | tr -d [a-z] | tr '\n' ','", shell=True).strip(',')
internet = "OK" if "transmitted" in run_cmd("ping -qc 1 sos.nethesis.it", shell=True) else "FAILED"
open_files_raw = run_cmd("cat /proc/sys/fs/file-nr", shell=True).split()
open_files = int(open_files_raw[0]) - int(open_files_raw[1]) if open_files_raw else "N/A"
root_fs = run_cmd("df -h | grep '/$'", shell=True).split()
uptime = run_cmd("uptime -p", shell=True)
timezone = run_cmd("timedatectl | grep 'Time zone'", shell=True).replace("Time zone:", "").strip()

dp("DomainName", hostname)
dp("IP(s)", ips)
dp("DNS", dns)
dp("Internet", internet, Colors.OKGREEN if internet == "OK" else Colors.FAIL)
dp("Open Files", open_files)
dp("Root filesystem", f"{root_fs[3]} free / {root_fs[1]} total" if len(root_fs) > 3 else "N/A")
dp("Uptime", uptime)
dp("TimeZone", timezone)

# --- 2. System Resources (Root) ---
print_section("1. Risorse del Sistema (Root)")

# CPU
try:
    cpu_idle = float(run_cmd("stdbuf -oL top -b -n 1 | grep 'Cpu(s)' | awk '{print $8}'", shell=True).split('.')[0])
    cpu_usage = int(100 - cpu_idle)
except:
    cpu_usage = 0
log(f"CPU : {create_bar(cpu_usage)}")

# RAM
try:
    free_output = run_cmd("free -m", shell=True).split('\n')[1].split()
    mem_total = int(free_output[1])
    mem_used = int(free_output[2])
    mem_usage = int((mem_used / mem_total) * 100)
except:
    mem_usage = 0
log(f"RAM : {create_bar(mem_usage)}")

# Disk
try:
    disk_usage = int(run_cmd("df / | awk 'NR==2 {print $5}' | sed 's/%//'", shell=True))
except:
    disk_usage = 0
log(f"Disk: {create_bar(disk_usage)}")
log("\nTop 5 processi per utilizzo CPU:")
top_procs = run_cmd("stdbuf -oL top -b -n 1 | head -n 12 | tail -n 6", shell=True)
log(top_procs)

# --- 3. NethVoice Instances ---
print_section("2. Verifica Istanze NethVoice")

istances_raw = run_cmd("loginctl list-users | grep nethvoice | awk '{print $2}'", shell=True)
istances = [i for i in istances_raw.split('\n') if i and i != "nethvoice-proxy"]

if not istances:
    log("Nessuna istanza di NethVoice trovata.", Colors.WARNING)
else:
    # --- Chiediamo all'utente quale istanza analizzare --- 
    log("\nIstanze trovate nel sistema:", Colors.HEADER)
    for idx, inst in enumerate(istances):
        log(f"  [{idx + 1}] {inst}")
    log(f"  [A] Analizza TUTTE le istanze")
    
    # Prendi la prima istanza come esempio per il prompt (se esiste)
    esempio = istances[0] if istances else "nethvoice1"
    scelta = input(f"\n{Colors.WARNING}Quale istanza vuoi analizzare? (Inserisci il numero, es. '1' per {esempio}, oppure 'A' per tutte): {Colors.ENDC}").strip().lower()
    
    istanze_selezionate = []
    if scelta == 'a' or scelta == 'all':
        istanze_selezionate = istances
    else:
        try:
            indice = int(scelta) - 1
            if 0 <= indice < len(istances):
                istanze_selezionate = [istances[indice]]
            else:
                log("Selezione non valida. Analizzo tutte le istanze per default.", Colors.FAIL)
                istanze_selezionate = istances
        except ValueError:
            log("Input non riconosciuto. Analizzo tutte le istanze per default.", Colors.FAIL)
            istanze_selezionate = istances

    for istanza in istanze_selezionate:
        log(f"\n[{Colors.HEADER}+++ Analisi Istanza: {istanza} +++{Colors.ENDC}]")
        
        # CPU/RAM in container
        try:
            podman_top = run_cmd(f"runagent -m {istanza} -- podman exec -it freepbx bash -c \"top -b -n 1\"", shell=True)
            cpu_idle_pod = float(re.search(r'id,.*?(\d+\.\d+) id', podman_top.replace('\n',' ')).group(1) if re.search(r'id,.*?(\d+\.\d+) id', podman_top.replace('\n',' ')) else 100)
            cpu_usage_pod = int(100 - cpu_idle_pod)
        except:
            cpu_usage_pod = 0
            
        try:
            podman_free = run_cmd(f"runagent -m {istanza} -- podman exec -it freepbx free -m", shell=True).split('\n')[1].split()
            mem_tot_pod = int(podman_free[1])
            mem_use_pod = int(podman_free[2])
            mem_usage_pod = int((mem_use_pod / mem_tot_pod) * 100)
        except:
            mem_usage_pod = 0
            
        log(f"CPU ({istanza}): {create_bar(cpu_usage_pod)}")
        log(f"RAM ({istanza}): {create_bar(mem_usage_pod)}")
        
        # Asterisk PJSIP Checks
        log("\n[PJSIP Registrations]", Colors.WARNING)
        registrations = run_cmd(f"runagent -m {istanza} -- podman exec -it freepbx asterisk -rx 'pjsip show registrations'", shell=True)
        log(registrations)

        log("\n[PJSIP Contacts]", Colors.WARNING)
        contacts = run_cmd(f"runagent -m {istanza} -- podman exec -it freepbx asterisk -rx 'pjsip show contacts'", shell=True)
        log(contacts)
        
        # API Server Logs Analysis
        log("\n[Analisi Log Sistema (API Server - Ultimi 200 eventi)]", Colors.WARNING)
        log("Ricerca di errori, warning o fallimenti...", Colors.HEADER)
        logs_out = run_cmd(f"api-server-logs logs -m dump -e module -n {istanza} -l 200", shell=True)
        
        issues_found = 0
        for line in logs_out.split('\n'):
            line_upper = line.upper()
            if 'ERROR' in line_upper or 'FAIL' in line_upper:
                log(line, Colors.FAIL)
                issues_found += 1
            elif 'WARN' in line_upper:
                log(line, Colors.WARNING)
                issues_found += 1
                
        if issues_found == 0:
            log("Nessun errore o warning critico trovato negli ultimi 200 log.", Colors.OKGREEN)
        else:
            log(f"Trovati {issues_found} log interessanti (Errori o Warning).", Colors.WARNING)

# --- 4. Network Connectivity ---
print_section("3. Connettività di Rete (Root)")

has_traceroute = run_cmd("command -v traceroute", shell=True)
if not has_traceroute:
    log("Traceroute non è installato. Installazione in corso...", Colors.WARNING)
    run_cmd("dnf install traceroute -y", shell=True)
    log("Traceroute installato.", Colors.OKGREEN)

log("Ping 8.8.8.8:")
ping_out = run_cmd("ping -c 4 8.8.8.8", shell=True)
log(ping_out)

log("\nTraceroute 8.8.8.8:")
tr_out = run_cmd("traceroute 8.8.8.8", shell=True)
log(tr_out)

print_section("Analisi Completata")
log(f"I risultati principali sono stati salvati nel file: {OUTPUT_FILE}", Colors.OKGREEN)

# --- 5. Live Call Analyzer (Interactive) ---
print_section("4. Advanced: Live Call Analysis")

while True:
    choice = input(f"{Colors.WARNING}Vuoi analizzare le chiamate in tempo reale? (y/n) {Colors.ENDC}").strip().lower()
    if choice in ['y', 'n']:
        break

if choice == 'y':
    log("\n[Avvio Analisi Live...]", Colors.HEADER)
    
    log("\nIstanze analizzate in precedenza (suggerite):", Colors.HEADER)
    # Mostriamo solo quelle selezionate all'inizio
    if 'istanze_selezionate' in locals() and istanze_selezionate:
        for idx, inst in enumerate(istanze_selezionate):
            log(f"  - {inst}", Colors.OKGREEN)
    else:
        log("  (Nessuna)", Colors.WARNING)
        
    log("\nTutte le istanze NethVoice disponibili sul sistema:", Colors.HEADER)
    for inst in istances:
        log(f"  - {inst}", Colors.OKGREEN)
        
    target_instance = input(f"\n{Colors.WARNING}Inserisci il nome dell'istanza da analizzare per il traffico (es. nethvoice1): {Colors.ENDC}").strip()
    
    if target_instance not in istances:
        log(f"Attenzione: l'istanza '{target_instance}' non sembra attiva o corretta. L'analisi potrebbe fallire.", Colors.FAIL)

    is_tls = input(f"\n{Colors.WARNING}Il traffico usa TLS/SIPS? (y/n) {Colors.ENDC}").strip().lower() == 'y'
    proxy_instance = ""
    if is_tls:
        log("\nModuli Proxy disponibili sul sistema:", Colors.HEADER)
        # Recupera la lista dei proxy (prima avevamo scartato "nethvoice-proxyX" dalla lista istances)
        proxy_raw = run_cmd("loginctl list-users | grep nethvoice-proxy | awk '{print $2}'", shell=True)
        proxies = [p for p in proxy_raw.split('\n') if p]
        
        if proxies:
            for p in proxies:
                log(f"  - {p}", Colors.OKGREEN)
        else:
            log("  (Nessun proxy trovato in esecuzione)", Colors.WARNING)
        
        proxy_instance = input(f"\n{Colors.WARNING}Inserisci il nome del proxy per abilitare siptrace (es. nethvoice-proxy2): {Colors.ENDC}").strip()
    
    try:
        duration = int(input(f"{Colors.WARNING}Per quanti secondi vuoi restare in ascolto? (es. 60): {Colors.ENDC}").strip())
    except:
        duration = 60
        log("Valore non valido. Utilizzo 60 secondi come default.", Colors.FAIL)
        
    sngrep_file = f"capture_{target_instance}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    ast_file = f"asterisk_{target_instance}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    
    # 1. Check and install capture tools
    log("\nVerifica presenza sngrep/tcpdump...", Colors.OKGREEN)
    if not run_cmd("command -v sngrep", shell=True):
        log("sngrep non trovato. Installazione in corso...", Colors.WARNING)
        run_cmd("dnf -y install http://repo.okay.com.mx/centos/9/x86_64/release/sngrep-1.6.0-1.el9.x86_64.rpm strace vim", shell=True)
    if is_tls and not run_cmd("command -v tcpdump", shell=True):
        log("tcpdump non trovato. Installazione in corso...", Colors.WARNING)
        run_cmd("dnf -y install tcpdump", shell=True)
        
    log("Tool di cattura pronti.", Colors.OKGREEN)
        
    # 2. Start captures
    log(f"\nAvvio ascolto su {target_instance} per {duration} secondi...", Colors.HEADER)
    log("Ti suggerisco di EVOCARE ORA LA CHIAMATA PROBLEMATICA.", Colors.FAIL)
    
    # SIP CAPTURE
    capture_proc_name = "sngrep"
    if is_tls and proxy_instance:
        log("Configurazione log TLS su proxy e cattura HEP con tcpdump...", Colors.WARNING)
        # Abilita su kamailio
        run_cmd(f"runagent -m {proxy_instance} kamcmd siptrace.status on", shell=True)
        
        # In TLS riceviamo pacchetti HEP su loopback (5065). SNGREP non salva i pcap da socket UDP nativi, quindi usiamo tcpdump.
        # Il file PCAP risultante conterrà i pacchetti UDP HEP decodificabili da Wireshark.
        sngrep_cmd = f"tcpdump -i any -s 0 udp port 5065 -w {sngrep_file}"
        capture_proc_name = "tcpdump"
    else:
        sngrep_cmd = f"sngrep -r -d any -N -O {sngrep_file}"
        
    sngrep_proc = subprocess.Popen(sngrep_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # ASTERISK LOGS (in background redigenti in file)
    ast_cmd = f"runagent -m {target_instance} -- podman exec -it freepbx asterisk -rvvvvvv > {ast_file} 2>&1"
    ast_proc = subprocess.Popen(ast_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 3. Wait with visual progress bar
    log("")
    for i in range(duration):
        progress = int((i+1) / duration * 100)
        sys.stdout.write(f"\rIn ascolto: {create_bar(progress, length=40)}")
        sys.stdout.flush()
        time.sleep(1)
    
    print("\n")
    log("Termine ascolto in corso, finalizzazione dei log...", Colors.WARNING)
    
    # 4. Stop captures gracefully to allow PCAP flushing
    run_cmd(f"pkill -INT {capture_proc_name}", shell=True)
    time.sleep(1.5) # Give it time to flush the .pcap file
    # Ensure terminal is restored correctly (fix staircase effect)
    run_cmd("stty sane", shell=True)
    print("\r", end="")

    # Pkill asterisk console sessions safely
    run_cmd(f"runagent -m {target_instance} -- podman exec -it freepbx pkill -9 -f 'asterisk -r'", shell=True)
    
    if is_tls and proxy_instance:
        # Disable siptrace
        run_cmd(f"runagent -m {proxy_instance} kamcmd siptrace.status off", shell=True)
        

    log("\n[Cattura Completata con Successo!]", Colors.OKGREEN)
    
    # Get file sizes to reassure the user
    ast_size = f"{os.path.getsize(ast_file)/1024:.1f} KB" if os.path.exists(ast_file) else "0 KB"
    sngrep_size = f"{os.path.getsize(sngrep_file)/1024:.1f} KB" if os.path.exists(sngrep_file) else "0 KB"
    
    log(f"  - Dump Asterisk: {ast_file} ({ast_size})")
    log(f"  - Dump SNGREP (SIP/HEP): {sngrep_file} ({sngrep_size})")
    log("Puoi trasferire questi file aprendo WinSCP oppure copiarli dal terminale.\n", Colors.HEADER)
    
    if is_tls:
        log("NOTA BENE PER I FILE TLS (PROXY):", Colors.WARNING)
        log("I log catturati in modalità proxy TLS sono decodificati ma incapsulati in pacchetti HEP sulle porte UDP/5065.")
        log("SNGREP *NON PUÒ* LEGGERE OFFLINE I PACCHETTI HEP DA FILE .PCAP CON IL COMANDO 'sngrep -I'!!", Colors.FAIL)
        log("Per vedere il contenuto di questo file pcap scaricalo sul PC e aprilo con **Wireshark** (Tasto destro su un pacchetto -> Decode As -> HEP).", Colors.WARNING)
        log("")
    
else:
    log("\nAnalisi realtime saltata come da richiesta.", Colors.OKGREEN)

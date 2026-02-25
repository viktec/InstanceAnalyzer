#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nethesis Analyzer NS8 + NethVoice - Analisi Sistema e Container
Analizza risorse di sistema, istanze NethVoice, PJSIP e log.
"""

import re
from datetime import datetime
from utils import *

# --- Config ---
SCRIPTNAME = "Nethesis Analyzer NS8 + NethVoice"
VERSION = "5.0"
ADV = (
    "This script should be used for analisys on NethServer 8 installations purposes only. "
    "Any misuse of this software will not be the responsibility of the author or of any other collaborator. "
    "Use it at your own computers and/or with the computer owner's permission."
)

OUTPUT_FILE = f"analisi_avanzata_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
init_log(OUTPUT_FILE)

# --- Root Check ---
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

istances = get_nethvoice_instances()

if not istances:
    log("Nessuna istanza di NethVoice trovata.", Colors.WARNING)
else:
    # --- Chiediamo all'utente quale istanza analizzare ---
    log("\nIstanze trovate nel sistema:", Colors.HEADER)
    for idx, inst in enumerate(istances):
        log(f"  [{idx + 1}] {inst}")
    log(f"  [A] Analizza TUTTE le istanze")

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
log(f"I risultati sono stati salvati nel file: {OUTPUT_FILE}", Colors.OKGREEN)

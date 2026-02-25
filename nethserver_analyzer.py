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
import socket
import struct
import threading
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

    # 1. Check and install sngrep (only needed for non-TLS)
    if not is_tls:
        log("\nVerifica presenza sngrep...", Colors.OKGREEN)
        if not run_cmd("command -v sngrep", shell=True):
            log("sngrep non trovato. Installazione in corso...", Colors.WARNING)
            run_cmd("dnf -y install http://repo.okay.com.mx/centos/9/x86_64/release/sngrep-1.6.0-1.el9.x86_64.rpm strace vim", shell=True)
        log("Tool di cattura pronti.", Colors.OKGREEN)

    # 2. Start captures
    log(f"\nAvvio ascolto su {target_instance} per {duration} secondi...", Colors.HEADER)
    log("Ti suggerisco di EVOCARE ORA LA CHIAMATA PROBLEMATICA.", Colors.FAIL)

    # --- SIP CAPTURE ---
    stop_event = threading.Event()
    hep_thread = None

    if is_tls and proxy_instance:
        log("Configurazione cattura TLS via HEP decoder Python nativo...", Colors.WARNING)
        # Abilita siptrace su kamailio proxy
        run_cmd(f"runagent -m {proxy_instance} kamcmd siptrace.status on", shell=True)

        # Funzione di cattura HEP -> PCAP pulito (gira in un thread)
        def capture_hep_to_pcap(output_file, stop_evt):
            """Ascolta sulla porta UDP 5065 i pacchetti HEP di Kamailio,
            li decodifica (HEPv2/v3) ed estrae il payload SIP puro,
            scrivendolo in un file PCAP standard leggibile da Wireshark e sngrep."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', 5065))
                sock.settimeout(1.0)
            except Exception:
                return

            debug_file = output_file.replace('.pcap', '_debug.txt')
            pkt_count = 0
            SIP_METHODS = [b'INVITE', b'REGISTER', b'OPTIONS', b'ACK', b'BYE',
                           b'CANCEL', b'SIP/2.0', b'SUBSCRIBE', b'NOTIFY',
                           b'PUBLISH', b'MESSAGE', b'INFO', b'REFER', b'UPDATE', b'PRACK']

            with open(output_file, 'wb') as f, open(debug_file, 'w') as dbg:
                # PCAP Global Header (link type 1 = Ethernet)
                f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                # Fake Ethernet header: dst_mac(6) + src_mac(6) + ethertype IPv4(2) = 14 bytes
                eth_hdr = b'\x00\x00\x00\x00\x00\x00' b'\x00\x00\x00\x00\x00\x00' b'\x08\x00'

                while not stop_evt.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                        if len(data) < 6:
                            continue

                        src_ip = b'\x00\x00\x00\x00'
                        dst_ip = b'\x00\x00\x00\x00'
                        sport = 5060
                        dport = 5060
                        sip_payload = b''
                        proto = 17  # UDP
                        detected_ver = "UNKNOWN"

                        # --- HEPv3 (chunk-based, header "HEP3") ---
                        if data[:4] == b'HEP3':
                            detected_ver = "HEPv3"
                            pos = 6
                            while pos + 6 <= len(data):
                                ch_vendor = struct.unpack('!H', data[pos:pos+2])[0]
                                ch_type   = struct.unpack('!H', data[pos+2:pos+4])[0]
                                ch_len    = struct.unpack('!H', data[pos+4:pos+6])[0]
                                if ch_len < 6 or pos + ch_len > len(data):
                                    break
                                ch_data = data[pos+6:pos+ch_len]
                                if ch_vendor == 0:
                                    if   ch_type == 3  and len(ch_data) >= 4: src_ip = ch_data[:4]
                                    elif ch_type == 4  and len(ch_data) >= 4: dst_ip = ch_data[:4]
                                    elif ch_type == 7  and len(ch_data) >= 2: sport  = struct.unpack('!H', ch_data[:2])[0]
                                    elif ch_type == 8  and len(ch_data) >= 2: dport  = struct.unpack('!H', ch_data[:2])[0]
                                    elif ch_type == 15: sip_payload = ch_data
                                pos += ch_len

                        # --- HEPv1 / HEPv2 ---
                        elif data[0] in (1, 2):
                            detected_ver = f"HEPv{data[0]}"
                            hdr_len = data[1]  # Base header length (tipicamente 16)
                            if hdr_len > len(data):
                                continue
                            sport = struct.unpack('!H', data[4:6])[0]
                            dport = struct.unpack('!H', data[6:8])[0]
                            if data[2] == 2 and hdr_len >= 16:  # IPv4
                                src_ip = data[8:12]
                                dst_ip = data[12:16]
                            # HEPv2 ha una timestamp extension header di 12 byte dopo il base header:
                            # tv_sec(4) + tv_usec(4) + captid(4) = 12 bytes
                            if data[0] == 2:
                                sip_payload = data[hdr_len + 12:]
                            else:
                                sip_payload = data[hdr_len:]

                        # --- Fallback: forse è SIP puro senza HEP ---
                        else:
                            for method in SIP_METHODS:
                                if data.lstrip(b'\x00').startswith(method):
                                    detected_ver = "RAW_SIP"
                                    sip_payload = data.lstrip(b'\x00')
                                    break

                        # Debug: log dei primi 10 pacchetti
                        if pkt_count < 10:
                            dbg.write(f"=== PKT #{pkt_count+1} from {addr}, {len(data)} bytes, detected: {detected_ver} ===\n")
                            dbg.write(f"Raw first 80 bytes (hex): {data[:80].hex()}\n")
                            try:
                                dbg.write(f"Raw first 80 bytes (ascii): {data[:80].decode('ascii', errors='replace')}\n")
                            except:
                                dbg.write(f"Raw first 80 bytes (ascii): <decode error>\n")
                            if sip_payload:
                                dbg.write(f"SIP payload len: {len(sip_payload)}\n")
                                try:
                                    dbg.write(f"SIP first 200 chars: {sip_payload[:200].decode('ascii', errors='replace')}\n")
                                except:
                                    dbg.write(f"SIP payload hex: {sip_payload[:100].hex()}\n")
                            else:
                                dbg.write("SIP payload: EMPTY!\n")
                            dbg.write(f"Extracted: src={socket.inet_ntoa(src_ip)}:{sport} -> dst={socket.inet_ntoa(dst_ip)}:{dport}\n\n")
                            dbg.flush()

                        if not sip_payload:
                            continue

                        # Strip any trailing null bytes dal payload SIP
                        sip_payload = sip_payload.rstrip(b'\x00')
                        if not sip_payload:
                            continue

                        pkt_count += 1

                        # Costruiamo un pacchetto Ethernet+IP+UDP con il payload SIP reale
                        udp_len = 8 + len(sip_payload)
                        udp_hdr = struct.pack('!HHHH', sport, dport, udp_len, 0)
                        ip_total = 20 + udp_len
                        ip_hdr_raw = struct.pack('!BBHHHBBH4s4s',
                            0x45, 0, ip_total, 0, 0x4000, 64, proto, 0, src_ip, dst_ip)
                        # Calcola IP checksum
                        chksum = 0
                        for i in range(0, 20, 2):
                            chksum += (ip_hdr_raw[i] << 8) + ip_hdr_raw[i+1]
                        chksum = (chksum >> 16) + (chksum & 0xFFFF)
                        chksum = ~chksum & 0xFFFF
                        ip_hdr = ip_hdr_raw[:10] + struct.pack('!H', chksum) + ip_hdr_raw[12:]

                        packet = eth_hdr + ip_hdr + udp_hdr + sip_payload

                        # PCAP Packet Record
                        ts = time.time()
                        ts_sec = int(ts)
                        ts_usec = int((ts - ts_sec) * 1000000)
                        f.write(struct.pack('<IIII', ts_sec, ts_usec, len(packet), len(packet)))
                        f.write(packet)
                        f.flush()

                    except socket.timeout:
                        continue
                    except Exception:
                        continue

                dbg.write(f"\n=== TOTALE PACCHETTI SCRITTI: {pkt_count} ===\n")
            sock.close()

        # Avvia il decoder HEP in un thread separato
        hep_thread = threading.Thread(target=capture_hep_to_pcap, args=(sngrep_file, stop_event), daemon=True)
        hep_thread.start()
        log("Decoder HEP Python avviato su 127.0.0.1:5065", Colors.OKGREEN)
    else:
        # Non-TLS: usa sngrep classico
        sngrep_cmd = f"sngrep -r -d any -N -O {sngrep_file}"
        sngrep_proc = subprocess.Popen(sngrep_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ASTERISK LOGS (in background)
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

    # 4. Stop captures
    if is_tls and proxy_instance:
        # Ferma il thread HEP
        stop_event.set()
        if hep_thread:
            hep_thread.join(timeout=3)
        # Disabilita siptrace su kamailio
        run_cmd(f"runagent -m {proxy_instance} kamcmd siptrace.status off", shell=True)
    else:
        # Ferma sngrep
        run_cmd("pkill -INT sngrep", shell=True)
        time.sleep(1.5)

    # Restore terminal
    run_cmd("stty sane", shell=True)
    print("\r", end="")

    # Pkill asterisk console sessions safely
    run_cmd(f"runagent -m {target_instance} -- podman exec -it freepbx pkill -9 -f 'asterisk -r'", shell=True)

    log("\n[Cattura Completata con Successo!]", Colors.OKGREEN)

    # Get file sizes
    ast_size = f"{os.path.getsize(ast_file)/1024:.1f} KB" if os.path.exists(ast_file) else "0 KB"
    sngrep_size = f"{os.path.getsize(sngrep_file)/1024:.1f} KB" if os.path.exists(sngrep_file) else "0 KB"

    log(f"  - Dump Asterisk: {ast_file} ({ast_size})")
    log(f"  - Dump SIP: {sngrep_file} ({sngrep_size})")
    log("Puoi trasferire questi file aprendo WinSCP oppure copiarli dal terminale.", Colors.HEADER)

    if is_tls:
        log("\nIl file PCAP TLS è stato decodificato automaticamente dal nostro decoder HEP.", Colors.OKGREEN)
        log("Puoi aprirlo direttamente con Wireshark o con 'sngrep -I <file.pcap>' e vedrai il traffico SIP in chiaro!\n", Colors.OKGREEN)

else:
    log("\nAnalisi realtime saltata come da richiesta.", Colors.OKGREEN)

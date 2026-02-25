#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NethVoice Call Analyzer - Cattura Live SIP (Standard e TLS/HEP)
Cattura il traffico SIP tramite sngrep o decoder HEP nativo + log Asterisk.
"""

import os
import sys
import time
import subprocess
import socket
import struct
import threading
from datetime import datetime
from utils import *

# --- Config ---
SCRIPTNAME = "NethVoice Call Analyzer"
VERSION = "1.0"
OUTPUT_FILE = f"call_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
init_log(OUTPUT_FILE)

# --- Root Check ---
check_root()

# --- Header ---
log(f"{Colors.HEADER}======================================================{Colors.ENDC}")
log(f"{Colors.HEADER}{SCRIPTNAME} {VERSION}{Colors.ENDC}")
log(f"{Colors.HEADER}======================================================{Colors.ENDC}")
log(f"Analisi Chiamate in Tempo Reale - {datetime.now()}\n")

# --- Recupera istanze ---
istances = get_nethvoice_instances()

if not istances:
    log("Nessuna istanza NethVoice trovata sul sistema. Impossibile proseguire.", Colors.FAIL)
    sys.exit(1)

log("Istanze NethVoice disponibili:", Colors.HEADER)
for idx, inst in enumerate(istances):
    log(f"  [{idx + 1}] {inst}")

esempio = istances[0]
scelta = input(f"\n{Colors.WARNING}Su quale istanza vuoi catturare il traffico? (Inserisci il numero, es. '1' per {esempio}): {Colors.ENDC}").strip()

try:
    indice = int(scelta) - 1
    if 0 <= indice < len(istances):
        target_instance = istances[indice]
    else:
        log("Selezione non valida. Uso la prima istanza.", Colors.FAIL)
        target_instance = istances[0]
except ValueError:
    log("Input non riconosciuto. Uso la prima istanza.", Colors.FAIL)
    target_instance = istances[0]

log(f"\nIstanza selezionata: {target_instance}", Colors.OKGREEN)

# --- TLS? ---
is_tls = input(f"\n{Colors.WARNING}Il traffico usa TLS/SIPS? (y/n) {Colors.ENDC}").strip().lower() == 'y'
proxy_instance = ""
if is_tls:
    proxies = get_proxy_instances()
    if proxies:
        log("\nModuli Proxy disponibili:", Colors.HEADER)
        for idx, p in enumerate(proxies):
            log(f"  [{idx + 1}] {p}")
        p_scelta = input(f"\n{Colors.WARNING}Quale proxy usare? (Inserisci il numero, es. '1' per {proxies[0]}): {Colors.ENDC}").strip()
        try:
            p_idx = int(p_scelta) - 1
            if 0 <= p_idx < len(proxies):
                proxy_instance = proxies[p_idx]
            else:
                proxy_instance = proxies[0]
        except ValueError:
            proxy_instance = proxies[0]
        log(f"Proxy selezionato: {proxy_instance}", Colors.OKGREEN)
    else:
        log("Nessun proxy trovato. TLS non disponibile.", Colors.FAIL)
        is_tls = False

# --- Durata ---
try:
    duration = int(input(f"\n{Colors.WARNING}Per quanti secondi restare in ascolto? (es. 60): {Colors.ENDC}").strip())
except:
    duration = 60
    log("Valore non valido. Utilizzo 60 secondi come default.", Colors.FAIL)

# --- File di output ---
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
sngrep_file = f"capture_{target_instance}_{ts_str}.pcap"
ast_file = f"asterisk_{target_instance}_{ts_str}.txt"

# --- 1. Installa tool se necessari ---
if not is_tls:
    log("\nVerifica presenza sngrep...", Colors.OKGREEN)
    if not run_cmd("command -v sngrep", shell=True):
        log("sngrep non trovato. Installazione in corso...", Colors.WARNING)
        run_cmd("dnf -y install http://repo.okay.com.mx/centos/9/x86_64/release/sngrep-1.6.0-1.el9.x86_64.rpm strace vim", shell=True)
    log("Tool di cattura pronti.", Colors.OKGREEN)

# --- 2. Avvio cattura ---
print_section("Cattura in corso")
log(f"Ascolto su {target_instance} per {duration} secondi...", Colors.HEADER)
log("ESEGUI ORA LA CHIAMATA PROBLEMATICA!", Colors.FAIL)

stop_event = threading.Event()
hep_thread = None

if is_tls and proxy_instance:
    log("\nConfigurazione cattura TLS via HEP decoder Python...", Colors.WARNING)
    run_cmd(f"runagent -m {proxy_instance} kamcmd siptrace.status on", shell=True)

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

        debug_file = f"debug_pcap_{output_file.replace('.pcap','')}.txt"
        pkt_count = 0
        SIP_METHODS = [b'INVITE', b'REGISTER', b'OPTIONS', b'ACK', b'BYE',
                       b'CANCEL', b'SIP/2.0', b'SUBSCRIBE', b'NOTIFY',
                       b'PUBLISH', b'MESSAGE', b'INFO', b'REFER', b'UPDATE', b'PRACK']

        with open(output_file, 'wb') as f, open(debug_file, 'w') as dbg:
            # PCAP Global Header (link type 1 = Ethernet)
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
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
                    proto = 17
                    detected_ver = "UNKNOWN"

                    # --- HEPv3 ---
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
                        hdr_len = data[1]
                        if hdr_len > len(data):
                            continue
                        sport = struct.unpack('!H', data[4:6])[0]
                        dport = struct.unpack('!H', data[6:8])[0]
                        if data[2] == 2 and hdr_len >= 16:
                            src_ip = data[8:12]
                            dst_ip = data[12:16]
                        # HEPv2: +12 byte di timestamp extension
                        if data[0] == 2:
                            sip_payload = data[hdr_len + 12:]
                        else:
                            sip_payload = data[hdr_len:]

                    # --- Fallback: SIP puro ---
                    else:
                        for method in SIP_METHODS:
                            if data.lstrip(b'\x00').startswith(method):
                                detected_ver = "RAW_SIP"
                                sip_payload = data.lstrip(b'\x00')
                                break

                    # Debug primi 10 pacchetti
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

                    sip_payload = sip_payload.rstrip(b'\x00')
                    if not sip_payload:
                        continue

                    pkt_count += 1

                    # Pacchetto Ethernet+IP+UDP+SIP
                    udp_len = 8 + len(sip_payload)
                    udp_hdr = struct.pack('!HHHH', sport, dport, udp_len, 0)
                    ip_total = 20 + udp_len
                    ip_hdr_raw = struct.pack('!BBHHHBBH4s4s',
                        0x45, 0, ip_total, 0, 0x4000, 64, proto, 0, src_ip, dst_ip)
                    chksum = 0
                    for i in range(0, 20, 2):
                        chksum += (ip_hdr_raw[i] << 8) + ip_hdr_raw[i+1]
                    chksum = (chksum >> 16) + (chksum & 0xFFFF)
                    chksum = ~chksum & 0xFFFF
                    ip_hdr = ip_hdr_raw[:10] + struct.pack('!H', chksum) + ip_hdr_raw[12:]

                    packet = eth_hdr + ip_hdr + udp_hdr + sip_payload

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

    hep_thread = threading.Thread(target=capture_hep_to_pcap, args=(sngrep_file, stop_event), daemon=True)
    hep_thread.start()
    log("Decoder HEP Python avviato su 127.0.0.1:5065", Colors.OKGREEN)
else:
    sngrep_cmd = f"sngrep -r -d any -N -O {sngrep_file}"
    sngrep_proc = subprocess.Popen(sngrep_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Asterisk logs
ast_cmd = f"runagent -m {target_instance} -- podman exec -it freepbx asterisk -rvvvvvv > {ast_file} 2>&1"
ast_proc = subprocess.Popen(ast_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# --- 3. Progress bar ---
log("")
for i in range(duration):
    progress = int((i+1) / duration * 100)
    sys.stdout.write(f"\rIn ascolto: {create_bar(progress, length=40)}")
    sys.stdout.flush()
    time.sleep(1)

print("\n")
log("Termine ascolto, finalizzazione dei log...", Colors.WARNING)

# --- 4. Cleanup ---
if is_tls and proxy_instance:
    stop_event.set()
    if hep_thread:
        hep_thread.join(timeout=3)
    run_cmd(f"runagent -m {proxy_instance} kamcmd siptrace.status off", shell=True)
else:
    run_cmd("pkill -INT sngrep", shell=True)
    time.sleep(1.5)

run_cmd("stty sane", shell=True)
print("\r", end="")

run_cmd(f"runagent -m {target_instance} -- podman exec -it freepbx pkill -9 -f 'asterisk -r'", shell=True)

# --- 5. Output ---
print_section("Cattura Completata")

ast_size = f"{os.path.getsize(ast_file)/1024:.1f} KB" if os.path.exists(ast_file) else "0 KB"
sngrep_size = f"{os.path.getsize(sngrep_file)/1024:.1f} KB" if os.path.exists(sngrep_file) else "0 KB"

log(f"  - Dump Asterisk: {ast_file} ({ast_size})")
log(f"  - Dump SIP: {sngrep_file} ({sngrep_size})")
log("Puoi trasferire questi file aprendo WinSCP oppure copiarli dal terminale.", Colors.HEADER)

if is_tls:
    log("\nIl file PCAP TLS è stato decodificato automaticamente dal decoder HEP.", Colors.OKGREEN)
    log("Puoi aprirlo con Wireshark o con 'sngrep -I <file.pcap>' e vedrai il traffico SIP in chiaro!\n", Colors.OKGREEN)

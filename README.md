# InstanceAnalyzer – NethServer 8 & NethVoice Diagnostic Tool

Tool di diagnostica per installazioni **NethServer 8** con moduli **NethVoice**.  
Ora suddiviso in **due script indipendenti** + un modulo di utility condivise.

> **Requisiti**: Python (nessuna dipendenza esterna), esecuzione come `root`.

---

## Struttura del progetto

| File | Descrizione |
|------|-------------|
| `utils.py` | Modulo condiviso: Colors, logging, run_cmd, barre di progresso, helpers |
| `nethserver_analyzer.py` | Analisi del sistema e dei container NethVoice |
| `call_analyzer.py` | Cattura live del traffico SIP (standard e TLS) |

---

## 1. Analisi Sistema e Container

```bash
python nethserver_analyzer.py
```

### Cosa analizza

- **Sistema Root**: Hostname, IP, DNS, Internet, CPU/RAM/Disco (barre colorate), Open Files, Top 5 processi, Uptime
- **Istanze NethVoice**: Selezione interattiva (singola istanza o tutte), poi per ognuna:
  - CPU/RAM del container
  - PJSIP Registrations e Contacts
  - Ultimi 200 log API Server con evidenziazione errori (🔴) e warning (🟡)
- **Rete**: Ping e Traceroute verso `8.8.8.8`

**Output**: `analisi_avanzata_YYYYMMDD_HHMMSS.log`

---

## 2. Cattura Chiamate Live

```bash
python call_analyzer.py
```

### Flusso interattivo

1. Mostra le istanze NethVoice disponibili → seleziona quella da analizzare
2. Chiede se il traffico è TLS/SIPS (`y/n`)
3. Se TLS: mostra i proxy disponibili → seleziona il proxy Kamailio
4. Chiede la durata dell'ascolto in secondi (default 60)
5. Avvia la cattura contemporanea di **Asterisk** (verbose) e **SIP** (pcap)
6. Mostra barra di progresso → al termine salva i file

### Modalità non-TLS (standard)

Usa `sngrep` per catturare il traffico SIP dall'interfaccia di rete:

```bash
sngrep -r -d any -N -O capture.pcap
```

### Modalità TLS (decoder HEP nativo)

Quando il traffico è TLS, `sngrep` non può salvare il pcap. Lo script usa un **decoder HEP scritto interamente in Python** che:

1. Abilita `siptrace` su Kamailio (`kamcmd siptrace.status on`)
2. Apre un socket UDP su `127.0.0.1:5065`
3. Riceve i pacchetti **HEP** (supporto HEPv1, HEPv2, HEPv3) inviati da Kamailio
4. **Decodifica l'incapsulamento HEP** ed estrae IP, porte e payload SIP in chiaro
5. Ricostruisce pacchetti sintetici `Ethernet + IP + UDP + SIP`
6. Scrive un file `.pcap` standard
7. Al termine disabilita `siptrace`

Il risultato è un PCAP con **traffico SIP puro decodificato**, apribile con:

```bash
sngrep -I capture_nethvoice1_*.pcap     # Da terminale sul server
wireshark capture_nethvoice1_*.pcap      # Da PC dopo trasferimento via WinSCP
```

### Come funziona il decoder HEP

```
Chiamata TLS (SIPS)
        │
        ▼
┌──────────────┐       HEP/UDP         ┌──────────────────┐
│  Kamailio    │ ───────────────────►  │  Python Decoder  │
│  (siptrace)  │    127.0.0.1:5065     │  (socket UDP)    │
└──────────────┘                       └──────┬───────────┘
                                              │
                                    Estrae SIP puro
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │   File .pcap     │
                                    │ (Eth+IP+UDP+SIP) │
                                    └──────────────────┘
```

**Struttura HEPv2** (usato da NethVoice/NS8):
```
Base Header (16 byte)        → version, family, proto, porte, IP src/dst
Timestamp Extension (12 byte) → tv_sec, tv_usec, captid
SIP Payload (variabile)       → INVITE sip:... SIP/2.0\r\n...
```

### File generati

| File | Contenuto |
|------|-----------|
| `asterisk_<istanza>_YYYYMMDD_HHMMSS.txt` | Log verboso Asterisk (`-rvvvvvv`) |
| `capture_<istanza>_YYYYMMDD_HHMMSS.pcap` | Cattura SIP (standard o TLS decodificato) |
| `debug_pcap_capture_<istanza>_*.txt` | Debug del decoder HEP (solo TLS, primi 10 pacchetti) |
| `call_analysis_YYYYMMDD_HHMMSS.log` | Log testuale della sessione di cattura |

---

## Note importanti

- Entrambi gli script devono essere eseguiti come **root** sul cluster NethServer 8
- Il file `utils.py` deve trovarsi nella stessa directory degli script
- La cattura TLS tramite HEP funziona **una sessione alla volta** (limitazione Kamailio siptrace)
- Per trasferire i file catturati, usare un client SCP (es. WinSCP su Windows)

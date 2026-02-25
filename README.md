# InstanceAnalyzer – NethServer 8 & NethVoice Diagnostic Tool

Script Python per l'analisi di primo livello delle installazioni **NethServer 8** con moduli **NethVoice**.

> **Requisiti**: Python 3 (nessuna dipendenza esterna), esecuzione come `root`.

---

## Avvio rapido

```bash
python3 nethserver_analyzer.py
```

Lo script produce un file di log testuale `analisi_avanzata_YYYYMMDD_HHMMSS.log` (senza colori ANSI) nella directory corrente.

---

## Cosa analizza

### 1. Stato del sistema (Root)

| Check | Dettaglio |
|-------|-----------|
| **Hostname / IP** | FQDN, IP, DNS configurati |
| **Internet** | Ping verso `sos.nethesis.it` |
| **Risorse** | CPU, RAM, Disco con barre visuali colorate (verde/giallo/rosso) |
| **Open Files** | File aperti dal sistema |
| **Top Processi** | I 5 processi con più utilizzo CPU |
| **Uptime / Timezone** | Tempo di attività e fuso orario |

### 2. Istanze NethVoice

Lo script rileva automaticamente le istanze NethVoice attive tramite `loginctl list-users`.

**Selezione interattiva**: prima di analizzare, lo script presenta un menu numerato:

```
Istanze trovate nel sistema:
  [1] nethvoice1
  [2] nethvoice7
  [A] Analizza TUTTE le istanze

Quale istanza vuoi analizzare? (Inserisci il numero, es. '1' per nethvoice1, oppure 'A' per tutte):
```

Per ogni istanza selezionata vengono verificati:

- **CPU / RAM** del container (via `podman exec` + `top` e `free`)
- **PJSIP Registrations** — stato dei trunk SIP
- **PJSIP Contacts** — dispositivi registrati
- **Log API Server** — ultimi 200 eventi, con evidenziazione automatica:
  - 🔴 `ERROR` / `FAIL` → rosso
  - 🟡 `WARN` → giallo

### 3. Connettività di rete

- Ping `8.8.8.8` (4 pacchetti)
- Traceroute verso `8.8.8.8` (installazione automatica di `traceroute` se mancante)

---

## Analisi chiamate in tempo reale (Live Call Analysis)

Al termine dell'analisi, lo script propone una cattura live del traffico SIP:

```
Vuoi analizzare le chiamate in tempo reale? (y/n)
```

### Scelta dell'istanza

Lo script mostra le istanze analizzate in precedenza e l'elenco completo delle istanze disponibili, così da poter scegliere anche un'istanza diversa da quella analizzata.

### Modalità non-TLS (standard)

1. Verifica e installa `sngrep` se assente
2. Avvia `sngrep -r -d any -N -O <file>.pcap` in background
3. Avvia `asterisk -rvvvvvv` con redirect su file `.txt`
4. Mostra una barra di progresso durante l'ascolto
5. Al termine, stoppa le catture e restituisce i file

### Modalità TLS (proxy Kamailio)

Se il traffico usa TLS/SIPS, lo script chiede quale proxy usare (mostrando la lista dei proxy attivi) e avvia un **decoder HEP nativo scritto in Python**:

1. Abilita `siptrace` su Kamailio via `kamcmd siptrace.status on`
2. Apre un socket UDP su `127.0.0.1:5065`
3. Riceve i pacchetti **HEP** (supporto HEPv1, HEPv2, HEPv3) inviati da Kamailio
4. **Decodifica l'incapsulamento HEP** ed estrae:
   - IP sorgente e destinazione reali
   - Porte SIP reali
   - **Payload SIP in chiaro** (INVITE, 200 OK, BYE, ecc.)
5. Ricostruisce pacchetti sintetici `Ethernet + IP + UDP + SIP`
6. Scrive un file `.pcap` standard
7. Al termine disabilita `siptrace` su Kamailio

Il risultato è un file PCAP che contiene **traffico SIP puro decodificato**, apribile direttamente con:

```bash
# Su server
sngrep -I capture_nethvoice1_20260225_110635.pcap

# Su PC (trasferito via WinSCP/SCP)
wireshark capture_nethvoice1_20260225_110635.pcap
```

### File generati

| File | Contenuto |
|------|-----------|
| `analisi_avanzata_YYYYMMDD_HHMMSS.log` | Report completo dell'analisi (testo) |
| `asterisk_<istanza>_YYYYMMDD_HHMMSS.txt` | Log verboso Asterisk (`-rvvvvvv`) |
| `capture_<istanza>_YYYYMMDD_HHMMSS.pcap` | Cattura SIP (standard o TLS decodificato) |
| `debug_pcap_capture_<istanza>_*.txt` | Debug del decoder HEP (solo in modalità TLS) |

---

## Come funziona il decoder HEP

Il protocollo **HEP** (Homer Encapsulation Protocol) è usato da Kamailio per esportare il traffico SIP decodificato da connessioni TLS.

### Flusso

```
Chiamata TLS (SIPS)
        │
        ▼
┌──────────────┐       HEP/UDP        ┌──────────────────┐
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

### Struttura HEPv2 (usato da NethVoice/NS8)

```
┌─────────────────────────────────────────────────┐
│ Base Header (16 byte)                           │
│  version(1) + length(1) + family(1) + proto(1)  │
│  src_port(2) + dst_port(2)                      │
│  src_ip(4) + dst_ip(4)                          │
├─────────────────────────────────────────────────┤
│ Timestamp Extension (12 byte)                   │
│  tv_sec(4) + tv_usec(4) + captid(4)            │
├─────────────────────────────────────────────────┤
│ SIP Payload (variabile)                         │
│  INVITE sip:... SIP/2.0\r\n...                  │
└─────────────────────────────────────────────────┘
```

---

## Note importanti

- Lo script deve essere eseguito come **root** sul cluster NethServer 8
- La cattura TLS tramite HEP funziona **una sessione alla volta** (limitazione Kamailio siptrace)
- Per trasferire i file catturati, usare un client SCP (es. WinSCP su Windows)
- Il file di debug `debug_pcap_*.txt` contiene l'hex dump dei primi 10 pacchetti HEP ricevuti, utile per diagnostica avanzata

---

## Licenza

Questo script è destinato esclusivamente all'analisi delle installazioni NethServer 8. Qualunque uso improprio non è responsabilità dell'autore.

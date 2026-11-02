import base64
import contextlib
import ctypes
import heapq
import http.cookiejar
import io
import itertools
import json
import msvcrt
import os
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import winreg
from collections import deque
from ctypes import wintypes
from datetime import datetime
from html.parser import HTMLParser

# NetTool: strumento unico per rete Wi-Fi + hotspot del PC.
#   Wi-Fi:   scansione reti, lock su un BSSID, test di traffic shaping,
#            limite di banda, stato connessione (Wi-Fi/Internet/captive portal),
#            login automatico al captive portal.
#   Hotspot: accensione/spegnimento, scelta banda (Auto/2,4/5 GHz) con banda
#            attiva visibile, SSID/password, persistenza (watchdog che lo
#            riaccende se cade) e anti-spegnimento automatico (registro).
#
# Il Wi-Fi parla direttamente con wlanapi.dll (API nativa di Windows) invece di
# interpretare l'output di netsh. L'hotspot usa l'API WinRT
# NetworkOperatorTetheringManager, pilotata via PowerShell (nessuna dipendenza
# nuova). Gli eventi (hotspot, Internet, portale) finiscono anche in net_tool.log.

wlanapi = ctypes.WinDLL("wlanapi.dll")

V, R, G, B, N = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


# ---------------------------------------------------------------- strutture WLAN

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", wintypes.DWORD)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", wintypes.ULONG),
                ("ucSSID", ctypes.c_ubyte * 32)]


class NDIS_OBJECT_HEADER(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_ubyte), ("Revision", ctypes.c_ubyte),
                ("Size", ctypes.c_ushort)]


class DOT11_BSSID_LIST(ctypes.Structure):
    _fields_ = [("Header", NDIS_OBJECT_HEADER),
                ("uNumOfEntries", wintypes.ULONG),
                ("uTotalNumOfEntries", wintypes.ULONG),
                ("BSSIDs", (ctypes.c_ubyte * 6) * 1)]


class WLAN_CONNECTION_PARAMETERS(ctypes.Structure):
    _fields_ = [("wlanConnectionMode", ctypes.c_int),
                ("strProfile", wintypes.LPCWSTR),
                ("pDot11Ssid", ctypes.POINTER(DOT11_SSID)),
                ("pDesiredBssidList", ctypes.POINTER(DOT11_BSSID_LIST)),
                ("dot11BssType", ctypes.c_int),
                ("dwFlags", wintypes.DWORD)]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("dot11BssType", ctypes.c_int),
                ("dot11Bssid", ctypes.c_ubyte * 6),
                ("dot11PhyType", ctypes.c_int),
                ("uDot11PhyIndex", wintypes.ULONG),
                ("wlanSignalQuality", wintypes.ULONG),
                ("ulRxRate", wintypes.ULONG),
                ("ulTxRate", wintypes.ULONG)]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    # ci servono solo i campi iniziali: la parte "security" che segue la
    # ignoriamo (copiamo solo sizeof di questa struttura)
    _fields_ = [("isState", ctypes.c_int),
                ("wlanConnectionMode", ctypes.c_int),
                ("strProfileName", ctypes.c_wchar * 256),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES)]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", wintypes.ULONG),
                ("usRateSet", wintypes.USHORT * 126)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("uPhyId", wintypes.ULONG),
                ("dot11Bssid", ctypes.c_ubyte * 6),
                ("dot11BssType", ctypes.c_int),
                ("dot11BssPhyType", ctypes.c_int),
                ("lRssi", wintypes.LONG),
                ("uLinkQuality", wintypes.ULONG),
                ("bInRegDomain", ctypes.c_ubyte),
                ("usBeaconPeriod", wintypes.USHORT),
                ("ullTimestamp", ctypes.c_ulonglong),
                ("ullHostTimestamp", ctypes.c_ulonglong),
                ("usCapabilityInformation", wintypes.USHORT),
                ("ulChCenterFrequency", wintypes.ULONG),
                ("wlanRateSet", WLAN_RATE_SET),
                ("ulIeOffset", wintypes.ULONG),
                ("ulIeSize", wintypes.ULONG)]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", wintypes.DWORD),
                ("dwNumberOfItems", wintypes.DWORD),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


# stati dell'interfaccia (WLAN_INTERFACE_STATE)
CONNESSO, DISCONNESSO = 1, 4
IN_CORSO = (5, 6, 7)  # associating, discovering, authenticating

OP_STATO, OP_CONNESSIONE, OP_CANALE = 6, 7, 8
OP_RSSI = 0x10000102

BSS_INFRASTRUTTURA, BSS_QUALSIASI = 1, 3
MODO_PROFILO, MODO_APERTA = 0, 3  # wlan_connection_mode_profile / discovery_unsecure
CAP_PRIVACY = 0x0010              # bit "rete cifrata" nelle capability del beacon


def mac_str(dati):
    return ":".join(f"{b:02x}" for b in dati)


def mac_byte(testo):
    return bytes(int(x, 16) for x in testo.replace("-", ":").split(":"))


def ssid_str(ssid):
    return bytes(ssid.ucSSID[:ssid.uSSIDLength]).decode("utf-8", "replace")


def banda_canale(freq_khz):
    mhz = freq_khz // 1000
    if mhz == 2484:
        return "2,4 GHz", 14
    if mhz < 3000:
        return "2,4 GHz", (mhz - 2407) // 5
    if mhz >= 5925:
        return "6 GHz", (mhz - 5950) // 5
    return "5 GHz", (mhz - 5000) // 5


def banda_da_canale(canale):
    return "2,4 GHz" if canale and canale <= 14 else "5 GHz"


class Wlan:
    # un handle verso il servizio WLAN sulla prima scheda Wi-Fi;
    # ogni thread ne apre uno suo

    def __init__(self):
        self.handle = wintypes.HANDLE()
        versione = wintypes.DWORD()
        err = wlanapi.WlanOpenHandle(2, None, ctypes.byref(versione), ctypes.byref(self.handle))
        if err:
            raise OSError(f"WlanOpenHandle fallita: {err}")
        lista = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        err = wlanapi.WlanEnumInterfaces(self.handle, None, ctypes.byref(lista))
        if err or lista.contents.dwNumberOfItems == 0:
            raise OSError(f"nessuna scheda Wi-Fi trovata ({err})")
        info = lista.contents.InterfaceInfo[0]
        self.guid = GUID.from_buffer_copy(bytes(info.InterfaceGuid))
        self.nome = info.strInterfaceDescription
        wlanapi.WlanFreeMemory(lista)

    def chiudi(self):
        wlanapi.WlanCloseHandle(self.handle, None)

    def _query(self, opcode, tipo):
        dim = wintypes.DWORD()
        ptr = ctypes.c_void_p()
        err = wlanapi.WlanQueryInterface(self.handle, ctypes.byref(self.guid), opcode, None,
                                         ctypes.byref(dim), ctypes.byref(ptr), None)
        if err:
            return None
        copia = tipo.from_buffer_copy(ctypes.string_at(ptr, ctypes.sizeof(tipo)))
        wlanapi.WlanFreeMemory(ptr)
        return copia

    def stato(self):
        conn = self._query(OP_CONNESSIONE, WLAN_CONNECTION_ATTRIBUTES)
        if conn is None or conn.isState != CONNESSO:
            st = self._query(OP_STATO, wintypes.DWORD)
            return {"stato": st.value if st is not None else DISCONNESSO}
        a = conn.wlanAssociationAttributes
        rssi = self._query(OP_RSSI, wintypes.LONG)
        canale = self._query(OP_CANALE, wintypes.ULONG)
        return {"stato": CONNESSO,
                "ssid": ssid_str(a.dot11Ssid),
                "bssid": mac_str(a.dot11Bssid),
                "segnale": a.wlanSignalQuality,
                "rssi": rssi.value if rssi is not None else None,
                "canale": canale.value if canale is not None else None}

    def avvia_scansione(self):
        # la scansione e' asincrona: i risultati arrivano entro ~4 secondi
        wlanapi.WlanScan(self.handle, ctypes.byref(self.guid), None, None, None)

    def antenne(self):
        lista = ctypes.POINTER(WLAN_BSS_LIST)()
        err = wlanapi.WlanGetNetworkBssList(self.handle, ctypes.byref(self.guid), None,
                                            BSS_QUALSIASI, False, None, ctypes.byref(lista))
        if err:
            raise OSError(f"WlanGetNetworkBssList fallita: {err}")
        n = lista.contents.dwNumberOfItems
        voci = (WLAN_BSS_ENTRY * n).from_address(
            ctypes.addressof(lista.contents) + WLAN_BSS_LIST.wlanBssEntries.offset)
        risultato = []
        for e in voci:
            banda, canale = banda_canale(e.ulChCenterFrequency)
            risultato.append({"ssid": ssid_str(e.dot11Ssid),
                              "bssid": mac_str(e.dot11Bssid),
                              "segnale": e.uLinkQuality,
                              "rssi": e.lRssi,
                              "banda": banda,
                              "canale": canale,
                              "protetta": bool(e.usCapabilityInformation & CAP_PRIVACY)})
        wlanapi.WlanFreeMemory(lista)
        return sorted(risultato, key=lambda x: -x["segnale"])

    def profilo_esiste(self, nome):
        xml = ctypes.c_wchar_p()
        flags, accesso = wintypes.DWORD(), wintypes.DWORD()
        err = wlanapi.WlanGetProfile(self.handle, ctypes.byref(self.guid), nome, None,
                                     ctypes.byref(xml), ctypes.byref(flags), ctypes.byref(accesso))
        if err:
            return False
        wlanapi.WlanFreeMemory(xml)
        return True

    def modalita(self, ssid, protetta):
        # con un profilo salvato usiamo quello; una rete aperta si puo'
        # agganciare anche senza profilo; una protetta senza profilo no
        if self.profilo_esiste(ssid):
            return MODO_PROFILO
        if not protetta:
            return MODO_APERTA
        raise ValueError(f"nessun profilo salvato per '{ssid}': connettiti una volta "
                         f"da Windows inserendo la password, poi riprova")

    def connetti(self, bssid, ssid, protetta):
        # WlanConnect con una lista di BSSID ammessi: la scheda si associa solo a quello
        lista = DOT11_BSSID_LIST()
        lista.Header.Type = 0x80      # NDIS_OBJECT_TYPE_DEFAULT
        lista.Header.Revision = 1     # DOT11_BSSID_LIST_REVISION_1
        lista.Header.Size = ctypes.sizeof(DOT11_BSSID_LIST)
        lista.uNumOfEntries = lista.uTotalNumOfEntries = 1
        ctypes.memmove(lista.BSSIDs[0], mac_byte(bssid), 6)

        param = WLAN_CONNECTION_PARAMETERS()
        param.wlanConnectionMode = self.modalita(ssid, protetta)
        if param.wlanConnectionMode == MODO_PROFILO:
            param.strProfile = ssid
        else:
            raw = ssid.encode("utf-8")
            dot11 = DOT11_SSID(len(raw))
            ctypes.memmove(dot11.ucSSID, raw, len(raw))
            param.pDot11Ssid = ctypes.pointer(dot11)
        param.pDesiredBssidList = ctypes.pointer(lista)
        param.dot11BssType = BSS_INFRASTRUTTURA
        return wlanapi.WlanConnect(self.handle, ctypes.byref(self.guid), ctypes.byref(param), None)


# ---------------------------------------------------------------- utilita' console

def cls():
    os.system("cls")


def ora():
    return datetime.now().strftime("%H:%M:%S")


def avvisa_suono():
    # beep di sistema: si sente anche restando nel menu o in un'altra schermata
    try:
        ctypes.windll.user32.MessageBeep(0xFFFFFFFF)
    except Exception:
        pass


def attendi_tasto(secondi):
    # aspetta fino a `secondi`; True se nel frattempo e' stato premuto un tasto
    fine = time.monotonic() + secondi
    while time.monotonic() < fine:
        if msvcrt.kbhit():
            msvcrt.getwch()
            return True
        time.sleep(0.05)
    return False


def premi_un_tasto(testo="Premi un tasto per tornare al menu..."):
    print(f"\n{testo}")
    while msvcrt.kbhit():
        msvcrt.getwch()
    msvcrt.getwch()


def leggi_numero(prompt, predefinito=None):
    testo = input(prompt).strip().replace(",", ".")
    if not testo:
        return predefinito
    try:
        valore = float(testo)
    except ValueError:
        return None
    return valore if valore > 0 else None


def barra(percento, larghezza=10):
    pieni = round(percento / 100 * larghezza)
    return "#" * pieni + "." * (larghezza - pieni)


# ---------------------------------------------------------------- 1-2. scansione

ultima_lista = []


def stampa_antenne(lista, connesso=None, lock=None):
    print(f"{B}{'#':>3}  {'SSID':<24} {'BSSID':<17}  {'segnale':<16} {'RSSI':>8}  "
          f"{'banda':<7} {'can':>3}  {'sicurezza':<9}{N}")
    for i, a in enumerate(lista, 1):
        ssid = a["ssid"] or "(nascosta)"
        colore = V if a["segnale"] >= 60 else G if a["segnale"] >= 40 else R
        segno = ""
        if a["bssid"] == lock:
            segno += f" {B}[LOCK]{N}"
        if a["bssid"] == connesso:
            segno += f" {V}<- connesso{N}"
        print(f"{i:>3}  {ssid[:24]:<24} {a['bssid']:<17}  "
              f"{colore}{barra(a['segnale'])} {a['segnale']:>3}%{N} {a['rssi']:>4} dBm  "
              f"{a['banda']:<7} {a['canale']:>3}  {'protetta' if a['protetta'] else 'aperta':<9}{segno}")
    if not lista:
        print("  nessuna antenna trovata")


def scansiona(w):
    global ultima_lista
    w.avvia_scansione()
    time.sleep(4)
    ultima_lista = w.antenne()
    return ultima_lista


def bssid_connesso(w):
    s = w.stato()
    return s.get("bssid") if s["stato"] == CONNESSO else None


def scansione_continua(w, lock):
    global ultima_lista
    giro = 0
    print("Scansione in corso...")
    while True:
        w.avvia_scansione()
        # mentre la scheda scansiona resta a schermo il giro precedente
        if attendi_tasto(4):
            return
        ultima_lista = w.antenne()
        giro += 1
        cls()
        print(f"{B}Scansione continua #{giro} - {ora()}{N} - {len(ultima_lista)} antenne "
              f"(premi un tasto per tornare al menu)\n")
        stampa_antenne(ultima_lista, bssid_connesso(w), lock.bssid if lock else None)


# ---------------------------------------------------------------- 3-5. lock su BSSID

class Lock(threading.Thread):
    # gira in background: se il driver ci sposta su un'altra antenna (roaming)
    # o cadiamo, ci riconnette subito al BSSID scelto

    def __init__(self, bssid, ssid, protetta, banda):
        super().__init__(daemon=True)
        self.bssid, self.ssid, self.protetta, self.banda = bssid, ssid, protetta, banda
        self.ferma = threading.Event()
        self.eventi = deque(maxlen=50)
        self.riconnessioni = 0
        self.ultimo = {"stato": DISCONNESSO}

    def evento(self, testo):
        self.eventi.append(f"[{ora()}] {testo}")

    def run(self):
        w = Wlan()
        self.evento(f"lock avviato su {self.bssid} ({self.ssid}, {self.banda})")
        try:
            while not self.ferma.is_set():
                s = w.stato()
                self.ultimo = s
                if s["stato"] == CONNESSO and s["bssid"] == self.bssid:
                    self.ferma.wait(1)
                    continue
                if s["stato"] in IN_CORSO:
                    # sta gia' negoziando una connessione: lasciamolo finire
                    self.ferma.wait(1)
                    continue
                dove = f"agganciato a {s['bssid']}" if s["stato"] == CONNESSO else "disconnesso"
                self.riconnessioni += 1
                try:
                    err = w.connetti(self.bssid, self.ssid, self.protetta)
                except ValueError as e:
                    self.evento(f"{R}ERRORE: {e}{N}")
                    return
                esito = "richiesta inviata" if err == 0 else f"{R}errore {err}{N}"
                self.evento(f"{dove} -> riconnessione #{self.riconnessioni} a {self.bssid}: {esito}")
                self.ferma.wait(3)
        finally:
            w.chiudi()


def mostra_lock(lock):
    while True:
        cls()
        s = lock.ultimo
        print(f"{B}LOCK su {lock.bssid}{N}  ({lock.ssid}, {lock.banda}) - "
              f"riconnessioni forzate: {lock.riconnessioni}\n")
        if not lock.is_alive():
            print(f"{R}Il lock si e' fermato (vedi eventi sotto).{N}")
        elif s["stato"] == CONNESSO and s["bssid"] == lock.bssid:
            print(f"{V}agganciato{N}  segnale={s['segnale']}% ({s['rssi']} dBm)  canale {s['canale']}")
        elif s["stato"] == CONNESSO:
            print(f"{G}su un'altra antenna ({s['bssid']}), riaggancio in corso...{N}")
        else:
            print(f"{G}non connesso, connessione in corso...{N}")
        print(f"\n{B}Eventi:{N}")
        for e in list(lock.eventi)[-12:]:
            print(" ", e)
        print("\nPremi un tasto per tornare al menu (il lock resta attivo).")
        if attendi_tasto(1):
            return


def avvia_lock(w, lock):
    print("Scansione in corso...")
    lista = scansiona(w)
    cls()
    stampa_antenne(lista, bssid_connesso(w), lock.bssid if lock else None)
    scelta = input("\nNumero dell'antenna o BSSID (invio = annulla): ").strip().lower()
    if not scelta:
        return lock
    if scelta.isdigit() and 1 <= int(scelta) <= len(lista):
        antenna = lista[int(scelta) - 1]
    else:
        trovate = [a for a in lista if a["bssid"] == scelta.replace("-", ":")]
        if not trovate:
            avvisa(f"{R}BSSID non trovato nella scansione.{N}")
            return lock
        antenna = trovate[0]
    if not antenna["ssid"]:
        avvisa(f"{R}Rete nascosta: serve l'SSID, non supportata.{N}")
        return lock
    try:
        w.modalita(antenna["ssid"], antenna["protetta"])
    except ValueError as e:
        avvisa(f"{R}{e}{N}")
        return lock

    if lock:
        lock.ferma.set()
        lock.join()
    nuovo = Lock(antenna["bssid"], antenna["ssid"], antenna["protetta"], antenna["banda"])
    nuovo.start()
    mostra_lock(nuovo)
    return nuovo


# ---------------------------------------------------------------- 6. traffic shaping

# file da 1 GB sul server di test OVH: con un solo download basta una sola
# richiesta per tutto il test. OVH limita le richieste per IP (gia' alla
# terza ravvicinata risponde 429 "Too Many Requests"), quindi niente
# download paralleli e niente richieste di controllo.
SERVER = "https://proof.ovh.net/files/1Gb.dat"
UA = {"User-Agent": "Mozilla/5.0", "Cache-Control": "no-cache"}
HOST_SERVER = urllib.parse.urlsplit(SERVER).hostname

BLOCCO = 16384         # byte letti per volta
RISCALDAMENTO = 5      # secondi ignorati all'avvio e dopo ogni pausa (avvio TCP)
QUOTA_CROLLO = 0.7     # mediana degli ultimi SECONDI_CROLLO sotto il 70% della soglia = crollo
SECONDI_CROLLO = 5
QUOTA_VINCENTE = 0.85  # a fine test la media deve essere almeno l'85% della soglia
PING_TIMEOUT = 2       # sotto carico la latenza puo' arrivare a quasi 1 s
PING_FALLITI = 3       # ping consecutivi falliti = rete giu'
PING_BASE_MAX = 400    # oltre questa latenza a riposo la rete e' gia' degradata: niente test
ERRORI_CROLLO = 6      # errori di connessione negli ultimi 5 s = rete giu'
RIFIUTI_MAX = 3        # risposte 429 dal server prima di rinunciare al test
ATTESA_429 = 10        # secondi di attesa se il server non indica Retry-After
WIFI_GIU = 2           # secondi di fila senza Wi-Fi = disconnessione

storico = []


class Limitatore:
    # "pacing": distribuisce i byte nel tempo per non superare la soglia.
    # Leggendo piu' lentamente, TCP riduce la finestra e il server rallenta.

    def __init__(self, mbps):
        self.byte_al_secondo = mbps * 1e6 / 8
        self.prossimo = time.monotonic()
        self.lock = threading.Lock()

    def consuma(self, n):
        with self.lock:
            adesso = time.monotonic()
            # al massimo 200 ms di credito accumulato: niente raffiche
            self.prossimo = max(self.prossimo, adesso - 0.2) + n / self.byte_al_secondo
            attesa = self.prossimo - adesso
        if attesa > 0:
            time.sleep(attesa)


class StatoTest:
    def __init__(self, mbps):
        self.limite = Limitatore(mbps)
        self.byte = 0
        self.errori = deque(maxlen=100)  # (istante, messaggio)
        self.rifiuti = 0
        self.attesa_fino = 0.0           # il server ci ha chiesto di aspettare fino a qui
        self.ferma = threading.Event()
        self.lock = threading.Lock()

    def aggiungi(self, n):
        with self.lock:
            self.byte += n

    def errore_rete(self, e):
        with self.lock:
            self.errori.append((time.monotonic(), f"{type(e).__name__}: {e}"))

    def server_rifiuta(self, e):
        # il server ha risposto, quindi la rete funziona: e' lui che rifiuta.
        # Aspettiamo quanto chiede (Retry-After) invece di insistere.
        try:
            attesa = int(e.headers.get("Retry-After", ATTESA_429))
        except (TypeError, ValueError):
            attesa = ATTESA_429
        with self.lock:
            self.rifiuti += 1
            self.attesa_fino = time.monotonic() + attesa

    def in_attesa(self):
        return time.monotonic() < self.attesa_fino

    def errori_recenti(self, secondi):
        limite = time.monotonic() - secondi
        with self.lock:
            return sum(1 for t, _ in self.errori if t >= limite)


def flusso(st):
    while not st.ferma.is_set():
        try:
            richiesta = urllib.request.Request(SERVER, headers=UA)
            with urllib.request.urlopen(richiesta, timeout=5) as r:
                while not st.ferma.is_set():
                    blocco = r.read(BLOCCO)
                    if not blocco:
                        break  # file finito: se ne riapre un altro
                    st.aggiungi(len(blocco))
                    st.limite.consuma(len(blocco))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                st.server_rifiuta(e)
                st.ferma.wait(st.attesa_fino - time.monotonic())
            else:
                st.errore_rete(e)
                st.ferma.wait(2)
        except Exception as e:
            st.errore_rete(e)
            st.ferma.wait(2)


def ping_tcp(ip):
    # tempo di apertura di una connessione TCP, in ms (None = fallito).
    # Non e' un ping ICMP (spesso bloccato): e' l'handshake TCP verso il
    # server OVH, che deve essere raggiungibile comunque per il test.
    # Non manda richieste HTTP, quindi non consuma il limite di OVH.
    # Sotto carico cresce se la rete accoda i pacchetti: indizio di shaping.
    t = time.perf_counter()
    try:
        socket.create_connection((ip, 443), timeout=PING_TIMEOUT).close()
    except OSError:
        return None
    return (time.perf_counter() - t) * 1000


def test_shaping(soglia, durata, lock):
    ris = {"soglia": soglia, "ora": ora()}
    # il Wi-Fi si controlla a ogni secondo: un crollo dovuto a un cambio
    # d'antenna o a una disconnessione non e' traffic shaping
    w = Wlan()
    try:
        return _test_shaping(soglia, durata, lock, ris, w)
    finally:
        w.chiudi()


def _test_shaping(soglia, durata, lock, ris, w):
    wifi = w.stato()
    if wifi["stato"] != CONNESSO:
        return ris | {"esito": "errore", "motivo": "Wi-Fi non connesso", "suggerita": None}
    antenna = wifi["bssid"]
    cambi = []  # (secondo, da, a)
    wifi_ko = 0

    # IP risolto una volta sola: il DNS non deve finire nella misura della latenza
    try:
        ip = socket.getaddrinfo(HOST_SERVER, 443, type=socket.SOCK_STREAM)[0][4][0]
    except OSError as e:
        return ris | {"esito": "errore",
                      "motivo": f"impossibile risolvere {HOST_SERVER}: rete o DNS non raggiungibili ({e})",
                      "suggerita": None}

    print("Misuro la latenza a riposo...")
    base = [p for p in (ping_tcp(ip) for _ in range(5)) if p is not None]
    if base:
        ris["ping_base"] = statistics.median(base)
    else:
        # la rete filtra anche le connessioni di prova: si giudica solo la velocita'
        ip = None
        ris["ping_base"] = None
        print(f"{G}Latenza non misurabile su questa rete: il test valutera' solo la velocita'.{N}")
    if ris["ping_base"] is not None and ris["ping_base"] > PING_BASE_MAX:
        # misurare una soglia su una rete gia' ferma darebbe un risultato falso
        return ris | {"esito": "errore",
                      "motivo": (f"rete gia' degradata prima del test (latenza a riposo "
                                 f"{ris['ping_base']:.0f} ms): il risultato non sarebbe attendibile, "
                                 f"aspetta che si riprenda e riprova"),
                      "suggerita": None}

    st = StatoTest(soglia)
    download = threading.Thread(target=flusso, args=(st,), daemon=True)
    download.start()
    lock_prima = lock.riconnessioni if lock else 0

    testo_base = f"{ris['ping_base']:.0f} ms" if ip else "n/d"
    print(f"\n{B}Test a {soglia:g} Mbps per {durata:g} s{N} - server OVH "
          f"- latenza a riposo {testo_base} - antenna {antenna} (premi un tasto per interrompere)\n")
    campioni = []  # (secondo, mbps, ping, byte totali, valido)
    ping_ko = 0
    motivo = None
    t0 = prec_t = inizio_misura = time.monotonic()
    prec_b = 0
    try:
        while True:
            if attendi_tasto(1):
                motivo = "interrotto"
                break
            p = ping_tcp(ip) if ip else None
            adesso, byte = time.monotonic(), st.byte
            mbps = (byte - prec_b) * 8 / 1e6 / (adesso - prec_t)
            prec_t, prec_b = adesso, byte
            sec = adesso - t0

            wifi = w.stato()
            if wifi["stato"] != CONNESSO:
                wifi_ko += 1
                campioni.append((sec, mbps, p, byte, False))
                print(f"[{sec:5.1f}s] {R}Wi-Fi scollegato{N}")
                if wifi_ko >= WIFI_GIU:
                    motivo = "wifi"
                    break
                continue
            wifi_ko = 0
            if wifi["bssid"] != antenna:
                cambi.append((sec, antenna, wifi["bssid"]))
                print(f"[{sec:5.1f}s] {G}il Wi-Fi ha cambiato antenna: {antenna} -> {wifi['bssid']}{N}")
                antenna = wifi["bssid"]

            if st.in_attesa():
                # pausa imposta dal server: questi secondi non dicono nulla
                # sulla rete; alla ripresa la misura ricomincia da capo
                campioni.append((sec, mbps, p, byte, False))
                if st.rifiuti > RIFIUTI_MAX:
                    motivo = "rifiuti"
                    break
                inizio_misura = st.attesa_fino
                ping_ko = 0
                print(f"[{sec:5.1f}s] {G}OVH ha risposto 429 (troppe richieste): "
                      f"riprovo tra {st.attesa_fino - adesso:.0f} s{N}")
                continue

            valido = adesso - inizio_misura >= RISCALDAMENTO
            campioni.append((sec, mbps, p, byte, valido))
            colore = V if mbps >= 0.9 * soglia else G if mbps >= QUOTA_CROLLO * soglia else R
            if not ip:
                testo_ping = "     n/d"
            else:
                testo_ping = f"{p:5.0f} ms" if p is not None else f"{R}  fallito{N}"
            print(f"[{sec:5.1f}s] {colore}{mbps:7.2f}{N} / {soglia:g} Mbps   "
                  f"ping {testo_ping}   tot {byte / 1e6:7.1f} MB")

            if valido:
                # mediana e non "N secondi di fila": una velocita' che oscilla
                # tra buono e pessimo e' comunque un crollo
                finestra = [c[1] for c in campioni if c[4]][-SECONDI_CROLLO:]
                sotto = (len(finestra) == SECONDI_CROLLO
                         and statistics.median(finestra) < QUOTA_CROLLO * soglia)
                ping_ko = ping_ko + 1 if ip and p is None else 0
                if ping_ko >= PING_FALLITI:
                    motivo = f"rete non raggiungibile: {PING_FALLITI} connessioni di prova consecutive fallite"
                    break
                if st.errori_recenti(5) >= ERRORI_CROLLO:
                    motivo = f"errori di connessione continui ({st.errori[-1][1]})"
                    break
                if sotto:
                    motivo = "velocita"
                    break
            # dopo una pausa del server la durata riparte: serve una misura continua
            if adesso - inizio_misura >= durata:
                break
    finally:
        st.ferma.set()
        download.join(timeout=6)

    ris["roaming"] = (lock.riconnessioni - lock_prima) if lock else None
    ris["durata"] = campioni[-1][0] if campioni else 0
    ris["rifiuti"] = st.rifiuti
    ris["cambi_antenna"] = cambi
    utili = [c for c in campioni if c[4]]
    ris["max"] = max((c[1] for c in utili), default=0)
    ping_carico = [c[2] for c in utili if c[2] is not None]
    ris["ping_carico"] = statistics.median(ping_carico) if ping_carico else None

    if motivo == "interrotto":
        return ris | {"esito": "interrotto", "motivo": "interrotto dall'utente", "suggerita": None}

    if motivo == "wifi":
        prima = f" dopo {len(cambi)} cambi d'antenna" if cambi else ""
        return ris | {"esito": "crollo",
                      "motivo": (f"il Wi-Fi si e' scollegato a {ris['durata']:.0f} s{prima}: "
                                 f"non e' traffic shaping, la soglia non c'entra. Blocca "
                                 f"un'antenna (opzione 3) e ripeti il test con la stessa soglia"),
                      "suggerita": None}

    if motivo == "rifiuti":
        return ris | {"esito": "errore",
                      "motivo": (f"OVH sta limitando le richieste (HTTP 429 per {st.rifiuti} volte): "
                                 f"non e' la tua rete. Aspetta un minuto e riprova"),
                      "suggerita": None}

    ris["media"] = statistics.mean(c[1] for c in utili) if utili else 0
    if motivo is None:
        if ris["media"] >= QUOTA_VINCENTE * soglia:
            return ris | {"esito": "vincente", "motivo": None, "suggerita": None}
        ris["reale"] = ris["media"]
        return ris | {"esito": "crollo",
                      "motivo": (f"soglia non sostenuta: media {ris['media']:.2f} Mbps, "
                                 f"sotto l'{QUOTA_VINCENTE:.0%} di {soglia:g} Mbps"),
                      "suggerita": round(ris["media"] * 0.9, 1)}

    if motivo == "velocita":
        # i campioni prima della finestra di crollo = com'era la rete prima
        prima = utili[:-SECONDI_CROLLO]
        dopo = [c[1] for c in utili[-SECONDI_CROLLO:]]
        reale = statistics.median(dopo)
        raggiunta = any(c[1] >= 0.8 * soglia for c in prima)
        inizio = utili[-SECONDI_CROLLO]
        ris["reale"] = reale
        if raggiunta:
            motivo = (f"velocita' crollata dopo {inizio[0]:.0f} s e {inizio[3] / 1e6:.1f} MB scaricati: "
                      f"da ~{soglia:g} a ~{reale:.2f} Mbps. Tipico del traffic shaping "
                      f"(raffica iniziale concessa, poi limitazione)")
        else:
            motivo = (f"la rete non regge {soglia:g} Mbps: massimo misurato "
                      f"{ris['max']:.2f} Mbps, poi stabile a ~{reale:.2f} Mbps")
        suggerita = round(reale * 0.9, 1) if reale >= 0.3 else round(soglia / 2, 1)
    else:
        # rete caduta: si riparte da quanto passava davvero prima del crollo
        passati = [c[1] for c in utili if c[1] > 0]
        misurata = statistics.median(passati) if passati else soglia / 2
        suggerita = round(min(soglia * 0.75, misurata * 0.9), 1)
    # crollo subito dopo un cambio d'antenna: la causa e' il Wi-Fi, non lo shaping
    vicini = [c for c in cambi if c[0] >= ris["durata"] - SECONDI_CROLLO - 3]
    if vicini:
        motivo += (f". Attenzione: coincide con un cambio d'antenna a {vicini[-1][0]:.0f} s, "
                   f"probabilmente non e' shaping: blocca un'antenna (opzione 3) e ripeti")
        suggerita = None
    return ris | {"esito": "crollo", "motivo": motivo, "suggerita": suggerita}


def stampa_risultato(r):
    print()
    if r["esito"] == "vincente":
        print(f"{V}{B}SOGLIA VINCENTE: {r['soglia']:g} Mbps{N} sostenuti per {r['durata']:.0f} s "
              f"(media {r['media']:.2f} Mbps)")
    elif r["esito"] == "interrotto":
        print(f"{G}Test interrotto dopo {r.get('durata', 0):.0f} s.{N}")
    elif r["esito"] == "errore":
        print(f"{R}{B}TEST NON ESEGUITO{N}")
        print(f"{R}{r['motivo']}{N}")
    else:
        print(f"{R}{B}RETE CROLLATA a {r['soglia']:g} Mbps{N}")
        print(f"{R}{r['motivo']}{N}")
        if r["suggerita"]:
            print(f"Prova ad abbassare la soglia, ad esempio a {B}{r['suggerita']:g} Mbps{N}.")

    if r.get("ping_base") is not None and r.get("ping_carico") is not None:
        print(f"Latenza: {r['ping_base']:.0f} ms a riposo, {r['ping_carico']:.0f} ms sotto carico", end="")
        if r["ping_carico"] > 3 * r["ping_base"] + 50:
            print(f" {G}-> gonfiata: la rete accoda i pacchetti, sei vicino al limite{N}")
        else:
            print()
    if r.get("cambi_antenna"):
        elenco = ", ".join(f"{c[0]:.0f} s" for c in r["cambi_antenna"])
        print(f"{G}Durante il test il Wi-Fi ha cambiato antenna {len(r['cambi_antenna'])} volte "
              f"(a {elenco}).{N}")
    if r.get("rifiuti") and r["esito"] != "errore":
        print(f"{G}OVH ha chiesto di aspettare {r['rifiuti']} volte (HTTP 429); "
              f"quei secondi sono esclusi dalla misura.{N}")
    if r.get("roaming"):
        print(f"{G}Durante il test il lock ha dovuto riagganciare l'antenna {r['roaming']} volte.{N}")


def stampa_storico():
    if not storico:
        return
    print(f"{B}Test precedenti:{N}")
    for r in storico:
        segno = {"vincente": f"{V}OK{N}", "crollo": f"{R}CROLLO{N}"}.get(r["esito"], f"{G}{r['esito']}{N}")
        extra = f" (reale ~{r['reale']:.2f} Mbps)" if r.get("reale") is not None else ""
        print(f"  [{r['ora']}] {r['soglia']:>7g} Mbps  {segno}{extra}")
    print()


def menu_shaping(lock):
    # loop real-time: il risultato dell'ultimo test resta a schermo (nessuna
    # pausa "premi un tasto"); soglia vuota = torna al menu
    dettaglio = ""
    while True:
        cls()
        print(f"{B}Test traffic shaping{N}\n")
        print("Scarica a una velocita' fissa (la soglia) e controlla che la rete la regga.")
        print("Soglia vuota = torna al menu.\n")
        stampa_storico()
        if dettaglio:
            print(dettaglio)
        suggerita = storico[-1]["suggerita"] if storico and storico[-1]["suggerita"] else None
        coda = f" (invio = {suggerita:g})" if suggerita else " (invio = torna al menu)"
        soglia = leggi_numero(f"Soglia in Mbps{coda}: ", suggerita)
        if soglia is None:
            return
        durata = leggi_numero("Durata in secondi (invio = 60): ", 60)
        if durata is None:
            return
        r = test_shaping(soglia, durata, lock)
        storico.append(r)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            stampa_risultato(r)
        dettaglio = buf.getvalue()
        scrivi_log(f"shaping {soglia:g} Mbps -> {r['esito']}"
                   + (f": {_senza_colori(r['motivo'])}" if r.get("motivo") else ""))


# ---------------------------------------------------------------- 7. limite di banda

# Se il PC non supera mai la velocita' a cui la rete fa traffic shaping,
# il limitatore della rete non scatta e non ci blocca.
# Windows sa limitare da solo solo l'upload (QoS), non il download: per
# questo intercettiamo i pacchetti della scheda Wi-Fi con WinDivert
# (driver di pydivert, serve l'amministratore) e li rilasciamo al ritmo
# scelto. Se un pacchetto dovrebbe aspettare troppo lo scartiamo: TCP (e
# QUIC) interpretano la perdita come congestione e il mittente rallenta.
# Se il programma si chiude o va in crash, il driver rilascia la scheda e
# il traffico torna normale da solo.

LIMITE_PREDEFINITO = 10  # Mbps, per direzione (download e upload separati)
CODA_MAX = 0.2           # secondi massimi di attesa in coda, oltre si scarta

limite_scelto = LIMITE_PREDEFINITO


def e_amministratore():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def riavvia_come_amministratore():
    # UAC: rilancia il programma in una nuova console elevata. "--elevato"
    # evita un ciclo infinito se l'elevazione non da' davvero i permessi.
    if getattr(sys, "frozen", False):
        # eseguibile PyInstaller: si rilancia l'exe stesso
        programma, parametri = sys.executable, "--elevato"
        cartella = os.path.dirname(sys.executable)
    else:
        script = os.path.abspath(__file__)
        programma, parametri = sys.executable, f'"{script}" --elevato'
        cartella = os.path.dirname(script)
    esito = ctypes.windll.shell32.ShellExecuteW(None, "runas", programma, parametri, cartella, 1)
    return esito > 32  # ShellExecute: valori <= 32 sono errori (es. UAC rifiutato)


def indice_interfaccia(guid):
    # WinDivert filtra per indice di interfaccia; wlanapi ci da' il GUID
    iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    luid = ctypes.c_uint64()
    indice = wintypes.ULONG()
    if (iphlpapi.ConvertInterfaceGuidToLuid(ctypes.byref(guid), ctypes.byref(luid))
            or iphlpapi.ConvertInterfaceLuidToIndex(ctypes.byref(luid), ctypes.byref(indice))):
        raise OSError("impossibile trovare l'indice della scheda Wi-Fi")
    return indice.value


class LimiteBanda(threading.Thread):
    # Due punti di intercettazione:
    #  - "rete" (scheda Wi-Fi): il traffico del PC stesso;
    #  - "inoltro": il traffico dei dispositivi collegati all'hotspot, che
    #    Windows inoltra fra Wi-Fi e hotspot. E' l'unico punto in cui si puo'
    #    frenarlo: sul livello "rete" il loro download compare solo come
    #    copia, e scartarla non serve (verificato: il telefono riceveva
    #    87 Mbps con il livello "rete" fermo a 10).
    # Per non contare due volte il telefono, dal livello di inoltro si
    # annotano i server con cui parlano i dispositivi in hotspot; sul livello
    # "rete" i pacchetti in arrivo da quei server passano senza essere contati.
    # Download e upload hanno ciascuno un solo secchiello condiviso: il
    # limite vale per il totale di PC + dispositivi in hotspot.

    def __init__(self, mbps, indice):
        super().__init__(daemon=True)
        self.mbps = mbps  # modificabile mentre gira
        self.indice = indice
        self.ferma = threading.Event()
        self.coda = []    # heap di (istante di invio, progressivo, handle, pacchetto)
        self.cond = threading.Condition()
        self.lock = threading.Lock()  # secchielli condivisi fra i due punti
        self.progressivo = itertools.count()
        self.prossimo = {True: 0.0, False: 0.0}  # per direzione (True = download)
        self.byte = {True: 0, False: 0}
        self.byte_hotspot = {True: 0, False: 0}  # di cui dispositivi in hotspot
        self.server_hotspot = {}  # (indirizzo, porta) remoto -> ultimo pacchetto visto
        self.ultima_pulizia = time.monotonic()
        self.scartati = 0
        self.errore = None
        self.handles = {}

    def run(self):
        import pydivert
        punti = {"rete": (pydivert.Layer.NETWORK, f"ifIdx == {self.indice} and !loopback"),
                 "inoltro": (pydivert.Layer.NETWORK_FORWARD, "true")}
        try:
            for nome, (layer, filtro) in punti.items():
                handle = pydivert.WinDivert(filtro, layer=layer)
                handle.open()
                self.handles[nome] = handle
        except Exception as e:
            self.errore = f"impossibile avviare WinDivert: {e}"
            self._chiudi()
            return
        invio = threading.Thread(target=self._invia_in_coda, daemon=True)
        invio.start()
        inoltro = threading.Thread(target=self._ricevi, args=(self.handles["inoltro"], True), daemon=True)
        inoltro.start()
        try:
            self._ricevi(self.handles["rete"], False)
        finally:
            self.ferma.set()
            self._sblocca()
            with self.cond:
                self.cond.notify()
            inoltro.join(timeout=2)
            invio.join(timeout=2)
            self._chiudi()

    def _ricevi(self, handle, inoltrato):
        while not self.ferma.is_set():
            try:
                pacchetto = handle.recv()
            except Exception as e:
                if not self.ferma.is_set():
                    self.errore = f"ricezione pacchetti interrotta: {e}"
                    self.ferma.set()
                    self._sblocca()
                return
            n = len(pacchetto.raw)
            if not n:
                continue
            if inoltrato:
                # sul livello di inoltro ifIdx e' la scheda di uscita:
                # verso il Wi-Fi e' upload, verso l'hotspot e' download
                verso_wifi = pacchetto.interface[0] == self.indice
                entrata = not verso_wifi
                if verso_wifi:
                    remoto = (pacchetto.dst_addr, pacchetto.dst_port)
                else:
                    remoto = (pacchetto.src_addr, pacchetto.src_port)
                self.server_hotspot[remoto] = time.monotonic()
            else:
                entrata = pacchetto.is_inbound
                if entrata and (pacchetto.src_addr, pacchetto.src_port) in self.server_hotspot:
                    # copia del download di un dispositivo in hotspot: la
                    # frena (e la conta) il livello di inoltro
                    self._invia(handle, pacchetto)
                    continue
            self._pulisci_server()
            with self.lock:
                adesso = time.monotonic()
                quando = max(self.prossimo[entrata], adesso)
                if quando - adesso > CODA_MAX:
                    self.scartati += 1  # coda piena: la perdita fa rallentare il mittente
                    continue
                self.prossimo[entrata] = quando + n * 8 / (self.mbps * 1e6)
                self.byte[entrata] += n
                if inoltrato:
                    self.byte_hotspot[entrata] += n
            if quando <= adesso:
                self._invia(handle, pacchetto)
            else:
                with self.cond:
                    heapq.heappush(self.coda, (quando, next(self.progressivo), handle, pacchetto))
                    self.cond.notify()

    def _pulisci_server(self):
        # dimentica i server che i dispositivi in hotspot non usano da 3 minuti
        adesso = time.monotonic()
        if adesso - self.ultima_pulizia < 30:
            return
        self.ultima_pulizia = adesso
        for chiave, visto in list(self.server_hotspot.items()):
            if adesso - visto > 180:
                self.server_hotspot.pop(chiave, None)

    def _invia(self, handle, pacchetto):
        try:
            handle.send(pacchetto, recalculate_checksum=False)
        except Exception:
            pass  # handle chiuso mentre si fermava: il pacchetto si perde

    def _invia_in_coda(self):
        while True:
            with self.cond:
                while not self.ferma.is_set():
                    if self.coda and self.coda[0][0] <= time.monotonic():
                        break
                    attesa = self.coda[0][0] - time.monotonic() if self.coda else None
                    self.cond.wait(attesa)
                if self.ferma.is_set():
                    return
                _, _, handle, pacchetto = heapq.heappop(self.coda)
            self._invia(handle, pacchetto)

    def _sblocca(self):
        # WinDivertShutdown sblocca le recv() in attesa su tutti gli handle
        import pydivert
        for handle in self.handles.values():
            if handle.is_open:
                pydivert.windivert_dll.WinDivertShutdown(handle._handle, 3)  # WINDIVERT_SHUTDOWN_BOTH

    def _chiudi(self):
        for handle in self.handles.values():
            try:
                handle.close()
            except Exception:
                pass

    def in_coda(self):
        return len(self.coda)

    def stop(self):
        self.ferma.set()
        self._sblocca()
        self.join(timeout=5)


def chiedi_limite():
    global limite_scelto
    valore = leggi_numero(f"Limite in Mbps (invio = {limite_scelto:g}): ", limite_scelto)
    if valore is None:
        avvisa(f"{R}Valore del limite non valido.{N}")
        return None
    limite_scelto = valore
    return valore


def mostra_limite(limite):
    # vista in tempo reale; [m] modifica il limite, [s] lo rimuove
    prec = dict(limite.byte)
    prec_hotspot = dict(limite.byte_hotspot)
    prec_scartati = limite.scartati
    prec_t = time.monotonic()
    while True:
        tasto = None
        fine = time.monotonic() + 1
        while time.monotonic() < fine and tasto is None:
            if msvcrt.kbhit():
                tasto = msvcrt.getwch().lower()
            time.sleep(0.05)
        if tasto == "m":
            nuovo = chiedi_limite()
            if nuovo:
                limite.mbps = nuovo
            continue
        if tasto == "s":
            limite.stop()
            return None
        if tasto is not None:
            return limite

        adesso = time.monotonic()
        dt = adesso - prec_t
        giu = (limite.byte[True] - prec[True]) * 8 / 1e6 / dt
        su = (limite.byte[False] - prec[False]) * 8 / 1e6 / dt
        hot_giu = (limite.byte_hotspot[True] - prec_hotspot[True]) * 8 / 1e6 / dt
        hot_su = (limite.byte_hotspot[False] - prec_hotspot[False]) * 8 / 1e6 / dt
        scartati = limite.scartati - prec_scartati
        prec, prec_scartati, prec_t = dict(limite.byte), limite.scartati, adesso
        prec_hotspot = dict(limite.byte_hotspot)

        cls()
        print(f"{B}LIMITE DI BANDA: {limite.mbps:g} Mbps{N} (download e upload, ciascuno; "
              f"PC + dispositivi in hotspot insieme) "
              f"- scheda Wi-Fi ifIdx {limite.indice}\n")
        if not limite.is_alive():
            avvisa(f"{R}Il limite di banda si e' fermato: {limite.errore}{N}")
            return None
        for nome, valore in (("download", giu), ("upload", su)):
            percento = min(100, valore / limite.mbps * 100)
            colore = R if percento >= 95 else G if percento >= 70 else V
            print(f"  {nome:<9} {colore}{barra(percento, 20)} {valore:6.2f}{N} / {limite.mbps:g} Mbps")
        print(f"  {'':<9} di cui dispositivi in hotspot: {hot_giu:.2f} giu / {hot_su:.2f} su Mbps")
        print(f"\n  pacchetti in coda: {limite.in_coda()}   scartati: {limite.scartati} "
              f"(ultimo secondo: {scartati})")
        print("\n[m] modifica il limite   [s] rimuovi il limite   "
              "[altro tasto] torna al menu (il limite resta attivo)")


def menu_limite(w, limite):
    # restituisce il limitatore attivo (o None) e se il programma deve uscire
    if limite and limite.is_alive():
        return mostra_limite(limite), False
    cls()
    print(f"{B}Limite di banda{N}\n")
    print("Tiene tutto il traffico del PC sotto una soglia, cosi' il traffic shaping")
    print("della rete non scatta. Serve il programma avviato come amministratore.\n")
    try:
        import pydivert  # noqa: F401
    except ImportError:
        avvisa(f"{R}Manca pydivert:{N} .venv\\Scripts\\python.exe -m pip install pydivert")
        return None, False
    if not e_amministratore():
        print(f"{G}Il programma non e' avviato come amministratore.{N}")
        if input("Lo riavvio come amministratore? Il lock attivo verra' fermato (s/N): ").strip().lower() == "s":
            if riavvia_come_amministratore():
                return None, True
            avvisa(f"{R}Riavvio come amministratore non riuscito (UAC rifiutato?).{N}")
        return None, False
    mbps = chiedi_limite()
    if mbps is None:
        return None, False
    nuovo = LimiteBanda(mbps, indice_interfaccia(w.guid))
    nuovo.start()
    time.sleep(0.5)
    if not nuovo.is_alive():
        avvisa(f"{R}Limite di banda non avviato: {nuovo.errore}{N}")
        return None, False
    return mostra_limite(nuovo), False


# ---------------------------------------------------------------- 9. stato della connessione

# Stesso controllo che fa Windows (NCSI): se si naviga davvero, questo URL
# risponde con un testo fisso. Un captive portal invece risponde con un
# redirect verso la pagina di accesso, o con una pagina diversa.
URL_VERIFICA = "http://www.msftconnecttest.com/connecttest.txt"
TESTO_VERIFICA = b"Microsoft Connect Test"
INTERVALLO_VERIFICA = 10   # secondi tra un controllo e l'altro
INTERVALLO_VISTA = 3       # piu' frequente mentre la schermata di stato e' aperta

NOMI_STATO = {"ok": f"{V}OK{N}",
              "portale": f"{R}CAPTIVE PORTAL: serve l'accesso{N}",
              "offline": f"{R}NESSUNA CONNESSIONE{N}",
              "verifica": f"{G}verifica in corso...{N}"}

# --- login automatico al captive portal --------------------------------------
# Alcune reti (tipico degli hotel/foresterie) buttano di nuovo sul portale ogni
# pochi minuti: qui, quando lo stato diventa "portale", si rifa' l'accesso da
# solo con le credenziali salvate, cosi' non serve riloggarsi a mano.
#
# In automatico si scarica la pagina del portale e si cerca il form di login
# (campo password + campo testo per l'utente): funziona con la maggior parte
# dei portali. Se l'auto-rilevamento non basta (form generato via JavaScript,
# endpoint particolare), si fissano qui i dettagli esatti presi con F12:
PORTALE_LOGIN_URL = ""      # es. "http://<ip-gateway>/cgi-bin/login"
PORTALE_LOGIN_METODO = "POST"
PORTALE_CAMPO_UTENTE = ""   # nome del campo utente, es. "user"
PORTALE_CAMPO_PASSWORD = ""  # nome del campo password, es. "password"
PORTALE_CAMPI_EXTRA = {}    # campi fissi aggiuntivi, es. {"cmd": "authenticate"}

MIN_INTERVALLO_LOGIN = 8    # secondi minimi tra due tentativi di login


def cartella_dati():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


FILE_PORTALE = os.path.join(cartella_dati(), "portale_login.json")


def carica_portale():
    # credenziali salvate accanto al programma (in chiaro: e' un login "ospite")
    try:
        with open(FILE_PORTALE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def salva_portale(dati):
    try:
        with open(FILE_PORTALE, "w", encoding="utf-8") as f:
            json.dump(dati, f)
        return True
    except OSError:
        return False


class RaccoltaForm(HTMLParser):
    # raccoglie i <form> della pagina con i loro <input>, segnando qual e' il
    # campo password e quali i campi di testo (candidati per l'utente)
    def __init__(self):
        super().__init__()
        self.forms = []
        self._corrente = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._corrente = {"action": a.get("action", ""),
                              "method": (a.get("method") or "get").lower(),
                              "campi": {}, "pwd": None, "testo": []}
            self.forms.append(self._corrente)
        elif tag == "input" and self._corrente is not None and a.get("name"):
            nome = a["name"]
            tipo = (a.get("type") or "text").lower()
            self._corrente["campi"][nome] = a.get("value", "")
            if tipo == "password":
                self._corrente["pwd"] = nome
            elif tipo in ("text", "email", "tel", ""):
                self._corrente["testo"].append(nome)

    def handle_endtag(self, tag):
        if tag == "form":
            self._corrente = None


def _invia_login(opener, url, metodo, dati):
    query = urllib.parse.urlencode(dati)
    try:
        if metodo.lower() == "post":
            req = urllib.request.Request(url, data=query.encode(), headers=UA)
        else:
            unione = "&" if "?" in url else "?"
            req = urllib.request.Request(f"{url}{unione}{query}", headers=UA)
        with opener.open(req, timeout=8) as r:
            r.read(2000)
        return True, "richiesta inviata"
    except urllib.error.HTTPError as e:
        # un 3xx qui di solito e' il rimando alla pagina "sei dentro"
        return 300 <= e.code < 400, f"HTTP {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}"


# Template per i captive portal Subgate/SonicWall. ATTENZIONE: qui non ci sono
# dati di una rete reale. Per usare questa modalita' compila la sezione
# "subgate_cfg" in portale_login.json con i valori della tua rete (URL dell'API,
# origin, ID hesapgrup/sablon, baseurl, lingua), che si ricavano osservando la
# richiesta di login del portale con gli strumenti sviluppatore del browser (F12).
# Con questi default vuoti la modalita' Subgate e' una semplice ossatura: senza
# configurazione il login non parte (vedi il controllo in login_subgate).
SUBGATE = {
    "api_url": "",     # es. http://<ip-portale>:<porta>/.../login
    "origin": "",      # es. http://<ip-portale>:<porta>
    "hesapgrup": "",   # ID gruppo account, dalla richiesta catturata
    "sablon": "",      # ID template, dalla richiesta catturata
    "platform": "sonicwall",
    "baseurl": "",     # es. https://<gateway>:<porta>/
    "dil": "",         # codice lingua del portale, es. "it", "en"
    "corpo_extra": {}, # campi extra del portale aggiunti al corpo del login;
                       # usa "__PASSWORD__" dove serve la password (vedi README)
}


def _testo_portale(opener, url_portale):
    # scarica la pagina del portale (e gli eventuali salti verso il server del
    # portale su una porta dedicata) e restituisce URL finali + corpi, per
    # estrarne i parametri di sessione. url-decodifica tutto cosi' i due-punti
    # del mac e gli '&' tornano leggibili.
    pezzi = []
    visti = set()
    partenza = url_portale if (url_portale or "").startswith("http") else URL_VERIFICA
    da_fare = [partenza]
    for _ in range(4):
        if not da_fare:
            break
        u = da_fare.pop(0)
        if u in visti:
            continue
        visti.add(u)
        try:
            with opener.open(urllib.request.Request(u, headers=UA), timeout=8) as r:
                corpo = r.read(200000).decode("utf-8", "replace")
                pezzi.append(r.geturl())
                pezzi.append(corpo)
        except Exception:
            continue
        # eventuali rimandi al portale (URL con porta esplicita) che possono
        # contenere il sessionId nel corpo della pagina
        for m in re.findall(r'https?://[0-9.]+:\d+/[^\s"\'<>]+', corpo):
            da_fare.append(m.replace("&amp;", "&"))
    return urllib.parse.unquote("\n".join(pezzi))


def _cerca_campo(nome, testo, valore_re):
    # trova un parametro nella pagina in tutte le forme possibili:
    #   sessionId=xxx  |  "sessionId":"xxx"  |  name="sessionId" value="xxx"
    for pat in (rf'{nome}["\']?\s*[:=]\s*["\']?({valore_re})',
                rf'name=["\']{nome}["\'][^>]*?value=["\']({valore_re})["\']',
                rf'value=["\']({valore_re})["\'][^>]*?name=["\']{nome}["\']'):
        m = re.search(pat, testo, re.I)
        if m:
            return m.group(1)
    return None


PWD_SEGNAPOSTO = "__PASSWORD__"


def _sostituisci_pwd(oggetto, password):
    # sostituisce ricorsivamente il segnaposto con la password reale nei
    # campi extra presi dalla configurazione
    if isinstance(oggetto, dict):
        return {k: _sostituisci_pwd(v, password) for k, v in oggetto.items()}
    if isinstance(oggetto, list):
        return [_sostituisci_pwd(v, password) for v in oggetto]
    return password if oggetto == PWD_SEGNAPOSTO else oggetto


def login_subgate(utente, password, url_portale, cfg):
    # portale Subgate/SonicWall: legge il sessionId corrente dalla pagina e
    # reinvia il login come JSON all'API (stateless, tutto nel corpo)
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    testo = _testo_portale(opener, url_portale)

    # default del codice (vuoti), sovrascritti dalle chiavi in "subgate_cfg"
    sg = {**SUBGATE, **((cfg or {}).get("subgate_cfg") or {})}
    if not sg["api_url"] or not sg["origin"]:
        return False, ("modalita' Subgate non configurata: compila la sezione "
                       "'subgate_cfg' in portale_login.json (api_url, origin, ecc.)")

    session_id = _cerca_campo("sessionId", testo, r"[0-9a-fA-F]{16,}")
    if not session_id:
        return False, "sessionId non trovato nella pagina del portale (cattura anche la richiesta 'kontrol')"

    mac = _cerca_campo("mac", testo, r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}") or cfg.get("mac", "")
    if not mac:
        return False, "mac non trovato: impostalo nelle impostazioni avanzate"

    corpo = {"username": utente, "password": password, "user": utente, "mac": mac,
             "cmd": "authenticate", "platform": sg["platform"], "magic": "",
             "hesapgrup": sg["hesapgrup"], "sablon": sg["sablon"],
             "dil": sg["dil"], "sessionId": session_id, "baseurl": sg["baseurl"]}
    # campi extra specifici del portale, forniti dall'utente in subgate_cfg
    # ("corpo_extra"): scrivi "__PASSWORD__" dove serve la password, che viene
    # reiniettata qui (cosi' non va messa in chiaro nel file di configurazione)
    corpo.update(_sostituisci_pwd(sg.get("corpo_extra") or {}, password))
    intestazioni = {**UA, "Content-Type": "application/json",
                    "Accept": "application/json, text/plain, */*",
                    "Origin": sg["origin"], "Referer": sg["origin"] + "/"}
    req = urllib.request.Request(sg["api_url"], data=json.dumps(corpo).encode(),
                                 method="POST", headers=intestazioni)
    try:
        with opener.open(req, timeout=8) as r:
            risposta = r.read(2000).decode("utf-8", "replace")
        return True, f"inviato (sessionId {session_id[:8]}...), risposta: {risposta[:100]}"
    except urllib.error.HTTPError as e:
        dettaglio = e.read(200).decode("utf-8", "replace") if hasattr(e, "read") else ""
        return False, f"HTTP {e.code} {dettaglio[:100]}"
    except Exception as e:
        return False, f"{type(e).__name__}"


def login_portale(utente, password, url_portale, cfg=None):
    # cfg = configurazione impostata dall'interfaccia (ha priorita' sulle
    # costanti in cima al file). Segue i redirect e conserva i cookie di
    # sessione per tutta la procedura.
    cfg = cfg or {}
    if cfg.get("subgate"):
        return login_subgate(utente, password, url_portale, cfg)
    login_url = cfg.get("login_url") or PORTALE_LOGIN_URL
    campo_u = cfg.get("campo_utente") or PORTALE_CAMPO_UTENTE
    campo_p = cfg.get("campo_password") or PORTALE_CAMPO_PASSWORD
    metodo = cfg.get("metodo") or PORTALE_LOGIN_METODO
    extra = cfg.get("campi_extra") or PORTALE_CAMPI_EXTRA

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # 1) indirizzo + nomi dei campi fissati a mano: si invia direttamente
    if login_url and campo_u and campo_p:
        dati = dict(extra)
        dati[campo_u] = utente
        dati[campo_p] = password
        return _invia_login(opener, login_url, metodo, dati)

    # 2) automatico: scarica la pagina (l'indirizzo scelto, o il redirect del
    #    portale, o come ultima spiaggia l'URL di verifica) e cerca il form
    target = login_url or url_portale
    if not target or not target.startswith("http"):
        target = URL_VERIFICA  # l'opener segue il redirect fino al portale
    try:
        with opener.open(urllib.request.Request(target, headers=UA), timeout=8) as r:
            pagina = r.read(200000).decode("utf-8", "replace")
            base = r.geturl()
    except Exception as e:
        return False, f"pagina del portale non raggiungibile ({type(e).__name__})"

    p = RaccoltaForm()
    p.feed(pagina)
    form = next((f for f in p.forms if f["pwd"] and f["testo"]), None)
    if form is None:
        return False, "form di login non trovato (imposta l'indirizzo esatto o i nomi dei campi)"
    dati = dict(form["campi"])
    dati[form["pwd"]] = password
    dati[form["testo"][0]] = utente
    action = urllib.parse.urljoin(base, form["action"]) if form["action"] else base
    return _invia_login(opener, action, form["method"], dati)


class SenzaRedirect(urllib.request.HTTPRedirectHandler):
    # un redirect e' proprio il segnale del portale: non va seguito
    def redirect_request(self, *args, **kwargs):
        return None


class StatoInternet(threading.Thread):

    def __init__(self):
        super().__init__(daemon=True)
        self.stato = "verifica"
        self.dettaglio = ""
        self.dal = datetime.now()     # da quando e' in questo stato
        self.ultimo_distacco = None   # ultima volta che si e' perso Internet
        self.eventi = deque(maxlen=20)
        self.intervallo = INTERVALLO_VERIFICA
        self.subito = threading.Event()  # chiede un controllo immediato
        self.apri = urllib.request.build_opener(SenzaRedirect).open
        cfg = carica_portale()
        self.utente = cfg.get("utente", "")
        self.password = cfg.get("password", "")
        self.auto_login = cfg.get("auto", False)
        # indirizzo e nomi dei campi, tutti modificabili dall'interfaccia
        self.login_url = cfg.get("login_url", PORTALE_LOGIN_URL)
        self.campo_utente = cfg.get("campo_utente", PORTALE_CAMPO_UTENTE)
        self.campo_password = cfg.get("campo_password", PORTALE_CAMPO_PASSWORD)
        self.metodo = cfg.get("metodo", PORTALE_LOGIN_METODO)
        self.subgate = cfg.get("subgate", False)  # handler dedicato Subgate/SonicWall
        self.mac = cfg.get("mac", "")             # forzato a mano se non si legge dalla pagina
        self.subgate_cfg = cfg.get("subgate_cfg", {})  # override dei default SUBGATE
        self.login_ok = 0            # quante volte il login automatico e' riuscito
        self._ultimo_login = 0.0     # per non ritentare troppo in fretta

    def config_login(self):
        return {"login_url": self.login_url, "campo_utente": self.campo_utente,
                "campo_password": self.campo_password, "metodo": self.metodo,
                "subgate": self.subgate, "mac": self.mac,
                "subgate_cfg": self.subgate_cfg}

    def salva_credenziali(self):
        return salva_portale({"utente": self.utente, "password": self.password,
                              "auto": self.auto_login, "login_url": self.login_url,
                              "campo_utente": self.campo_utente,
                              "campo_password": self.campo_password, "metodo": self.metodo,
                              "subgate": self.subgate, "mac": self.mac,
                              "subgate_cfg": self.subgate_cfg})

    def _prova_login(self, url_portale):
        # tenta il login e, se va, riverifica; restituisce (stato, dettaglio)
        if time.monotonic() - self._ultimo_login < MIN_INTERVALLO_LOGIN:
            return None
        self._ultimo_login = time.monotonic()
        # avviso udibile e a schermo: si vede/sente da qualsiasi schermata
        self.eventi.append(f"[{ora()}] {G}portale rilevato: provo il login ({self.utente})...{N}")
        avvisa_suono()
        ok, info = login_portale(self.utente, self.password, url_portale, self.config_login())
        if ok:
            stato, dettaglio = self.controlla()
            if stato == "ok":
                self.login_ok += 1
                self.eventi.append(f"[{ora()}] {V}login automatico riuscito{N} ({self.utente})")
                scrivi_log(f"login portale automatico riuscito ({self.utente})")
                return stato, dettaglio
            self.eventi.append(f"[{ora()}] login inviato ma ancora {stato} ({info})")
            scrivi_log(f"login portale inviato ma ancora {stato} ({info})")
            return stato, dettaglio
        self.eventi.append(f"[{ora()}] {R}login automatico fallito{N}: {info}")
        scrivi_log(f"login portale automatico fallito: {info}")
        return None

    def controlla(self):
        try:
            with self.apri(urllib.request.Request(URL_VERIFICA, headers=UA), timeout=5) as r:
                corpo = r.read(200)
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                return "portale", e.headers.get("Location", "")
            return "portale", f"HTTP {e.code}"
        except Exception as e:
            return "offline", type(e).__name__
        if corpo.startswith(TESTO_VERIFICA):
            return "ok", ""
        return "portale", "risposta diversa da quella attesa"

    def run(self):
        while True:
            stato, dettaglio = self.controlla()
            # portale rilevato e login automatico attivo: prova a rientrare
            if stato == "portale" and self.auto_login and self.utente and self.password:
                esito = self._prova_login(dettaglio)
                if esito is not None:
                    stato, dettaglio = esito
            if stato != self.stato:
                if self.stato == "ok":
                    self.ultimo_distacco = datetime.now()
                colore = V if stato == "ok" else R
                self.eventi.append(f"[{ora()}] {self.stato} -> {colore}{stato}{N}"
                                   f"{f' ({dettaglio})' if dettaglio else ''}")
                scrivi_log(f"Internet: {self.stato} -> {stato}"
                           + (f" ({dettaglio})" if dettaglio else ""))
                self.stato = stato
                self.dal = datetime.now()
            self.dettaglio = dettaglio
            self.subito.wait(self.intervallo)
            self.subito.clear()

    def riga(self):
        testo = f"Internet: {NOMI_STATO[self.stato]}"
        if self.stato != "verifica":
            testo += f" dalle {self.dal.strftime('%H:%M:%S')}"
        if self.stato == "portale" and self.dettaglio:
            testo += f" -> {self.dettaglio}"
        if self.ultimo_distacco and self.stato == "ok":
            testo += f"  (ultimo distacco: {self.ultimo_distacco.strftime('%H:%M:%S')})"
        return testo


def riga_wifi(w):
    s = w.stato()
    if s["stato"] == CONNESSO:
        return (f"Wi-Fi: {V}connesso{N} a {s['ssid']}  {s['bssid']}  {banda_da_canale(s['canale'])} "
                f"can {s['canale']}  {s['segnale']}% ({s['rssi']} dBm)")
    if s["stato"] in IN_CORSO:
        return f"Wi-Fi: {G}connessione in corso...{N}"
    return f"Wi-Fi: {R}non connesso{N}"


def mostra_stato(w, internet, lock, limite, hs):
    # schermata in tempo reale; [r] forza un controllo di Internet
    internet.intervallo = INTERVALLO_VISTA
    internet.subito.set()
    prec = dict(limite.byte) if limite else None
    prec_t = time.monotonic()
    try:
        while True:
            cls()
            print(f"{B}Stato della connessione{N} - {ora()}\n")
            print(riga_wifi(w))
            print(internet.riga())
            print(riga_hotspot(hs))
            if lock:
                stato_lock = f"{V}attivo{N}" if lock.is_alive() else f"{R}fermato{N}"
                print(f"Lock: {stato_lock} su {lock.bssid} ({lock.ssid}) - "
                      f"riconnessioni forzate: {lock.riconnessioni}")
            else:
                print("Lock: spento")
            if limite and limite.is_alive():
                adesso = time.monotonic()
                dt = adesso - prec_t
                giu = (limite.byte[True] - prec[True]) * 8 / 1e6 / dt
                su = (limite.byte[False] - prec[False]) * 8 / 1e6 / dt
                prec, prec_t = dict(limite.byte), adesso
                print(f"Limite: {V}attivo{N} a {limite.mbps:g} Mbps - ora {giu:.2f} giu / {su:.2f} su - "
                      f"scartati: {limite.scartati}")
            else:
                print("Limite: spento")
            print(riga_portale(internet))
            print(f"\n{B}Cambi di stato di Internet:{N}")
            for e in list(internet.eventi)[-10:]:
                print(" ", e)
            print("\n[r] ricontrolla Internet adesso   [altro tasto] torna al menu")
            tasto = None
            fine = time.monotonic() + 1
            while time.monotonic() < fine and tasto is None:
                if msvcrt.kbhit():
                    tasto = msvcrt.getwch().lower()
                time.sleep(0.05)
            if tasto == "r":
                internet.subito.set()
            elif tasto is not None:
                return
    finally:
        internet.intervallo = INTERVALLO_VERIFICA


def riga_portale(internet):
    if internet.auto_login and internet.utente:
        extra = f" - accessi rifatti: {internet.login_ok}" if internet.login_ok else ""
        return f"Login portale: {V}automatico{N} (utente {internet.utente}){extra}"
    if internet.utente:
        return f"Login portale: {G}configurato ma spento{N} (utente {internet.utente})"
    return "Login portale: non configurato"


def _chiedi_salvataggio(internet):
    salvare = input("Salvo la configurazione per i prossimi avvii? (in chiaro) (s/N): ")
    if salvare.strip().lower() == "s":
        if internet.salva_credenziali():
            return f"{V}Configurazione salvata in {FILE_PORTALE}{N}"
        return f"{R}Impossibile salvare il file di configurazione.{N}"
    return f"{G}Configurazione tenuta solo per questa sessione.{N}"


def menu_portale(internet):
    messaggio = ""
    while True:
        cls()
        print(f"{B}Login automatico al captive portal{N}\n")
        print("Quando la rete ti ributta sul portale, il programma rifa' l'accesso")
        print("da solo con le credenziali salvate, senza che tu debba riloggarti.\n")
        print(riga_portale(internet))
        print(f"  Utente:    {internet.utente or '(non impostato)'}")
        print(f"  Password:  {'*' * len(internet.password) if internet.password else '(non impostata)'}")
        modo = f"{V}Subgate/SonicWall{N}" if internet.subgate else "automatica (form)"
        print(f"  Modalita': {modo}")
        if internet.subgate:
            print(f"  MAC:       {internet.mac or '(letto dalla pagina del portale)'}")
        else:
            print(f"  Indirizzo: {internet.login_url or '(automatico: rilevato dal redirect)'}")
            if internet.campo_utente or internet.campo_password:
                print(f"  Campi:     utente='{internet.campo_utente}'  password='{internet.campo_password}'"
                      f"  ({internet.metodo})")
        if messaggio:
            print(f"\n{messaggio}")
            messaggio = ""
        print()
        print("1. Imposta utente e password")
        print(f"2. {'Disattiva' if internet.subgate else 'Attiva'} la modalita' Subgate (portale di questa rete)")
        print(f"3. {'Disattiva' if internet.auto_login else 'Attiva'} il login automatico")
        print("4. Prova il login adesso")
        print("5. Impostazioni avanzate (indirizzo, campi, MAC)")
        print("6. Cancella tutta la configurazione")
        print("\n0. Torna al menu")
        scelta = input("\nScelta: ").strip()
        if scelta == "1":
            utente = input("Utente: ").strip()
            if not utente:
                continue
            password = input("Password: ").strip()
            internet.utente, internet.password = utente, password
            if not internet.utente or not internet.password:
                internet.auto_login = False
            messaggio = _chiedi_salvataggio(internet)
        elif scelta == "2":
            internet.subgate = not internet.subgate
            internet.salva_credenziali()
            messaggio = (f"{V}Modalita' Subgate attivata{N} (API di questa rete, sessionId riletto a ogni accesso)."
                         if internet.subgate else
                         f"{G}Modalita' Subgate disattivata{N}: torna al rilevamento automatico del form.")
        elif scelta == "3":
            if not internet.auto_login and not (internet.utente and internet.password):
                messaggio = f"{R}Prima imposta utente e password (opzione 1).{N}"
                continue
            internet.auto_login = not internet.auto_login
            internet.salva_credenziali()
            if internet.auto_login:
                internet.subito.set()  # se e' gia' sul portale, rientra subito
            messaggio = (f"{V}Login automatico attivato.{N}" if internet.auto_login
                         else f"{G}Login automatico disattivato.{N}")
        elif scelta == "4":
            if not (internet.utente and internet.password):
                messaggio = f"{R}Prima imposta utente e password (opzione 1).{N}"
                continue
            print("Login in corso...")
            ok, info = login_portale(internet.utente, internet.password,
                                     internet.dettaglio, internet.config_login())
            if ok:
                stato, _ = internet.controlla()
                if stato == "ok":
                    messaggio = f"{V}Login riuscito: Internet raggiungibile.{N}"
                else:
                    messaggio = (f"{G}Richiesta inviata, ma lo stato e' ancora '{stato}'{N} ({info}). "
                                 "Controlla il MAC nelle avanzate (5) o ricattura la richiesta.")
            else:
                messaggio = f"{R}Login non riuscito: {info}{N}"
            scrivi_log(f"login portale manuale: {_senza_colori(messaggio)}")
            internet.subito.set()
        elif scelta == "5":
            def _modifica(etichetta, valore):
                nuovo = input(f"{etichetta} [{valore}]: ").strip()
                if nuovo == "-":
                    return ""
                return nuovo or valore
            if internet.subgate:
                print("Modalita' Subgate: normalmente il MAC si legge dalla pagina.")
                print("Forzalo solo se il login fallisce con 'mac non trovato'.")
                print("(lascia vuoto per non cambiare, '-' per svuotare)\n")
                internet.mac = _modifica("MAC del PC (es. aa:bb:cc:dd:ee:ff)", internet.mac)
            else:
                print("Indirizzo e nomi dei campi, per il login diretto quando")
                print("l'auto-rilevamento del form non basta.")
                print("(lascia vuoto per non cambiare, '-' per svuotare)\n")
                internet.login_url = _modifica("Indirizzo di login", internet.login_url)
                internet.campo_utente = _modifica("Nome campo utente", internet.campo_utente)
                internet.campo_password = _modifica("Nome campo password", internet.campo_password)
                metodo = input(f"Metodo POST/GET [{internet.metodo}]: ").strip().upper()
                if metodo in ("POST", "GET"):
                    internet.metodo = metodo
            messaggio = _chiedi_salvataggio(internet)
        elif scelta == "6":
            internet.utente = internet.password = ""
            internet.login_url = internet.campo_utente = internet.campo_password = ""
            internet.metodo = "POST"
            internet.mac = ""
            internet.subgate = internet.auto_login = False
            try:
                os.remove(FILE_PORTALE)
            except OSError:
                pass
            messaggio = f"{G}Configurazione cancellata.{N}"
        elif scelta == "0":
            return


# ---------------------------------------------------------------- log e messaggi

FILE_LOG = os.path.join(cartella_dati(), "net_tool.log")
MESSAGGI = deque(maxlen=6)   # esiti delle azioni, mostrati nell'header


def _senza_colori(s):
    return re.sub(r"\033\[[0-9;]*m", "", s)


def scrivi_log(testo):
    try:
        with open(FILE_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {_senza_colori(testo)}\n")
    except OSError:
        pass


def avvisa(testo):
    # messaggio mostrato nell'header al prossimo refresh + riga di log
    MESSAGGI.append(f"[{ora()}] {testo}")
    scrivi_log(testo)


# ---------------------------------------------------------------- hotspot (WinRT via PowerShell)

CREATE_NO_WINDOW = 0x08000000
INTERVALLO_HOTSPOT = 5    # secondi tra due letture dello stato hotspot
ATTESA_DOPO_AVVIO = 6     # secondi di grazia dopo una riaccensione

# TetheringOperationalState
SCONOSCIUTO, ACCESO, SPENTO, IN_TRANSIZIONE = 0, 1, 2, 3
# TetheringWiFiBand
BANDA_AUTO, BANDA_24, BANDA_5 = 0, 1, 2

NOMI_HS = {ACCESO: f"{V}acceso{N}", SPENTO: f"{R}spento{N}",
           IN_TRANSIZIONE: f"{G}in transizione{N}", SCONOSCIUTO: f"{R}?{N}"}
NOMI_BANDA = {BANDA_AUTO: "Auto (scelta da Windows)", BANDA_24: "2,4 GHz", BANDA_5: "5 GHz", -1: "n/d"}
ESITI_HS = {0: "ok", 1: "sconosciuto", 2: "modem mobile spento", 3: "scheda Wi-Fi spenta",
            4: "timeout verifica abilitazione", 5: "verifica abilitazione fallita",
            6: "operazione gia' in corso", 7: "Bluetooth spento",
            8: "connettivita' di rete limitata"}

# un unico script: l'azione e gli eventuali parametri arrivano dalle variabili
# d'ambiente (HS_ACTION, HS_BAND, HS_SSID, HS_PASS), cosi' niente problemi di
# virgolette e nessuna injection da SSID/password.
PS_HOTSPOT = r'''
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    function Await($op, $t) {
        $m = $asTaskGeneric.MakeGenericMethod($t)
        $task = $m.Invoke($null, @($op))
        $task.Wait(-1) | Out-Null
        $task.Result
    }
    $resType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]
    $cp = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
    if ($null -eq $cp) { Write-Output 'ERR:nessuna connessione Internet da condividere (collega prima il PC a Internet)'; return }
    $mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($cp)
    switch ($env:HS_ACTION) {
        'status' {
            $clients = -1
            try { $clients = $mgr.ClientCount } catch {}
            $band = -1
            try { $band = [int]$mgr.GetCurrentAccessPointConfiguration().Band } catch {}
            Write-Output ('STATE:' + [int]$mgr.TetheringOperationalState + ':' + $clients + ':' + $band)
        }
        'start' {
            if ([int]$mgr.TetheringOperationalState -eq 1) { Write-Output 'RESULT:0'; return }
            $r = Await ($mgr.StartTetheringAsync()) $resType
            Write-Output ('RESULT:' + [int]$r.Status)
        }
        'stop' {
            if ([int]$mgr.TetheringOperationalState -eq 2) { Write-Output 'RESULT:0'; return }
            $r = Await ($mgr.StopTetheringAsync()) $resType
            Write-Output ('RESULT:' + [int]$r.Status)
        }
        'getcfg' {
            $c = $mgr.GetCurrentAccessPointConfiguration()
            $band = -1
            try { $band = [int]$c.Band } catch {}
            Write-Output ('BAND:' + $band)
            Write-Output ('SSID:' + $c.Ssid)
            Write-Output ('PASS:' + $c.Passphrase)
        }
        'setband' {
            $c = $mgr.GetCurrentAccessPointConfiguration()
            $c.Band = [Windows.Networking.NetworkOperators.TetheringWiFiBand]([int]$env:HS_BAND)
            $r = Await ($mgr.ConfigureAccessPointAsync($c)) $resType
            Write-Output ('RESULT:' + [int]$r.Status)
        }
        'setap' {
            $c = $mgr.GetCurrentAccessPointConfiguration()
            if ($env:HS_SSID) { $c.Ssid = $env:HS_SSID }
            if ($env:HS_PASS) { $c.Passphrase = $env:HS_PASS }
            $r = Await ($mgr.ConfigureAccessPointAsync($c)) $resType
            Write-Output ('RESULT:' + [int]$r.Status)
        }
    }
} catch {
    Write-Output ('ERR:' + $_.Exception.Message)
}
'''

_PS_B64 = base64.b64encode(PS_HOTSPOT.encode("utf-16-le")).decode()


def _ps_hotspot(action, extra_env=None):
    env = dict(os.environ)
    env["HS_ACTION"] = action
    if extra_env:
        env.update(extra_env)
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-EncodedCommand", _PS_B64],
                           capture_output=True, text=True, timeout=45, env=env,
                           creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return ["ERR:PowerShell non ha risposto (timeout)"]
    except Exception as e:
        return [f"ERR:{type(e).__name__}: {e}"]
    righe = [r.strip() for r in (p.stdout or "").splitlines() if r.strip()]
    if not righe:
        return [f"ERR:{(p.stderr or '').strip() or 'nessuna risposta da PowerShell'}"]
    return righe


class Hotspot:
    # monitor in un thread: tiene aggiornato lo stato (per header e viste) e, se
    # la persistenza e' attiva, riaccende l'hotspot quando Windows lo spegne.

    def __init__(self):
        self.stato = SCONOSCIUTO
        self.clienti = -1
        self.banda = -1
        self.ssid = ""
        self.password = ""
        self.errore = None
        self.persistenza = False
        self.riavvii = 0
        self.ultimo_riavvio = None
        self.eventi = deque(maxlen=50)
        self._ferma = threading.Event()
        self._thread = threading.Thread(target=self._monitor, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._ferma.set()

    def evento(self, testo):
        self.eventi.append(f"[{ora()}] {testo}")
        scrivi_log(f"hotspot: {_senza_colori(testo)}")

    def _aggiorna(self):
        for r in _ps_hotspot("status"):
            if r.startswith("STATE:"):
                _, s, c, b = r.split(":")
                self.stato, self.clienti, self.banda = int(s), int(c), int(b)
                self.errore = None
                return True
            if r.startswith("ERR:"):
                self.stato, self.errore = SCONOSCIUTO, r[4:]
                return False
        self.errore = "risposta non riconosciuta"
        return False

    def _monitor(self):
        while not self._ferma.is_set():
            ok = self._aggiorna()
            if ok and self.persistenza and self.stato == SPENTO:
                self.riavvii += 1
                self.ultimo_riavvio = datetime.now()
                esito, info = self.accendi()
                self.evento(f"{G}era spento -> riacceso{N} (#{self.riavvii})" if esito
                            else f"{R}riaccensione #{self.riavvii} fallita: {info}{N}")
                self._ferma.wait(ATTESA_DOPO_AVVIO)
            else:
                self._ferma.wait(INTERVALLO_HOTSPOT)

    def _azione(self, action, extra_env=None):
        for r in _ps_hotspot(action, extra_env):
            if r.startswith("RESULT:"):
                code = int(r.split(":", 1)[1])
                return code == 0, ESITI_HS.get(code, f"codice {code}")
            if r.startswith("ERR:"):
                return False, r[4:]
        return False, "risposta non riconosciuta"

    def accendi(self):
        return self._azione("start")

    def spegni(self):
        return self._azione("stop")

    def imposta_banda(self, banda, riavvia=True):
        ok, info = self._azione("setband", {"HS_BAND": str(banda)})
        if ok and riavvia and self.stato == ACCESO:
            # la banda ha effetto solo al (ri)avvio dell'hotspot
            self.spegni()
            time.sleep(1)
            self.accendi()
        return ok, info

    def imposta_ap(self, ssid, password):
        env = {}
        if ssid:
            env["HS_SSID"] = ssid
        if password:
            env["HS_PASS"] = password
        return self._azione("setap", env)

    def leggi_cfg(self):
        for r in _ps_hotspot("getcfg"):
            if r.startswith("BAND:"):
                self.banda = int(r[5:])
            elif r.startswith("SSID:"):
                self.ssid = r[5:]
            elif r.startswith("PASS:"):
                self.password = r[5:]
            elif r.startswith("ERR:"):
                return False, r[4:]
        return True, "ok"


def riga_hotspot(hs):
    if hs.stato == SCONOSCIUTO and hs.errore:
        return f"Hotspot: {R}n/d{N} ({hs.errore})"
    testo = f"Hotspot: {NOMI_HS.get(hs.stato, '?')}"
    if hs.stato == ACCESO:
        testo += f"  banda {NOMI_BANDA.get(hs.banda, '?')}"
        if hs.clienti >= 0:
            testo += f"  dispositivi: {hs.clienti}"
    if hs.persistenza:
        testo += f"  {B}[persistenza]{N}"
    return testo


# ---------------------------------------------------------------- hotspot: anti-spegnimento (registro)

CHIAVE_ICS = r"SYSTEM\CurrentControlSet\Services\icssvc\Settings"


def leggi_peerless():
    # None = non impostato (default Windows = timeout attivo)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CHIAVE_ICS) as k:
            valore, _ = winreg.QueryValueEx(k, "PeerlessTimeoutEnabled")
            return valore
    except OSError:
        return None


def imposta_peerless(valore):
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, CHIAVE_ICS, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "PeerlessTimeoutEnabled", 0, winreg.REG_DWORD, valore)


def riavvia_servizio_ics():
    # applica la modifica al registro; interrompe brevemente l'hotspot (la
    # persistenza lo rialza, o lo riaccendi a mano)
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", "Restart-Service icssvc -Force"],
                       capture_output=True, text=True, timeout=30, creationflags=CREATE_NO_WINDOW)
        return True
    except Exception:
        return False


def menu_registro():
    messaggio = ""
    while True:
        cls()
        print(f"{B}Anti-spegnimento automatico dell'hotspot{N}\n")
        print("Windows spegne l'hotspot quando nessun dispositivo resta collegato per")
        print("qualche minuto. Qui disattivi quel timeout a livello di sistema")
        print("(PeerlessTimeoutEnabled = 0): e' la soluzione alla radice. Serve l'admin.\n")
        admin = e_amministratore()
        attuale = leggi_peerless()
        descr = {0: f"{V}timeout DISATTIVATO (non si spegne da solo){N}",
                 1: f"{R}attivo (default Windows){N}",
                 None: f"{R}non impostato (default = attivo){N}"}.get(attuale, str(attuale))
        print(f"Stato attuale: {descr}")
        if not admin:
            print(f"{R}Non sei amministratore: riavvia il programma come admin per modificarlo.{N}")
        if messaggio:
            print(f"\n{messaggio}")
            messaggio = ""
        print()
        if admin:
            print("1. Disattiva il timeout (consigliato)")
            print("2. Ripristina il default di Windows")
        print("\n0. Torna")
        scelta = input("\nScelta: ").strip()
        if admin and scelta == "1":
            try:
                imposta_peerless(0)
                riavvia_servizio_ics()
                messaggio = f"{V}Timeout disattivato (servizio hotspot riavviato).{N}"
            except OSError as e:
                messaggio = f"{R}Scrittura nel registro fallita: {e}{N}"
            scrivi_log(_senza_colori(messaggio))
        elif admin and scelta == "2":
            try:
                imposta_peerless(1)
                riavvia_servizio_ics()
                messaggio = f"{G}Default ripristinato (servizio hotspot riavviato).{N}"
            except OSError as e:
                messaggio = f"{R}Scrittura nel registro fallita: {e}{N}"
            scrivi_log(_senza_colori(messaggio))
        elif scelta == "0":
            return


def menu_hotspot(hs):
    while True:
        cls()
        hs.leggi_cfg()  # aggiorna SSID/password/banda
        print(f"{B}Hotspot{N}\n")
        print(riga_hotspot(hs))
        print(f"  SSID: {hs.ssid or '(sconosciuto)'}    password: {hs.password or '(sconosciuta)'}")
        if hs.persistenza:
            print(f"  Persistenza: {V}attiva{N} - riaccensioni forzate: {hs.riavvii}")
        else:
            print("  Persistenza: spenta")
        if hs.eventi:
            print(f"\n{B}Eventi:{N}")
            for e in list(hs.eventi)[-6:]:
                print(" ", e)
        print()
        print("1. Spegni l'hotspot" if hs.stato == ACCESO else "1. Accendi l'hotspot")
        print(f"2. Banda: Auto {'(attuale)' if hs.banda == BANDA_AUTO else ''}")
        print(f"3. Banda: 2,4 GHz {'(attuale)' if hs.banda == BANDA_24 else ''}")
        print(f"4. Banda: 5 GHz {'(attuale)' if hs.banda == BANDA_5 else ''}")
        print("5. Cambia SSID e password")
        print(f"6. {'Disattiva' if hs.persistenza else 'Attiva'} la persistenza")
        print("7. Anti-spegnimento automatico (registro, serve admin)")
        print("\n0. Torna al menu")
        scelta = input("\nScelta: ").strip()
        if scelta == "1":
            if hs.stato == ACCESO:
                if hs.persistenza:
                    hs.persistenza = False
                    hs.evento("persistenza disattivata (spegnimento manuale)")
                ok, info = hs.spegni()
                hs.evento(f"{V}spento{N}" if ok else f"{R}spegnimento fallito: {info}{N}")
            else:
                ok, info = hs.accendi()
                hs.evento(f"{V}acceso{N}" if ok else f"{R}accensione fallita: {info}{N}")
        elif scelta in ("2", "3", "4"):
            banda = {"2": BANDA_AUTO, "3": BANDA_24, "4": BANDA_5}[scelta]
            ok, info = hs.imposta_banda(banda)
            hs.evento(f"banda -> {NOMI_BANDA[banda]}" if ok
                      else f"{R}cambio banda fallito: {info}{N} (l'adattatore potrebbe non supportarla)")
        elif scelta == "5":
            ssid = input(f"Nuovo SSID (invio = invariato) [{hs.ssid}]: ").strip()
            pwd = input("Nuova password (min 8 caratteri, invio = invariata): ").strip()
            if pwd and len(pwd) < 8:
                hs.evento(f"{R}password troppo corta (min 8): non cambiata{N}")
            elif not ssid and not pwd:
                hs.evento("nessuna modifica a SSID/password")
            else:
                ok, info = hs.imposta_ap(ssid, pwd)
                hs.evento(f"{V}SSID/password aggiornati{N}" if ok
                          else f"{R}aggiornamento fallito: {info}{N}")
        elif scelta == "6":
            hs.persistenza = not hs.persistenza
            hs.evento(f"{V}persistenza attivata{N}" if hs.persistenza else "persistenza disattivata")
        elif scelta == "7":
            menu_registro()
        elif scelta == "0":
            return


# ---------------------------------------------------------------- menu

def intestazione(w, internet, lock, limite, hs):
    print(f"{B}=== NetTool ==={N}  {w.nome}")
    print(riga_wifi(w))
    print(internet.riga())
    print(riga_hotspot(hs))
    if lock and not lock.is_alive():
        print(f"{R}LOCK fermato per un errore{N} (opzione 4 per i dettagli)")
    elif lock:
        print(f"{B}LOCK attivo{N} su {lock.bssid} ({lock.ssid}, {lock.banda}) - "
              f"riconnessioni forzate: {lock.riconnessioni}")
    if limite and limite.is_alive():
        print(f"{B}LIMITE attivo{N} a {limite.mbps:g} Mbps - pacchetti scartati: {limite.scartati}")
    elif limite:
        print(f"{R}LIMITE fermato per un errore:{N} {limite.errore}")
    if internet.auto_login and internet.utente:
        extra = f", accessi rifatti: {internet.login_ok}" if internet.login_ok else ""
        print(f"{B}LOGIN PORTALE automatico{N} (utente {internet.utente}{extra})")
    if MESSAGGI:
        print(f"{G}>{N} {list(MESSAGGI)[-1]}")
    print()


def main():
    os.system("")  # abilita i colori ANSI nella console di Windows
    w = Wlan()
    internet = StatoInternet()
    internet.start()
    hs = Hotspot()
    hs.start()
    lock = None
    limite = None
    try:
        while True:
            cls()
            intestazione(w, internet, lock, limite, hs)
            print(f"{B}Wi-Fi{N}")
            print("1. Scansione reti (continua, real-time)")
            print("2. Connetti e blocca su un BSSID")
            if lock:
                # anche un lock fermato da un errore resta consultabile
                print("3. Mostra stato del lock")
            print("4. Test traffic shaping")
            if limite and limite.is_alive():
                print(f"5. Mostra / modifica il limite (attivo a {limite.mbps:g} Mbps)")
            else:
                print("5. Limite di banda")
            print(f"\n{B}Hotspot / Rete{N}")
            print("h. Hotspot (accensione, banda 2,4/5 GHz, persistenza)")
            print("9. Stato della connessione (in tempo reale)")
            if internet.auto_login and internet.utente:
                print("p. Login captive portal (automatico attivo)")
            else:
                print("p. Login automatico al captive portal")
            if lock or limite:
                # i comandi per spegnere stanno a parte, per non sbagliare tasto
                print()
                if lock:
                    print("6. Rimuovi il lock")
                if limite:
                    print("7. Rimuovi il limite")
            print("\n0. Esci")
            scelta = input("\nScelta: ").strip().lower()
            try:
                if scelta == "1":
                    scansione_continua(w, lock)
                elif scelta == "2":
                    lock = avvia_lock(w, lock)
                elif scelta == "3" and lock:
                    mostra_lock(lock)
                elif scelta == "4":
                    menu_shaping(lock)
                elif scelta == "5":
                    limite, esci = menu_limite(w, limite)
                    if esci:
                        break
                elif scelta == "6" and lock:
                    lock.ferma.set()
                    lock.join()
                    lock = None
                elif scelta == "7" and limite:
                    if limite.is_alive():
                        limite.stop()
                    limite = None
                elif scelta == "h":
                    menu_hotspot(hs)
                elif scelta == "9":
                    mostra_stato(w, internet, lock, limite, hs)
                elif scelta == "p":
                    menu_portale(internet)
                elif scelta == "0":
                    break
            except KeyboardInterrupt:
                pass  # Ctrl+C dentro una funzione: si torna al menu
    except KeyboardInterrupt:
        pass
    finally:
        hs.stop()
        if limite and limite.is_alive():
            limite.stop()
        if lock:
            lock.ferma.set()
        w.chiudi()


if __name__ == "__main__":
    # l'elevazione si chiede subito, cosi' non si perde lo stato a meta' lavoro;
    # se l'utente rifiuta si prosegue senza la funzione 7
    if not e_amministratore() and "--elevato" not in sys.argv and riavvia_come_amministratore():
        sys.exit(0)
    try:
        main()
    except Exception:
        # la console elevata si chiuderebbe subito: mostriamo l'errore prima
        traceback.print_exc()
        premi_un_tasto("Errore imprevisto: premi un tasto per chiudere...")

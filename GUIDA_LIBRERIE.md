# Guida alle librerie e ai concetti di `net_tool.py`

Guida di studio per chi sa Python ma non conosce (bene) le librerie e i concetti
di dominio usati in `net_tool.py`. L'obiettivo non è rispiegare il Python di
base (cicli, classi, dict, comprehension), ma **cosa fanno le librerie** e i
**concetti di rete/Windows** su cui si regge il programma.

I riferimenti al codice sono per **nome di classe/funzione** (non per numero di
riga, che cambia a ogni modifica): cerca quel nome nel file.

Ordine consigliato di studio:

1. `ctypes` — senza, la classe `Wlan` è illeggibile
2. Vocabolario Wi-Fi (SSID/BSSID/RSSI/roaming/captive portal)
3. `threading` (soprattutto `Event`)
4. HTTP fatto a mano (`urllib` + `cookiejar` + `html.parser`)
5. L'hotspot (WinRT pilotato via PowerShell: `subprocess`, `base64`, `winreg`)
6. Il resto (`msvcrt`, `socket`, `heapq`/`deque`, `pydivert`) man mano

---

## 1. `ctypes` — parlare con le DLL native di Windows

**Dove:** le classi `GUID`, `WLAN_*`, `DOT11_*` in cima al file, la classe `Wlan`
e gli helper `mac_str` / `mac_byte` / `ssid_str`.

È la libreria che fa "parlare" Python con il codice C delle DLL di sistema.
Capita questa, hai capito metà del file.

### Concetti chiave

- **Caricare una DLL**
  ```python
  wlanapi = ctypes.WinDLL("wlanapi.dll")
  wlanapi.WlanOpenHandle(...)              # le funzioni C diventano metodi
  ```

- **`ctypes.Structure`** — in C i dati si scambiano con `struct`: blocchi di byte
  con campi in ordine e tipo fissi. `_fields_` li dichiara. **L'ordine e i tipi
  devono combaciare esattamente** con la definizione Microsoft, altrimenti si
  leggono byte a caso.
  ```python
  class DOT11_SSID(ctypes.Structure):
      _fields_ = [("uSSIDLength", wintypes.ULONG),
                  ("ucSSID", ctypes.c_ubyte * 32)]   # array di 32 byte
  ```
  In `WLAN_CONNECTION_ATTRIBUTES` si dichiarano **solo i primi campi** di una
  struct più grande, di proposito (si copia solo `sizeof` di quella parziale).

- **Tipi C (`wintypes`)** — alias per i tipi dell'API Windows:
  `DWORD` (int 32 bit), `WORD` (16), `ULONG`, `LONG`, `HANDLE`, `LPCWSTR`
  (stringa wide/UTF-16), `USHORT`, `c_ubyte` (byte). `Tipo * N` = array.

- **Puntatori e passaggio per riferimento** — le funzioni C non "ritornano"
  valori: li scrivono in memoria che passi tu.
  - `ctypes.byref(x)` → indirizzo di `x`
  - `ctypes.POINTER(Tipo)()` → puntatore vuoto da far riempire
  - `ctypes.pointer(x)` → puntatore a un oggetto esistente
  - `.contents` → dereferenzia il puntatore
  (vedi `Wlan.__init__`, `Wlan._query`, `Wlan.antenne`, `Wlan.connetti`)

- **Copia di memoria grezza**
  - `Tipo.from_buffer_copy(bytes)` — costruisce una struct da byte
  - `ctypes.string_at(ptr, n)` — legge `n` byte da un indirizzo
  - `ctypes.memmove(dst, src, n)` — copia byte, come `memcpy`
  - `ctypes.addressof(x)` + `Campo.offset` + `Tipo.from_address(addr)` —
    aritmetica sugli indirizzi per leggere un array a lunghezza variabile che
    segue una struct (vedi `Wlan.antenne`)

- **Memoria manuale** — `wlanapi.WlanFreeMemory(ptr)`. La memoria che l'API ti
  dà la devi liberare tu: Python qui non lo fa da solo.

- **Altre DLL al volo** — `ctypes.windll.user32`, `.shell32` (`avvisa_suono`,
  `e_amministratore`, `riavvia_come_amministratore`) per beep, controllo admin,
  elevazione UAC; `iphlpapi.dll` in `indice_interfaccia`.

### Esempio minimo (giocattolo)

Definire una struct, riempirla, leggerne i byte:

```python
import ctypes

class Punto(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int), ("y", ctypes.c_int)]

p = Punto(3, 4)
print(p.x, p.y)                       # 3 4
print(ctypes.sizeof(p))               # 8  (due int da 4 byte)

# byte grezzi della struct e ricostruzione
grezzi = ctypes.string_at(ctypes.byref(p), ctypes.sizeof(p))
p2 = Punto.from_buffer_copy(grezzi)
print(p2.x, p2.y)                     # 3 4
```

### Da leggere

Doc ufficiale `ctypes`, sezioni *Structures*, *Pointers*, *byref()/pointer()*.

---

## 2. La Windows WLAN API — concetti, non Python

**Dove:** la classe `Wlan` e le costanti `OP_*`, `BSS_*`, `MODO_*`.

Il codice, invece di interpretare l'output testuale di `netsh` (che cambia con
la lingua di sistema), parla direttamente con `wlanapi.dll`.

### Pattern e chiamate

- **Handle**: `WlanOpenHandle` → usi l'handle → `WlanCloseHandle`
  (`Wlan.__init__` / `Wlan.chiudi`). Come aprire/chiudere un file.
- **`WlanQueryInterface(opcode)`** — chiedi una specifica informazione usando un
  *opcode* (costanti `OP_STATO`, `OP_CONNESSIONE`, `OP_CANALE`, `OP_RSSI`); vedi
  `Wlan._query` e `Wlan.stato`.
- **`WlanScan` è asincrona** (`Wlan.avvia_scansione`): avvii la scansione,
  aspetti ~4 s, poi leggi i risultati con `WlanGetNetworkBssList`
  (`Wlan.antenne`). Niente ritorno immediato.
- **`WlanConnect` con lista BSSID** (`Wlan.connetti`): il cuore del "lock" —
  costringere la scheda ad associarsi a **una sola** antenna.
- **`WlanGetProfile`** (`Wlan.profilo_esiste` / `Wlan.modalita`): verifica se
  esiste un profilo salvato (serve per le reti protette: senza profilo/password
  non ci si può agganciare).

### Vocabolario Wi-Fi indispensabile

- **SSID** = nome della rete. **BSSID** = indirizzo MAC di **una** antenna/access
  point. Una rete (SSID) può avere molte antenne (BSSID).
- **RSSI** = potenza del segnale in dBm (numero negativo; più vicino a 0 =
  meglio). Il "segnale %" è una qualità normalizzata 0–100.
- **Banda / canale / frequenza** (`banda_canale`): conversione MHz → banda
  (2.4 / 5 / 6 GHz) e numero di canale.
- **Roaming**: il driver Windows può spostarti da solo su un'altra antenna. La
  classe `Lock` esiste apposta per contrastarlo e riagganciare il BSSID scelto.
- **Capability / privacy bit** (`CAP_PRIVACY`): bit nel beacon che dice se la
  rete è cifrata (protetta) o aperta.

---

## 3. `threading` — concorrenza

**Dove:** le classi `Lock`, `LimiteBanda`, `StatoInternet`, `Hotspot` e le viste
"in tempo reale".

Il programma fa più cose insieme: menu interattivo + monitor Internet + monitor
hotspot + lock + limite di banda.

- **`threading.Thread`** sottoclassata con `run()` e `daemon=True` (`Lock`,
  `LimiteBanda`, `StatoInternet`) oppure incapsulata (`Hotspot` crea un thread
  interno). Un daemon thread muore insieme al programma.
- **`threading.Event`** — flag on/off tra thread: `.set()`, `.clear()`,
  `.is_set()`, `.wait(timeout)`. Usato in due modi:
  1. "ferma il thread" (`self.ferma.set()`)
  2. **sleep interrompibile**: `self.ferma.wait(3)` = dormi 3 s ma svegliati
     subito se qualcuno ferma. Molto meglio di `time.sleep` in un loop.
  (vedi `Lock.run`, `Hotspot._monitor`, `StatoInternet.subito`)
- **`threading.Lock`** — mutua esclusione: il classico `with self.lock:` per
  proteggere dati condivisi (vedi `Limitatore`, `StatoTest`, `LimiteBanda`).
- **`threading.Condition`** — più avanzato: un thread `wait()` finché un altro
  non `notify()` che c'è lavoro. Usato nella coda dei pacchetti del limitatore
  (`LimiteBanda._invia_in_coda`).

### Esempio minimo: `Event` come sleep interrompibile

```python
import threading, time

ferma = threading.Event()

def lavoratore():
    while not ferma.is_set():
        print("giro...")
        ferma.wait(2)          # dorme 2s, ma esce subito se ferma.set()
    print("fermato")

t = threading.Thread(target=lavoratore, daemon=True)
t.start()
time.sleep(5)
ferma.set()                    # lo sveglia e lo ferma senza aspettare i 2s
t.join()
```

Se `threading` ti è nuovo, concentrati su **`Event`** e sul pattern
**`with lock:`**: coprono il 90% degli usi nel file.

---

## 4. HTTP fatto a mano: `urllib` + `http.cookiejar` + `html.parser`

**Dove:** `flusso` (download di test), la sezione captive portal
(`RaccoltaForm`, `login_portale`, `login_subgate`, `_testo_portale`,
`StatoInternet`).

Non si usa `requests`, ma la libreria standard, più verbosa.

- **`urllib.request.Request` / `urlopen`** (`flusso`): costruisci una richiesta
  con header (la costante `UA`) e la apri. `r.read(n)` legge il corpo a blocchi.
  `r.geturl()` dà l'URL finale dopo eventuali redirect.
- **`urllib.error.HTTPError`**: attenzione — un 4xx/5xx qui arriva come
  **eccezione**, non come oggetto risposta (diverso da `requests`). Da lì leggi
  `e.code`, `e.headers.get("Retry-After")`, `e.read()` (vedi `flusso` e
  `StatoTest.server_rifiuta`).
- **`urllib.parse`**: `urlsplit`, `urlencode`, `urljoin`, `unquote` —
  costruzione/manipolazione di URL e dati form.
- **`http.cookiejar.CookieJar` + `build_opener(HTTPCookieProcessor)`**
  (`login_portale` / `login_subgate`): un "opener" che conserva i cookie tra più
  richieste, come una mini-sessione browser. Essenziale per i captive portal.
- **`HTTPRedirectHandler`** sottoclassato per **bloccare** i redirect
  (`SenzaRedirect`): qui un redirect **è** il segnale del captive portal, quindi
  non va seguito (vedi `StatoInternet.controlla`).
- **`html.parser.HTMLParser`** (`RaccoltaForm`): parser HTML della stdlib a
  **callback** (`handle_starttag`), non ad albero DOM. Usato per trovare i
  `<form>` di login e i loro `<input>` (campo password + campi testo).

### Concetti di dominio

- **Captive portal**: le pagine "accetta e naviga" di hotel/foresterie. Il
  rilevamento sfrutta il *connectivity check* di Windows/NCSI (costanti
  `URL_VERIFICA` / `TESTO_VERIFICA`): si scarica un URL che deve rispondere con
  un testo fisso; se invece risponde con un redirect o una pagina diversa → sei
  dietro un portale.
- **Modalità Subgate/SonicWall** (`login_subgate`): gestione per un tipo di
  portale che rilegge il `sessionId` dalla pagina a ogni accesso e reinvia il
  login come JSON all'API. **Nel codice pubblico la costante `SUBGATE` è un
  template vuoto**: i valori reali della propria rete vanno in `subgate_cfg`
  dentro `portale_login.json` (vedi README).

---

## 5. L'hotspot: WinRT pilotato via PowerShell (`subprocess` + `base64` + `winreg`)

**Dove:** la classe `Hotspot`, la funzione `_ps_hotspot`, la stringa
`PS_HOTSPOT`, e per l'anti-spegnimento `leggi_peerless` / `imposta_peerless`.

Windows non ha un comando pulito per accendere/spegnere l'hotspot: l'unica via è
l'API nativa **WinRT `NetworkOperatorTetheringManager`**. Da Python pura è
scomoda, quindi si delega a **PowerShell** (che sa caricare i tipi WinRT), e si
legge la sua risposta.

- **`subprocess.run(...)`** (`_ps_hotspot`): lancia `powershell`, ne cattura
  `stdout`, con `timeout` e `creationflags=CREATE_NO_WINDOW` (niente finestra
  che lampeggia a ogni chiamata). È il modo standard per invocare un processo
  esterno e leggerne l'output.
- **`-EncodedCommand` + `base64`**: lo script PowerShell viene codificato in
  base64 UTF-16LE e passato così. Trucco per **evitare ogni problema di
  virgolette/escape**; i parametri variabili (azione, banda, SSID, password)
  passano invece via **variabili d'ambiente** (`HS_ACTION`, `HS_BAND`,
  `HS_SSID`, `HS_PASS`) — anche per non rischiare injection da SSID/password.
- **WinRT asincrono**: i metodi `StartTetheringAsync` / `StopTetheringAsync` /
  `ConfigureAccessPointAsync` ritornano operazioni *async*; nello script c'è una
  funzione `Await` che le trasforma in task .NET e aspetta il risultato.
- **Protocollo testuale**: lo script stampa righe tipo `STATE:<stato>:<clienti>:<banda>`,
  `RESULT:<codice>`, `BAND:/SSID:/PASS:`, `ERR:<msg>`; `Hotspot` le interpreta.
- **`Hotspot` come monitor**: un thread (`_monitor`) legge lo stato ogni pochi
  secondi (così header e viste sono sempre aggiornati) e, se la persistenza è
  attiva, riaccende l'hotspot quando Windows lo spegne.
- **`winreg`** (`leggi_peerless` / `imposta_peerless`): legge/scrive il registro
  di Windows (`HKLM\...\icssvc\Settings\PeerlessTimeoutEnabled`) per disattivare
  il timeout che spegne l'hotspot quando nessuno è collegato. Richiede
  l'amministratore; poi si riavvia il servizio `icssvc`.

### Concetti di dominio

- **Hotspot / tethering**: il PC condivide la **connessione Internet attiva** con
  i dispositivi. Se il PC non è connesso, l'API fallisce (lo script lo segnala).
- **Banda (`TetheringWiFiBand`)**: Auto / 2,4 / 5 GHz. La banda effettiva dipende
  dal supporto dell'adattatore Wi-Fi; con "Auto" la sceglie Windows. Il cambio
  banda ha effetto solo al (ri)avvio dell'hotspot (vedi `Hotspot.imposta_banda`).

---

## 6. `msvcrt` — tastiera nella console Windows

**Dove:** `attendi_tasto`, `premi_un_tasto`, le viste `mostra_lock`,
`mostra_limite`, `mostra_stato`, `menu_hotspot`.

Libreria **solo Windows** per leggere i tasti senza aspettare Invio:

- `msvcrt.kbhit()` → "è stato premuto un tasto?" (non blocca)
- `msvcrt.getwch()` → leggi quel carattere

Serve alle schermate "in tempo reale" che si aggiornano da sole ma reagiscono
subito a un tasto. `input()` invece **blocca** finché non premi Invio.

```python
import msvcrt, time
fine = time.monotonic() + 5
while time.monotonic() < fine:
    if msvcrt.kbhit():
        print("premuto:", msvcrt.getwch())
        break
    time.sleep(0.05)
```

---

## 7. `socket` — rete a basso livello

**Dove:** `ping_tcp`, e `getaddrinfo` in `_test_shaping`.

- **`socket.create_connection((ip, 443))`** cronometrato (`ping_tcp`): un "ping"
  fatto aprendo una connessione TCP e misurandone il tempo. **Non è ICMP**
  (spesso bloccato): è l'handshake TCP verso il server.
- **`socket.getaddrinfo`**: risoluzione DNS fatta **una volta sola**, per non far
  finire il DNS dentro la misura della latenza.
- **`time.perf_counter` / `time.monotonic`**: orologi monotoni per misurare
  intervalli, immuni ai cambi dell'ora di sistema. Preferirli a `time.time()`
  per i cronometri.

---

## 8. `pydivert` / WinDivert — la parte più esotica

**Dove:** la classe `LimiteBanda`.

Libreria di **terze parti** (non stdlib) che, tramite un driver kernel,
**intercetta i pacchetti di rete** prima che passino. Richiede privilegi di
**amministratore**.

- **Layer `NETWORK` vs `NETWORK_FORWARD`** (`LimiteBanda.run`): traffico del PC
  vs traffico *inoltrato* ai dispositivi collegati all'hotspot.
- **Filtri** in sintassi WinDivert: `ifIdx == ... and !loopback`.
- `handle.recv()` / `handle.send()`: prendi un pacchetto, decidi se rilasciarlo,
  scartarlo o ritardarlo.
- **Il perché** (commento in testa a `LimiteBanda`): Windows sa limitare solo
  l'upload (QoS), non il download. Per limitare il download si intercettano i
  pacchetti e si rilasciano a ritmo; quelli in eccesso si **scartano**, e
  TCP/QUIC interpretano la perdita come congestione e rallentano.

---

## 9. Concetti/algoritmi trasversali

Non sono "una libreria", ma servono per capire la logica.

- **Token bucket / pacing** (`Limitatore`, e `LimiteBanda._ricevi`): come imporre
  un tetto di banda distribuendo i byte nel tempo. Formula ricorrente:
  `byte * 8 / 1e6` = byte → megabit.
- **Traffic shaping** (`test_shaping` / `_test_shaping`): l'idea che una rete
  conceda una raffica iniziale e poi limiti. Il test misura mediana/media della
  velocità per rilevarlo. Utili `statistics.median` / `statistics.mean` (stdlib).
- **HTTP 429 / Retry-After** (`StatoTest.server_rifiuta`): il server di test che
  rifiuta troppe richieste, gestito per non falsare la misura.

### Esempio minimo: token bucket

```python
import time

class Limitatore:
    def __init__(self, mbps):
        self.byte_al_secondo = mbps * 1e6 / 8
        self.prossimo = time.monotonic()

    def consuma(self, n):
        adesso = time.monotonic()
        self.prossimo = max(self.prossimo, adesso) + n / self.byte_al_secondo
        attesa = self.prossimo - adesso
        if attesa > 0:
            time.sleep(attesa)
```

---

## 10. Strutture dati e utilità minori

- **`collections.deque(maxlen=N)`**: coda a lunghezza fissa, perfetta per
  "ultimi N eventi/campioni" (i vecchi cadono da soli). Usata per gli eventi di
  `Lock`, `StatoInternet`, `Hotspot` e per i messaggi dell'header (`MESSAGGI`).
- **`heapq`** (`LimiteBanda`): coda a priorità (min-heap) per rilasciare i
  pacchetti nell'ordine di scadenza.
- **`itertools.count()`** (`LimiteBanda`): contatore infinito, usato come
  tie-breaker nell'heap (se due pacchetti hanno lo stesso istante, si ordina per
  progressivo).
- **`io.StringIO` + `contextlib.redirect_stdout`** (`menu_shaping`): cattura in
  una stringa ciò che una funzione stampa, per tenere il risultato del test a
  schermo senza pause.
- **`re`** (`_cerca_campo`, `_testo_portale`, `_senza_colori`): espressioni
  regolari per estrarre parametri dalla pagina del portale e per togliere i
  codici colore dal log.
- **Codici ANSI** (costanti `V, R, G, B, N`): sequenze per colorare il testo nel
  terminale. `os.system("")` in `main` serve solo ad **abilitarli** su Windows.
- **Merge di dict con `d1 | d2`**: sintassi Python 3.9+, ritorna un nuovo dict
  unendo i due (usato ovunque nei risultati del test shaping e in `SUBGATE`).

---

## 11. Integrazione con Windows / packaging

**Dove:** `e_amministratore`, `riavvia_come_amministratore`, `cartella_dati`, e
il blocco `if __name__ == "__main__"`.

- **UAC / elevazione admin**: `IsUserAnAdmin` e `ShellExecuteW(..., "runas", ...)`
  per rilanciarsi con privilegi elevati (servono per il limite di banda e
  l'anti-spegnimento hotspot). Il flag `--elevato` evita loop infiniti se
  l'elevazione non concede davvero i permessi.
- **`sys.frozen` / `sys.executable`** (`cartella_dati`): distinguono se il
  programma gira come script `.py` o come `.exe` impacchettato con **PyInstaller**.
  Cambia dove cercare i file dati (es. `portale_login.json`, `net_tool.log`).

---

## Riepilogo: percorso di studio

1. **`ctypes`** (doc: Structures, Pointers, byref/pointer) — indispensabile.
2. **Vocabolario Wi-Fi**: SSID / BSSID / RSSI / roaming / captive portal.
3. **`threading`**: `Event` e `with lock:`.
4. **HTTP stdlib**: `urllib` + `cookiejar` + `HTMLParser` insieme.
5. **Hotspot**: `subprocess` + `-EncodedCommand`/`base64`, WinRT async, `winreg`.
6. **Il resto**: `msvcrt`, `socket`, `heapq` / `deque`, `pydivert` man mano.

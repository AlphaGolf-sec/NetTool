# NetTool

Strumento da console per **Windows** che riunisce la gestione del Wi-Fi e
dell'hotspot del PC in un unico programma. Parla direttamente con le API native
di Windows (`wlanapi.dll` per il Wi-Fi, WinRT `NetworkOperatorTetheringManager`
per l'hotspot), senza affidarsi all'output testuale di `netsh`.

> Solo Windows 10/11. L'interfaccia e i messaggi sono in italiano.

## Funzionalità

**Wi-Fi**
- Scansione delle reti in tempo reale (SSID, BSSID, RSSI, banda, canale, sicurezza).
- "Lock" su un BSSID specifico: un watchdog riconnette l'antenna scelta se il
  driver fa roaming o la connessione cade.
- Test di *traffic shaping*: scarica a una soglia fissa e verifica che la rete la
  regga, segnalando crolli e latenza sotto carico.
- Limite di banda su tutto il traffico del PC (download + upload, PC e dispositivi
  in hotspot insieme) intercettando i pacchetti con [WinDivert](https://github.com/basil00/WinDivert)
  tramite `pydivert`.
- Stato della connessione in tempo reale (Wi-Fi, Internet, captive portal).
- Login automatico ai captive portal (rilevamento form generico oppure modalità
  Subgate/SonicWall — vedi *Configurazione*).

**Hotspot**
- Accensione/spegnimento dell'hotspot del PC.
- Scelta della banda: **Auto / 2,4 GHz / 5 GHz**, con la banda attiva sempre
  visibile (dipende dal supporto dell'adattatore Wi-Fi).
- Modifica di SSID e password.
- **Persistenza**: watchdog che riaccende l'hotspot se Windows lo spegne.
- **Anti-spegnimento**: disattiva a livello di sistema il timeout che spegne
  l'hotspot quando nessun dispositivo è collegato (richiede privilegi di
  amministratore).

Gli eventi (cambi stato Internet, login portale, hotspot) vengono registrati in
`net_tool.log`, accanto al programma.

## Requisiti

- Windows 10/11 con Python 3.11+.
- Dipendenza a runtime: [`pydivert`](https://pypi.org/project/pydivert/) (serve
  solo per la funzione "Limite di banda"; il resto funziona senza).
- Per compilare l'eseguibile: `pyinstaller`.

```bat
python -m venv .venv
.venv\Scripts\python -m pip install pydivert pyinstaller
```

> `requirements.txt` contiene l'intero freeze dell'ambiente usato per lo sviluppo
> (comprende pacchetti di build e librerie usate solo da script accessori): per il
> solo utilizzo di NetTool basta `pydivert`.

## Uso

Da sorgente:

```bat
.venv\Scripts\python net_tool.py
```

Alcune funzioni (limite di banda, anti-spegnimento hotspot) richiedono i
privilegi di amministratore: il programma propone di rilanciarsi elevato tramite
UAC quando serve.

## Compilare l'eseguibile

```bat
.venv\Scripts\pyinstaller NetTool.spec
```

Produce `dist\NetTool.exe` (console, con richiesta di elevazione UAC all'avvio).

## Configurazione del captive portal

La configurazione del login al portale è **opzionale** e viene salvata in
`portale_login.json`, creato dal programma accanto all'eseguibile (o allo script).
Il file **non è incluso nel repository** e non deve esserlo: contiene le tue
credenziali in chiaro.

Due modalità:

1. **Automatica (form)**: il programma scarica la pagina del portale e cerca da
   solo il form di login (campo utente + password). Nessuna configurazione nel
   codice.
2. **Subgate/SonicWall**: per i portali basati su Subgate. I valori specifici
   della tua rete (URL dell'API, `origin`, ID `hesapgrup`/`sablon`, `baseurl`,
   lingua) **non sono inclusi nel codice**: la costante `SUBGATE` in `net_tool.py`
   è un template vuoto. Vanno inseriti nella sezione `subgate_cfg` di
   `portale_login.json`, ricavandoli dalla richiesta di login del portale
   osservata con gli strumenti sviluppatore del browser (F12). Senza questa
   configurazione la modalità Subgate non si attiva.

   Anche gli eventuali **campi aggiuntivi** che il tuo portale richiede nel corpo
   della richiesta (flag di consenso, campi "extra", ecc.) non sono nel codice:
   mettili nell'oggetto `corpo_extra` dentro `subgate_cfg`. Dove serve la
   password, scrivi il segnaposto `"__PASSWORD__"`: il programma lo sostituisce a
   runtime con la password reale (così non la metti in chiaro due volte).

Esempio di `portale_login.json` per la modalità Subgate (valori di esempio):

```json
{
  "utente": "ESEMPIO",
  "password": "ESEMPIO",
  "auto": true,
  "subgate": true,
  "mac": "",
  "subgate_cfg": {
    "api_url": "http://<ip-portale>:<porta>/.../login",
    "origin": "http://<ip-portale>:<porta>",
    "hesapgrup": "<id-gruppo-account>",
    "sablon": "<id-template>",
    "platform": "sonicwall",
    "baseurl": "https://<gateway>:<porta>/",
    "dil": "it",
    "corpo_extra": {
      "<campo-consenso-1>": false,
      "extra": [{"label": "<etichetta>", "value": "__PASSWORD__", "tipi": "password"}]
    }
  }
}
```

## Avvertenze

Strumento personale, da usare solo su reti e dispositivi propri o per cui si ha
autorizzazione. La modifica del registro (anti-spegnimento) e l'intercettazione
dei pacchetti (limite di banda) agiscono a basso livello sul sistema; se il
programma si chiude, il traffico e le impostazioni tornano normali da soli.

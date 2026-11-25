# TCP / UDP IP Scanner (`pyipscan.py`)

Ein grafischer IP-Scanner auf Basis von Python und Tkinter, mit dem IP-Bereiche (CIDR) auf einen bestimmten Port über **TCP**, **UDP** oder **beide Protokolle (`BOTH`)** geprüft werden können. Nach dem Scan werden gefundene Treffer – sofern im lokalen Subnetz ermittelbar – mit den zugehörigen MAC-Adressen aus der ARP-Tabelle angezeigt.

---

## Funktionsübersicht

* **CIDR-Scan:** Unterstützt Netzwerke wie `/24`, `/16` oder `/8` über `ipaddress.ip_network` (Standardwert: `192.168.1.0/24`).
* **Port- & Protokollauswahl:** Prüft einen frei wählbaren Port (Standard: `80`) wahlweise per **TCP**, **UDP** oder **BOTH**.
* **Multithreading:** Nutzt eine Warteschlange (`Queue`) mit **100 parallelen Worker-Threads** und einem Timeout von **0,5 Sekunden** pro Verbindungsversuch.
* **MAC-Adressauflösung:** Liest nach Abschluss des Scans über `arp -a` die lokale ARP-Tabelle aus und ordnet Treffern im selben Subnetz die MAC-Adresse zu (ansonsten `"unbekannt"`).
* **Ergebnisansicht & Zwischenablage:** Zeigt Treffer tabellarisch (**IP-Adresse**, **MAC-Adresse**) an; Mehrfachauswahl sowie Kopieren (`Strg+C` oder Button *„Auswahl kopieren“*) im tabulatorgetrennten Format (TSV) werden unterstützt.
* **Integrierter Info-Dialog:** Enthält Hinweise zu CIDR-Größen, Protokollbeispielen (u. a. TCP/Modbus, UDP/BACnet), MAC-Sichtbarkeit, Bedienung und Nutzungsberechtigung.

---

## Voraussetzungen & Start

* **Python 3** mit Standardbibliotheken (`socket`, `threading`, `subprocess`, `ipaddress`, `queue`, `tkinter`) – es sind **keine** externen Drittanbieter-Pakete erforderlich.
* **Plattform:** Auf **Windows** ausgerichtet (Fenstertitel sowie Auswertung von `arp -a`).

Starten über die Kommandozeile:

```bash
python pyipscan.py

"""TCP / UDP IP Scanner (pyipscan.py)
​Ein grafischer IP-Scanner auf Basis von Python und Tkinter, mit dem IP-Bereiche (CIDR) auf einen bestimmten Port über TCP, UDP oder beide Protokolle (BOTH) geprüft werden können. Nach dem Scan werden gefundene Treffer mit – sofern im lokalen Subnetz ermittelbar – zugehörigen MAC-Adressen aus der ARP-Tabelle angezeigt.  
​Funktionsübersicht
​CIDR-Scan: Unterstützt Netzwerke wie /24, /16 oder /8 über ipaddress.ip_network (Standardwert: 192.168.1.0/24).  
​Port- & Protokollauswahl: Prüft einen frei wählbaren Port (Standard: 80) wahlweise per TCP, UDP oder BOTH.  
​Multithreading: Nutzt eine Warteschlange (Queue) mit 100 parallelen Worker-Threads und einem Timeout von 0.5 Sekunden pro Verbindungsversuch.  
​MAC-Adressauflösung: Liest nach Abschluss des Scans über arp -a die lokale ARP-Tabelle aus und ordnet Treffern im selben Subnetz die MAC-Adresse zu (ansonsten "unbekannt").  
​Ergebnisansicht & Export in Zwischenablage: Zeigt Treffer tabellarisch (IP-Adresse, MAC-Adresse) an; Mehrfachauswahl und Kopieren (Strg+C oder Button „Auswahl kopieren“) im Tab-getrennten Format werden unterstützt.  
​Integrierter Info-Dialog: Enthält Hinweise zu CIDR-Größen, Protokollbeispielen (u. a. TCP/Modbus, UDP/BACnet), MAC-Sichtbarkeit, Bedienung und Nutzungsberechtigung.  
​Voraussetzungen & Start
​Python 3 mit Standardbibliotheken (socket, threading, subprocess, ipaddress, queue, tkinter). Keine externen Drittanbieter-Pakete erforderlich.  
​Plattform: Auf Windows ausgerichtet (Fenstertitel und arp -a-Auswertung).  """



import socket
import threading
import subprocess
import ipaddress
from queue import Queue
import tkinter as tk
from tkinter import ttk, messagebox

# ---------------- Konfiguration ----------------

THREADS = 100
TIMEOUT = 0.5

queue = Queue()
results = []
lock = threading.Lock()

# ---------------- Scan Funktionen ----------------

def tcp_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((str(ip), port))
            return True
    except:
        return False


def udp_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(b'\x00', (str(ip), port))
            s.recvfrom(1024)
            return True
    except:
        return False


def worker(port, mode):
    while not queue.empty():
        ip = queue.get()

        found = False
        if mode in ("TCP", "BOTH"):
            found = tcp_scan(ip, port)

        if not found and mode in ("UDP", "BOTH"):
            found = udp_scan(ip, port)

        if found:
            with lock:
                results.append(str(ip))

        queue.task_done()

# ---------------- ARP / MAC ----------------

def get_arp_table():
    arp = {}
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0]:
                arp[parts[0]] = parts[1]
    except:
        pass
    return arp

# ---------------- GUI Funktionen ----------------

def start_scan():
    results.clear()
    for i in tree.get_children():
        tree.delete(i)

    net_input = ip_entry.get().strip()
    port_input = port_entry.get().strip()
    mode = protocol_var.get()

    try:
        network = ipaddress.ip_network(net_input, strict=False)
        port = int(port_input)
    except:
        messagebox.showerror("Fehler", "Ungültiger IP-Bereich oder Port")
        return

    while not queue.empty():
        queue.get()

    for ip in network.hosts():
        queue.put(ip)

    for _ in range(THREADS):
        threading.Thread(
            target=worker,
            args=(port, mode),
            daemon=True
        ).start()

    status.set("Scan läuft...")
    root.after(200, check_finished)


def check_finished():
    if queue.unfinished_tasks == 0:
        arp = get_arp_table()
        for ip in sorted(results):
            mac = arp.get(ip, "unbekannt")
            tree.insert("", "end", values=(ip, mac))
        status.set(f"Scan abgeschlossen ({len(results)} Treffer)")
    else:
        root.after(200, check_finished)


def copy_selection(event=None):
    selected = tree.selection()
    if not selected:
        return

    lines = []
    for item in selected:
        ip, mac = tree.item(item, "values")
        lines.append(f"{ip}\t{mac}")

    text = "\n".join(lines)
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


def show_info():
    info = tk.Toplevel(root)
    info.title("Info")
    info.geometry("750x500")
    info.resizable(False, False)

    text = tk.Text(info, wrap="word")
    text.pack(fill="both", expand=True, padx=10, pady=10)

    info_text = (
        "TCP / UDP IP Scanner – Information\n\n"
        "IP-Bereich (CIDR):\n"
        "  /24  = letzte Zahl wird gescannt, 254 Adressen in Sekunden (z.B. 192.168.1.x)\n"
        "  /16  = letzte zwei Zahlen werden gescannt, 64.516 Adressen in Minuten (z.B. 192.168.x.x)\n"
        "  /8  = letzte drei Zahlen werden gescannt, 16 Mio. Adressen >24h (z.B. 192.x.x.x)\n\n"
        "Protokolle:\n"
        "  TCP  – MODBUS \n"
        "  UDP  – BACNET \n\n"
        "MAC-Adressen:\n"
        "  Nur sichtbar im gleichen Subnetz\n"
        "  Werden aus der lokalen ARP-Tabelle gelesen\n\n"
        "Bedienung:\n"
        "  Mehrere Einträge mit Shift/Strg markieren\n"
        "  Kopieren mit Strg+C oder Button\n\n"
        "Hinweis:\n"
        "  Nur Netzwerke scannen, für die eine Berechtigung besteht.\n\n" 
        "ACHTUNG: Das Scannen von Netzwerken kann Sicherheits- bzw. Überwachungssysteme auslösen."
    )

    text.insert("1.0", info_text)
    text.config(state="disabled")

    ttk.Button(info, text="Schließen", command=info.destroy)\
        .pack(pady=5)

# ---------------- GUI ----------------

root = tk.Tk()
root.title("TCP / UDP IP Scanner (Windows)")
root.geometry("640x480")

top = ttk.Frame(root, padding=10)
top.pack(fill="x")

ttk.Label(top, text="IP-Bereich:").grid(row=0, column=0, sticky="w")
ip_entry = ttk.Entry(top, width=24)
ip_entry.insert(0, "192.168.1.0/24")
ip_entry.grid(row=0, column=1, padx=5)

ttk.Label(top, text="Port:").grid(row=0, column=2, sticky="w")
port_entry = ttk.Entry(top, width=6)
port_entry.insert(0, "80")
port_entry.grid(row=0, column=3)

protocol_var = tk.StringVar(value="TCP")
protocol_box = ttk.Combobox(
    top,
    textvariable=protocol_var,
    values=["TCP", "UDP", "BOTH"],
    width=8,
    state="readonly"
)
protocol_box.grid(row=0, column=4, padx=5)

ttk.Button(top, text="Scan starten", command=start_scan)\
    .grid(row=0, column=5, padx=5)

ttk.Button(top, text="Info", command=show_info)\
    .grid(row=0, column=6, padx=5)

tree = ttk.Treeview(
    root,
    columns=("IP", "MAC"),
    show="headings",
    selectmode="extended"
)
tree.heading("IP", text="IP-Adresse")
tree.heading("MAC", text="MAC-Adresse")
tree.pack(fill="both", expand=True, padx=10, pady=10)

tree.bind("<Control-c>", copy_selection)

ttk.Button(
    root,
    text="Auswahl kopieren",
    command=copy_selection
).pack(anchor="e", padx=10, pady=(0, 5))

status = tk.StringVar(value="Bereit")
ttk.Label(root, textvariable=status)\
    .pack(anchor="w", padx=10)

root.mainloop()
import tkinter as tk
from tkinter import scrolledtext
import nmap

class NmapScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap TCP Port Scanner")

        # IP input
        self.ip_label = tk.Label(root, text="Enter IP address (e.g., 172.166.16.2):")
        self.ip_label.pack(pady=(10, 0))
        self.ip_entry = tk.Entry(root, width=40)
        self.ip_entry.pack()

        # Port input
        self.port_label = tk.Label(root, text="Enter port range (e.g., 1-1024):")
        self.port_label.pack(pady=(10, 0))
        self.port_entry = tk.Entry(root, width=40)
        self.port_entry.pack()

        # Scan button
        self.scan_button = tk.Button(root, text="Start Scan", command=self.run_scan)
        self.scan_button.pack(pady=10)

        # Result display
        self.result_text = scrolledtext.ScrolledText(root, width=60, height=20, wrap=tk.WORD)
        self.result_text.pack(padx=10, pady=10)

    def run_scan(self):
        target = self.ip_entry.get().strip()
        ports = self.port_entry.get().strip() or "1-1024"
        ports = ports.replace(" ", "")
        self.result_text.delete(1.0, tk.END)

        try:
            nm = nmap.PortScanner()
            self.result_text.insert(tk.END, f"Scanning {target} on ports {ports}...\n")
            nm.scan(hosts=target, ports=ports)

            if not nm.all_hosts():
                self.result_text.insert(tk.END, "No hosts found. Check IP or network.\n")
                return

            for host in nm.all_hosts():
                self.result_text.insert(tk.END, f"\nHost: {host} ({nm[host].hostname()})\n")
                self.result_text.insert(tk.END, f"Status: {nm[host].state()}\n")
                if 'tcp' in nm[host]:
                    self.result_text.insert(tk.END, "TCP Ports:\n")
                    for port in sorted(nm[host]['tcp']):
                        state = nm[host]['tcp'][port]['state']
                        self.result_text.insert(tk.END, f"  Port {port}: {state}\n")
                else:
                    self.result_text.insert(tk.END, "No TCP ports found.\n")

        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {str(e)}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NmapScannerApp(root)
    root.mainloop()

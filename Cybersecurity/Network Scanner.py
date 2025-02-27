import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    """Scans the network and returns a list of active devices."""
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    
    answered, _ = srp(packet, timeout=2, verbose=False)
    
    devices = []
    for sent, received in answered:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
    
    return devices

def display_results(devices, tree):
    """Displays the scanned devices in the GUI table."""    
    for row in tree.get_children():
        tree.delete(row)
    
    for device in devices:
        tree.insert("", "end", values=(device['IP'], device['MAC']))

def start_scan():
    ip_range = entry.get()
    if not ip_range:
        messagebox.showerror("Error", "Please enter an IP range")
        return
    
    results = scan_network(ip_range)
    display_results(results, tree)

# GUI Setup
root = tk.Tk()
root.title("Network Scanner")
root.configure(bg="#f0f0f0")

frame = tk.Frame(root, bg="#f0f0f0")
frame.grid(row=0, column=0, padx=10, pady=10, columnspan=3)

tk.Label(frame, text="Enter IP range:", bg="#f0f0f0", font=("Arial", 14)).grid(row=0, column=0, padx=5, pady=5)
entry = tk.Entry(frame)
entry.grid(row=0, column=1, padx=5, pady=5)
scan_button = tk.Button(frame, text="Scan", command=start_scan, bg="#4CAF50", fg="white", font=("Arial", 14))
scan_button.grid(row=0, column=2, padx=5, pady=5)

columns = ("IP Address", "MAC Address")
tree = ttk.Treeview(root, columns=columns, show="headings", style="Custom.Treeview")
tree.heading("IP Address", text="IP Address")
tree.heading("MAC Address", text="MAC Address")
tree.column("IP Address", anchor=tk.CENTER, width=250)
tree.column("MAC Address", anchor=tk.CENTER, width=250)

tree.grid(row=1, column=0, padx=10, pady=10, columnspan=3, sticky="nsew")

# Adding style for border and column colors
style = ttk.Style()
style.configure("Custom.Treeview", background="#ffffff", foreground="Red", rowheight=25, fieldbackground="black")
style.configure("Custom.Treeview.Heading", font=("Arial", 10, "bold"), background="#4CAF50", foreground="Black", relief="raised", borderwidth=1)
style.configure("Custom.Treeview", borderwidth=10, relief="solid")
style.map("Custom.Treeview", background=[("selected", "#4CAF50")])

# Add striped row effect
style.map("Custom.Treeview", background=[("!selected", "#EAEAEA"), ("selected", "#4CAF50")])

# Add separators manually by inserting blank rows with lines
separator_style = ttk.Style()
separator_style.configure("Separator.Treeview", rowheight=2, background="black")

root.mainloop()

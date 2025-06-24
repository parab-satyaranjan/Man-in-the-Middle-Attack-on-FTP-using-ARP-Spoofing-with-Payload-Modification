#!/usr/bin/env python3
import os
import time
import subprocess
import socket
import requests
import smtplib
import ssl
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from twilio.rest import Client
import certifi

class ARPSpoofDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoofing Detector")
        self.root.geometry("800x600")
        
        # Twilio Credentials
        self.account_sid = ""   # USE YOUR OWN ACCOUNT SID
        self.auth_token = ""      # USE YOUR OWN AUTH TOKEN
        self.twilio_number = ""                       # USE YOUR OWN TWILIO No.
        self.to_number = ""                          # USE YOUR OWN PHONE No.
        
        # Email Credentials
        self.sender_email = ""  # USE YOUR OWN EMAIL ID
        self.receiver_email = ""  # USE YOUR OWN EMAIL ID
        self.email_password = "" # USE YOUR OWN EMAIL ID PASSWORD
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # Initialize ARP tables
        self.arp_table = defaultdict(list)
        self.known_duplicates = set()
        self.baseline_arp = {}
        
        # GUI setup
        self.setup_gui()
        self.refresh_arp_table(init=True)
        
        # Start monitoring
        self.running = True
        self.monitor_thread = Thread(target=self.monitor_arp_table)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_gui(self):
        """Initialize GUI components"""
        self.top_frame = tk.Frame(self.root)
        self.top_frame.pack(pady=10)
        
        self.table_frame = tk.Frame(self.root)
        self.table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.bottom_frame = tk.Frame(self.root)
        self.bottom_frame.pack(pady=10)
        
        # Title label
        self.title_label = tk.Label(
            self.top_frame,
            text="ARP Spoofing Detector",
            font=('Helvetica', 16, 'bold')
        )
        self.title_label.pack()
        
        # Status label
        self.status_label = tk.Label(
            self.top_frame,
            text="Status: Monitoring...",
            font=('Helvetica', 10)
        )
        self.status_label.pack()
        
        # ARP table treeview
        self.tree = ttk.Treeview(self.table_frame, columns=('IP', 'MAC', 'Interface'), show='headings')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Interface', text='Interface')
        self.tree.column('IP', width=200, anchor=tk.CENTER)
        self.tree.column('MAC', width=250, anchor=tk.CENTER)
        self.tree.column('Interface', width=150, anchor=tk.CENTER)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        self.refresh_btn = tk.Button(
            self.bottom_frame,
            text="Refresh Now",
            command=lambda: self.refresh_arp_table(init=False)
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.exit_btn = tk.Button(
            self.bottom_frame,
            text="Exit",
            command=self.on_close
        )
        self.exit_btn.pack(side=tk.RIGHT, padx=5)

    def get_network_info(self):
        """Retrieves public IP, private IP, and hostname of the system."""
        try:
            public_ip = requests.get("https://api64.ipify.org").text
            local_ip = socket.gethostbyname(socket.gethostname())
            hostname = socket.gethostname()
            return public_ip, local_ip, hostname
        except Exception:
            return "Unavailable", "Unavailable", "Unavailable"
    
    def get_arp_table(self):
        """Fetch and parse the ARP table"""
        arp_table = defaultdict(list)
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 6 and parts[0] == '?' and parts[1].startswith('('):
                    ip = parts[1][1:-1]
                    mac = parts[3]
                    if mac.lower() not in ['incomplete', 'ff:ff:ff:ff:ff:ff']:
                        interface = parts[parts.index('on') + 1] if 'on' in parts else 'unknown'
                        arp_table[mac].append((ip, interface))
        except:
            try:
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True, check=True)
                for line in result.stdout.split('\n')[1:]:
                    if not line.strip():
                        continue
                    parts = line.split()
                    ip = parts[0]
                    mac = parts[2] if ':' in parts[2] else parts[1]
                    if mac.lower() not in ['incomplete', 'ff:ff:ff:ff:ff:ff']:
                        interface = parts[5] if len(parts) > 5 else 'unknown'
                        arp_table[mac].append((ip, interface))
            except Exception as e:
                print(f"Error getting ARP table: {e}")
        return arp_table
    
    def refresh_arp_table(self, init=False):
        """Refresh ARP table and check for anomalies"""
        self.status_label.config(text="Status: Refreshing...")
        self.root.update()
        
        current_arp = self.get_arp_table()
        if current_arp:
            self.update_arp_display(current_arp)
            
            if init:
                self.baseline_arp = {ip: mac for mac, entries in current_arp.items() for ip, _ in entries}
                print(f"Baseline ARP stored: {self.baseline_arp}")
            
            self.check_for_duplicates(current_arp)
        
        self.status_label.config(text="Status: Monitoring...")
    
    def update_arp_display(self, arp_table):
        """Update the GUI table"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for mac, entries in arp_table.items():
            for ip, interface in entries:
                self.tree.insert('', tk.END, values=(ip, mac, interface))
        
        duplicates = {mac: ips for mac, ips in arp_table.items() if len(ips) > 1}
        for mac in duplicates:
            for item in self.tree.get_children():
                if self.tree.item(item, 'values')[1] == mac:
                    self.tree.tag_configure('duplicate', background='#ffcccc')
                    self.tree.item(item, tags=('duplicate',))
    
    def check_for_duplicates(self, current_arp):
        """Check for MAC conflicts and changes from baseline"""
        for mac, entries in current_arp.items():
            for ip, _ in entries:
                if ip in self.baseline_arp and self.baseline_arp[ip] != mac:
                    print(f"MAC changed for {ip}! Was {self.baseline_arp[ip]}, now {mac}")
                    original_ip = next((ip for ip, mac_val in self.baseline_arp.items() if mac_val == mac), None)
                    if original_ip:
                        self.trigger_alerts(ip, mac, original_ip)
    
    def trigger_alerts(self, spoofed_ip, spoofed_mac, attacker_ip):
        """Trigger all alert mechanisms with simplified SMS/GUI messages"""
        public_ip, private_ip, hostname = self.get_network_info()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Detailed email message
        email_message = (
            f"🚨 ARP Spoofing Detected! 🚨\n\n"
            f"IP {spoofed_ip} now has MAC {spoofed_mac}\n"
            f"Originally had {self.baseline_arp[spoofed_ip]}\n"
            f"Likely attacker: {attacker_ip}\n\n"
            f"📅 Date & Time: {now}\n"
            f"🌐 Public IP: {public_ip}\n"
            f"🏠 Private IP: {private_ip}\n"
            f"🖥 Hostname: {hostname}\n"
            f"\n⚠️ Urgent action required!"
        )
        
        # Simplified messages for other channels
        sms_message = "ARP ATTACK"
        gui_message = "ARP ATTACK"
        voice_message = "ARP ATTACK"
        
        # Show simplified GUI alert
        messagebox.showwarning("Security Alert", gui_message)
        
        # Send detailed email alert
        Thread(target=self.send_email_alert, args=(email_message,)).start()
        
        # Send simplified SMS alert
        Thread(target=self.send_sms_alert, args=(sms_message,)).start()
        
        # Send simplified voice alert
        Thread(target=self.send_voice_alert, args=(voice_message,)).start()
    
    def send_email_alert(self, message):
        """Send detailed email alert"""
        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender_email
            msg["To"] = self.receiver_email
            msg["Subject"] = "🚨 ARP Spoofing Detected!"
            msg.attach(MIMEText(message, "plain"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=self.ssl_context) as server:
                server.login(self.sender_email, self.email_password)
                server.sendmail(self.sender_email, self.receiver_email, msg.as_string())
            print("Detailed email alert sent successfully")
        except Exception as e:
            print(f"Failed to send email alert: {str(e)}")
    
    def send_sms_alert(self, message):
        """Send simplified SMS alert"""
        try:
            client = Client(self.account_sid, self.auth_token)
            client.messages.create(
                body=message,
                from_=self.twilio_number,
                to=self.to_number
            )
            print("SMS alert sent successfully")
        except Exception as e:
            print(f"Failed to send SMS alert: {str(e)}")
    
    def send_voice_alert(self, message):
        """Send simplified voice alert"""
        try:
            client = Client(self.account_sid, self.auth_token)
            call = client.calls.create(
                to=self.to_number,
                from_=self.twilio_number,
                twiml=f'<Response><Say voice="alice">{message}</Say></Response>'
            )
            print("Voice alert initiated successfully")
        except Exception as e:
            print(f"Failed to initiate voice call: {str(e)}")
    
    def monitor_arp_table(self):
        """Background thread to monitor ARP table"""
        while self.running:
            self.refresh_arp_table(init=False)
            time.sleep(5)
    
    def on_close(self):
        """Cleanup on window close"""
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ARPSpoofDetector(root)
    root.mainloop()

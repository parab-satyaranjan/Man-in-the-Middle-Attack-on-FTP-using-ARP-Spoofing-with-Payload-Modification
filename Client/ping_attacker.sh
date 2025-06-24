#!/bin/bash

# Ask user for IP address
read -p "Enter the ATTACKER IP: " ip

# Ping the IP (3 packets) and hide output, only check success/failure
if ping -c 3 "$ip" > /dev/null 2>&1; then
    echo "Success: Able to ping ATTACKER"
else
    echo "Failure: Not able to ping ATTACKER"
fi

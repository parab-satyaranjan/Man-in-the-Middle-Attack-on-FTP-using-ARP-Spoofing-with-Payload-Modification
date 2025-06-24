#!/bin/bash

# Ask user for IP address
read -p "Enter the CLIENT IP: " ip

# Ping the IP (3 packets) and hide output, only check success/failure
if ping -c 3 "$ip" > /dev/null 2>&1; then
    echo "Success: Able to ping CLIENT"
else
    echo "Failure: Not able to ping CLIENT"
fi

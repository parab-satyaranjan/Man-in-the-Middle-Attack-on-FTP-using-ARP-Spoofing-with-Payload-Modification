#!/bin/bash
interface=$(ip route | awk '/default/ {print $5}')
echo "Interface: $interface"

#!/bin/bash
echo "IP: $(hostname -I | awk '{print $1}')"

# Man-in-the-Middle-Attack-on-FTP-using-ARP-Spoofing-with-Payload-Modification

**Project Description**
This project demonstrates a Man-in-the-Middle (MITM) attack on FTP communication using ARP spoofing, along with a real-time detection and alert system.

**Overview**
In a simulated local network, three machines are involved:
•	Client – Uploads or downloads files using FTP.
•	Server – Hosts the FTP server.
•	Attacker – Performs ARP spoofing to intercept and modify files in transit.
The attacker positions itself between the client and server by poisoning their ARP tables, allowing interception, modification, and forwarding of FTP file transfers. This enables in-transit payload manipulation during both file uploads and downloads.

**ARP Spoofing Detection System**
To detect such attacks, the project includes a real-time ARP monitoring script on both the client and server sides. The system continuously scans the ARP table and checks for duplicate MAC addresses mapped to different IPs — a strong indicator of ARP spoofing.
When duplication is detected:
•	An alert is triggered and sent to the network security administrator.
•	The alert is delivered via:
  o	Phone call
  o	SMS
  o	Email
These notifications are powered using Twilio's API, ensuring the administrator is informed immediately about potential MITM activity.

**Key Features**
•	Simulates active file interception and modification in FTP using Scapy and NetfilterQueue.
•	Implements ARP table inspection for spoofing detection.
•	Sends multi-channel alerts via Twilio when an attack is detected.
•	Provides a real-world understanding of how MITM attacks compromise data integrity and how they can be detected.


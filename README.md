Sniffing-Tools — README

Thanks — I looked at your repository and wrote a complete README.md that explains each script, how to run them, required dependencies, common errors and safety/legal notes. Paste the text below into a README.md at the root of Sniffing-Tools.

Sniffing-Tools

Lightweight collection of Python sniffing/scanning tools (packet parsing + simple ICMP/UDP scanner).
Files in this repo: decoding_ip_layer.py, packet_sniffing.py, scanner.py, sniffer_with_icmp.py. 
GitHub

Warning / Legal: these scripts capture and transmit network traffic. Run them only on networks and hosts you own or are explicitly authorized to test. Unauthorized scanning or sniffing is illegal in many jurisdictions.

Requirements

Python 3.8+ (tested on Linux)

Recommended packages:

netaddr — pip install netaddr

Run as root / administrator for raw sockets:

Linux: sudo python3 <script>.py

Windows: run in an elevated prompt (some scripts enable SIO_RCVALL)

Quick setup

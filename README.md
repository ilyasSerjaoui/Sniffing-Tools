# Sniffing-Tools

Lightweight collection of Python sniffing/scanning tools (packet parsing + simple ICMP/UDP scanner).

> **Warning / Legal**: these scripts capture and transmit network traffic. Run them only on networks and hosts you own or are explicitly authorized to test. Unauthorized scanning or sniffing is illegal in many jurisdictions.

---

## Requirements

* Python 3.8+ (tested on Linux)
* Recommended packages:

  * `netaddr` — `pip install netaddr`
* Run as root / administrator for raw sockets:

  * Linux: `sudo python3 <script>.py`
  * Windows: run in an elevated prompt (some scripts enable `SIO_RCVALL`)

---

## Quick setup

```bash
git clone https://github.com/ilyasSerjaoui/Sniffing-Tools.git
cd Sniffing-Tools
pip3 install netaddr
sudo python3 packet_sniffing.py
```

---

## Files & what they do

### `decoding_ip_layer.py`

Parses raw bytes and decodes the IPv4 header fields (version, IHL, TTL, protocol, src/dst). Useful as a reusable module when you want to extract and print IP-layer information from packets.

### `packet_sniffing.py`

Simple packet sniffer that captures packets and prints the IP header (protocol, source, destination).

* Behavior:

  * On **Linux**, captures using `AF_PACKET` and skips the 14-byte Ethernet header.
  * On **Windows**, uses `AF_INET` raw socket and enables promiscuous mode via `SIO_RCVALL`.
* Typical run:

  * Linux: `sudo python3 packet_sniffing.py`
  * Windows (elevated): `python packet_sniffing.py`
* Common errors:

  * `OSError: [Errno 93] Protocol not supported` → using `IPPROTO_IP` on Linux; ensure script uses `AF_PACKET` on Linux.
  * `Cannot assign requested address` → the `host` variable was set to an IP not assigned to any interface; use `0.0.0.0` or your actual interface IP.

### `sniffer_with_icmp.py`

Builds on `packet_sniffing.py` to parse ICMP headers in addition to the IP header.

* It extracts and prints ICMP Type/Code when an ICMP packet is observed.
* Notes:

  * Make sure the `IP` structure sizes use `c_uint32` for addresses (4 bytes) to avoid `ValueError: Buffer size too small`.
  * When capturing with `AF_PACKET`, skip the Ethernet header before creating the IP structure (`raw[14:34]`).

### `scanner.py`

UDP-based host discovery scanner that:

* Sprays UDP datagrams containing a “magic” payload to many IPs in a target subnet/wordlist.
* Listens for ICMP Type 3 / Code 3 (Destination Unreachable — Port Unreachable) replies that indicate a host is up (but the target UDP port is closed).
* Typical flow:

  1. Start the sniffer.
  2. After a short delay, the scanner thread sends `magic_message` to each host in the configured subnet/port.
  3. Sniffer watches for ICMP replies that include the original payload and prints `Host UP` for that IP.
* Usage:

  * Edit `subnet` variable (e.g., `10.0.2.0/24`), set `magic_message = b"PYTHONRULES!"`, then run as root.
* Caveats:

  * Many networks drop ICMP, or middleboxes / firewalls modify traffic, so results can be incomplete.
  * The script uses a tail-compare of the packet to the `magic_message`. This is a simple heuristic and may produce false negatives/positives in noisy environments.

---

## How to configure (common edits)

* `host` — IP to bind the sniffer to:

  * Use `"0.0.0.0"` for listening on all interfaces (Linux).
  * On Windows set it to the actual interface IP (e.g., `"192.168.1.50"`).
  * You can auto-detect local IP with a small helper:

    ```python
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host = s.getsockname()[0]
    s.close()
    ```
* `subnet` (scanner) — must be a valid CIDR: e.g. `"10.0.2.0/24"`
* `magic_message` — must be bytes: `b"PYTHONRULES!"`
* `AF_PACKET` vs `AF_INET`:

  * Linux: prefer `AF_PACKET` to capture link-layer + IP frames.
  * Windows: `AF_INET` + `IPPROTO_IP` + `SIO_RCVALL`.

---

## Troubleshooting – common errors & fixes

* `OSError: [Errno 99] Cannot assign requested address`

  * The `host` value is not an IP assigned to the machine. Use `0.0.0.0` or the correct interface IP.
  * Verify with: `ip addr show` or `ifconfig`.
* `OSError: [Errno 93] Protocol not supported`

  * Creating `socket.socket(AF_INET, SOCK_RAW, IPPROTO_IP)` on Linux can fail. Use `AF_PACKET` on Linux (example code in repo handles this).
* `ValueError: Buffer size too small (20 instead of at least 32 bytes)`

  * Caused by using `c_ulong` for IPv4 addresses on 64-bit systems. Use `c_uint32` for `src`/`dst` in the `IP` Structure.
* `PermissionError` or raw socket errors:

  * Run as root: `sudo python3 <script>.py`

---

## Safety & responsible use

* Only run these tools on networks and devices you own or for which you have explicit permission.
* Scanning or sniffing networks without authorization can be illegal and may get you blocked or prosecuted.
* If you plan to use these tools for learning, use an isolated lab/VM or a controlled testing network.

---

## Extending the tools

If you want to expand the project, consider:

* Adding CLI argument parsing (`argparse`) so `host`, `subnet`, `magic_message`, and logging options are configurable.
* Decoding TCP/UDP headers and printing ports/payload lengths.
* Save results to a CSV or JSON report.
* Add rate-limiting for UDP sender and a size or terminator check for file transfers (if you add upload features).

---

## License & contact

Add a license file if you want to permit reuse (MIT is a common choice for learning tools).
If you want, I can prepare an MIT `LICENSE` file and a short CONTRIBUTING guide.

---

## Author

ilyasSerjaoui — tools and scripts for learning packet sniffing and host discovery.

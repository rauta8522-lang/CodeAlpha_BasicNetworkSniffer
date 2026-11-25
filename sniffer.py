import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from colorama import init, Fore, Style

# Initialize colorama for Windows terminal support
init(autoreset=True)

captured_packets = []

def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP", Fore.GREEN
    elif packet.haslayer(UDP):
        return "UDP", Fore.CYAN
    elif packet.haslayer(ICMP):
        return "ICMP", Fore.YELLOW
    else:
        return "OTHER", Fore.MAGENTA

def format_payload(payload_bytes, max_len=60):
    try:
        decoded = payload_bytes.decode("utf-8", errors="replace").strip()
        clean = "".join(ch if ch.isprintable() else "." for ch in decoded)
        return clean[:max_len] + ("..." if len(clean) > max_len else "")
    except Exception:
        return "<Binary Data>"

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    captured_packets.append(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_name, color = get_protocol_name(packet)

    port_info = ""
    if packet.haslayer(TCP):
        port_info = f" | Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
    elif packet.haslayer(UDP):
        port_info = f" | Ports: {packet[UDP].sport} -> {packet[UDP].dport}"

    print(
        f"{Fore.WHITE}[{timestamp}] "
        f"{color}{Style.BRIGHT}[{proto_name}]{Style.RESET_ALL} "
        f"{src_ip} -> {dst_ip}{port_info}"
    )

    if packet.haslayer(Raw):
        payload_preview = format_payload(packet[Raw].load)
        if payload_preview:
            print(f"   {Fore.LIGHTBLACK_EX}Payload: {payload_preview}")

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Packet Sniffer")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface (e.g., Wi-Fi, eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", type=str, default="ip", help="BPF filter (e.g., 'tcp', 'udp', 'icmp', 'port 80')")
    parser.add_argument("-o", "--output", type=str, default="captured_traffic.pcap", help="Save captured packets to PCAP file")
    args = parser.parse_args()

    print(f"{Fore.CYAN}{Style.BRIGHT}====================================================")
    print(f"       CodeAlpha - Basic Network Sniffer Tool       ")
    print(f"===================================================={Style.RESET_ALL}")
    print(f"Filter     : {args.filter}")
    print(f"Interface  : {args.interface or 'Default Active Interface'}")
    print(f"Count      : {'Unlimited (Press Ctrl+C to stop)' if args.count == 0 else args.count}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Capture stopped by user.")
    except PermissionError:
        print(f"\n{Fore.RED}[Error] Permission denied! Please run your terminal as Administrator/root.")
        return

    if captured_packets and args.output:
        wrpcap(args.output, captured_packets)
        print(f"{Fore.GREEN}[+] Saved {len(captured_packets)} packets to '{args.output}'")

if __name__ == "__main__":
    from waitress import serve

    sniffer_thread = threading.Thread(target=start_sniffer_background, daemon=True)
    sniffer_thread.start()
    print("[*] Live Web Sniffer running at http://127.0.0.1:5000")
    serve(app, host="127.0.0.1", port=5000, threads=8)
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from collections import Counter
import datetime

# Map protocol numbers to names
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

captured = []
proto_counter = Counter()

def analyse_packet(packet):
    # Skip non-IP packets
    if not packet.haslayer(IP):
        return

    captured.append(packet)

    ip = packet[IP]
    now = datetime.datetime.now().strftime("%H:%M:%S")
    proto_name = PROTO_MAP.get(ip.proto, f"PROTO-{ip.proto}")

    # Get port numbers (only TCP and UDP have ports)
    sport, dport = "-", "-"
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    # Get payload preview
    payload = ""
    if packet.haslayer(Raw):
        raw = packet[Raw].load
        payload = raw.decode("utf-8", errors="replace")[:40]
        payload = repr(payload)

    # Print formatted output
    print(f"[{now}] {proto_name:<5} {ip.src}:{sport} --> {ip.dst}:{dport}")
    if payload:
        print(f"         Payload: {payload}")
    print("-" * 60)

    # Count protocols
    if packet.haslayer(TCP):
        proto_counter["TCP"] += 1
    elif packet.haslayer(UDP):
        proto_counter["UDP"] += 1
    elif packet.haslayer(ICMP):
        proto_counter["ICMP"] += 1
    else:
        proto_counter["Other"] += 1

print("=== CodeAlpha Network Sniffer ===")
print("Capturing 30 packets... Press Ctrl+C to stop")
print("-" * 60)

sniff(prn=analyse_packet, count=30, verbose=False)

# Save to .pcap file
wrpcap("capture.pcap", captured)
print("\nSaved to capture.pcap")

# Print summary
print("\n=== Traffic Summary ===")
print(f"Total packets : {len(captured)}")
for proto, count in proto_counter.most_common():
    print(f"  {proto:<8}: {count} packets")
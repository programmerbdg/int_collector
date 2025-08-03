# -*- coding: utf-8 -*-
from scapy.all import sniff, IP, UDP, Raw
import struct

# Ganti sesuai port dan IP monitoring (dari do_report_encapsulation)
INT_REPORT_DST_PORT = 5001  # Sesuaikan jika tidak cocok

def parse_int_metadata(data):
    hop_len = 24  # 6 field @ 4 bytes
    hops = []
    while len(data) >= hop_len:
        hop_data = data[:hop_len]
        fields = struct.unpack(">6I", hop_data)
        hop = {
            "switch_id": fields[0],
            "ingress_ts": fields[1],
            "egress_ts": fields[2],
            "hop_latency": fields[3],
            "queue_occupancy": fields[4],
            "egress_tx_util": fields[5]
        }
        hops.append(hop)
        data = data[hop_len:]
    return hops

def handle_packet(pkt):
    if UDP in pkt and pkt[UDP].dport == INT_REPORT_DST_PORT:
        payload = bytes(pkt[Raw]) if Raw in pkt else None
        if payload:
            print("[+] INT Report received from %s" % pkt[IP].src)
            hops = parse_int_metadata(payload)
            for i, hop in enumerate(hops):
                print("  Hop #%d:" % (i + 1))
                for k, v in hop.items():
                    print("    %s: %s" % (k, v))
            print("-" * 40)

def main():
    iface = "s12-eth1"  # Ganti sesuai interface BMv2
    print("INT Collector started. Listening on interface %s..." % iface)
    sniff(iface=iface, prn=handle_packet, store=0)

if __name__ == "__main__":
    main()


#!/usr/bin/env python2
from scapy.all import Ether, IP, UDP, Raw, sendp
import time, random, string

# Configuration
dst_ip = "10.0.0.2"      # H2
src_ip = "10.0.0.3"      # H3
dst_port = 5001          # target port (e.g., application at H2)
iface = "s12-eth1"       # interface to s12

def random_payload(size=200):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

print("Starting background flooding to {}:{} from {} via {} ...".format(
    dst_ip, dst_port, src_ip, iface))
try:
    while True:
        sport = random.randint(1024, 65535)      # random source port
        payload = random_payload(200)            # random application data
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(dport=dst_port, sport=sport)/Raw(load=payload)
        sendp(pkt, iface=iface, verbose=False)

except KeyboardInterrupt:
    print("\nFlooding stopped by user.")


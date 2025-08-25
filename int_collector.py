# int_collector_prometheus.py
# -*- coding: utf-8 -*-
from scapy.all import sniff, IP, UDP, Raw
import struct
from flask import Flask, Response
import threading
import csv, os
from datetime import datetime
import argparse

CSV_FILE = "int_dataset.csv"

INT_REPORT_DST_PORT = 5001  # Port tujuan INT report
iface = "s12-eth1"  # Ganti dengan interface kamu (ex: s1-eth1, eth0, dll)

# Menyimpan data INT terakhir per switch
last_hops_data = []

# Global variabel label
LABEL = None   # None = tidak ada label / tidak simpan ke CSV

# Flask App untuk Prometheus metrics
app = Flask(__name__)

@app.route("/metrics")
def metrics():
    global last_hops_data
    output = []

    for i, hop in enumerate(last_hops_data):
        labels = 'index="{}",switch_id="{}"'.format(i, hop["switch_id"])
        output.append('int_ingress_ts{{{}}} {}'.format(labels, hop["ingress_ts"]))
        output.append('int_egress_ts{{{}}} {}'.format(labels, hop["egress_ts"]))
        output.append('int_hop_latency{{{}}} {}'.format(labels, hop["hop_latency"]))
        output.append('int_queue_occupancy{{{}}} {}'.format(labels, hop["queue_occupancy"]))
        output.append('int_egress_tx_util{{{}}} {}'.format(labels, hop["egress_tx_util"]))

    return Response("\n".join(output) + "\n", mimetype="text/plain")


def parse_int_metadata(data: bytes):
    hop_len = 24  # 6 field x 4 byte = 24 bytes per hop
    hops = []
    while len(data) >= hop_len:
        hop_data = data[:hop_len]

        switch_id = struct.unpack(">I", hop_data[0:4])[0]
        ingress_ts = struct.unpack(">I", hop_data[4:8])[0]
        egress_ts = struct.unpack(">I", hop_data[8:12])[0]
        hop_latency = struct.unpack(">I", hop_data[12:16])[0]

        # Python 3: gunakan int.from_bytes()
        q_id = hop_data[16]
        q_occ = (hop_data[17] << 16) | (hop_data[18] << 8) | hop_data[19]

        egress_tx_util = struct.unpack(">I", hop_data[20:24])[0]

        hop = {
            "switch_id": switch_id,
            "ingress_ts": ingress_ts,
            "egress_ts": egress_ts,
            "hop_latency": hop_latency,
            "queue_id": q_id,
            "queue_occupancy": q_occ,
            "egress_tx_util": egress_tx_util
        }
        hops.append(hop)
        data = data[hop_len:]
    return hops


def handle_packet(pkt):
    global last_hops_data, LABEL
    if UDP in pkt and pkt[UDP].dport == INT_REPORT_DST_PORT:
        payload = bytes(pkt[Raw]) if Raw in pkt else None  # Python3: Raw -> bytes
        if payload:
            hops = parse_int_metadata(payload)
            last_hops_data = hops  # update data untuk Prometheus
            for i, hop in enumerate(hops):
                print("  Hop #{}".format(i + 1))
                for k, v in hop.items():
                    print("    {}: {}".format(k, v))
            print("-" * 40)

            # Simpan ke CSV hanya jika LABEL tidak None
            if LABEL is not None:
                save_to_csv(hops, label=LABEL)


def save_to_csv(hops, label=0):  # default label = normal
    file_exists = os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:  # Python3: text mode, newline=""
        writer = csv.writer(f)
        # tulis header kalau file baru
        if not file_exists:
            writer.writerow([
                "timestamp", "switch_id", "hop_latency",
                "queue_occupancy", "egress_tx_util", "label"
            ])
        for hop in hops:
            writer.writerow([
                datetime.utcnow().isoformat(),
                hop["switch_id"],
                hop["hop_latency"],
                hop["queue_occupancy"],
                hop["egress_tx_util"],
                label
            ])


def sniff_thread():
    print("INT Collector started. Listening on interface {}...".format(iface))
    sniff(iface=iface, prn=handle_packet, store=0)


def main():
    parser = argparse.ArgumentParser(description="INT Collector with optional labeling")
    parser.add_argument("--label", type=str, choices=["normal", "ddos"],
                        help="Label traffic type: normal or ddos. Jika tidak diberikan, collector hanya untuk Prometheus (tanpa simpan CSV).")
    args = parser.parse_args()

    global LABEL

    if args.label is None:
        print("[*] Prometheus only mode")
        LABEL = None
    else:
        LABEL = 0 if args.label == "normal" else 1
        print("[*] Collector started with label =", args.label)

    # Jalankan thread untuk sniffing
    t = threading.Thread(target=sniff_thread)
    t.daemon = True
    t.start()

    # Jalankan Flask untuk endpoint Prometheus
    app.run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()

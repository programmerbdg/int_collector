def handle_packet(pkt):
    global last_hops_data, LABEL
    if UDP in pkt and pkt[UDP].dport == INT_REPORT_DST_PORT:
        payload = bytes(pkt[Raw]) if Raw in pkt else None
        if payload:
            hops = parse_int_metadata(payload)
            last_hops_data = hops  # update data for Prometheus
            for i, hop in enumerate(hops):
                print("  Hop #{}".format(i + 1))
                for k, v in hop.items():
                    print("    {}: {}".format(k, v))
            print("-" * 40)

            # Only save if LABEL is not None
            if LABEL is not None:
                save_to_csv(hops, label=LABEL)


def main():
    parser = argparse.ArgumentParser(description="INT Collector with labeling")
    parser.add_argument("--label", type=str, choices=["normal", "ddos"],
                        help="Label traffic type: normal or ddos (optional)")
    args = parser.parse_args()

    global LABEL

    if args.label is None:
        LABEL = None   # <-- no CSV saving
        print("[*] Collector started WITHOUT labeling (Prometheus only mode)")
    else:
        LABEL = 0 if args.label == "normal" else 1
        print("[*] Collector started WITH label =", args.label)

        # Create CSV file only if labeling is active
        if not os.path.exists(CSV_FILE):
            with open(CSV_FILE, "wb") as f:
                writer = csv.writer(f)
                writer.writerow([
                   "timestamp", "switch_id", "hop_latency",
                   "queue_occupancy", "egress_tx_util", "label"
                ])

    # Start sniffing thread
    t = threading.Thread(target=sniff_thread)
    t.daemon = True
    t.start()

    # Start Prometheus Flask app
    app.run(host="0.0.0.0", port=8000)


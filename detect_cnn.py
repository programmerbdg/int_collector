import time
import requests
import numpy as np
from collections import deque
from keras.models import load_model
import joblib

# === Load CNN model & scaler ===
try:
    model = load_model("cnn_int_model.h5")
    print("✅ Model loaded: cnn_int_model.h5")
except Exception as e:
    print("❌ Failed to load model:", e)
    exit(1)

try:
    scaler = joblib.load("scaler.pkl")
    print("✅ Scaler loaded: scaler.pkl")
except Exception as e:
    print("❌ Failed to load scaler:", e)
    exit(1)

# === Buffer sliding window ===
BUFFER_SIZE = 50   # harus sama dengan waktu training
buffer = deque(maxlen=BUFFER_SIZE)

PROM_URL = "http://127.0.0.1:8000/metrics"  # ganti sesuai alamat collector


def fetch_metrics():
    """
    Ambil data dari endpoint /metrics collector
    Return dict per switch_id dengan metric terupdate
    """
    try:
        resp = requests.get(PROM_URL, timeout=5)
        lines = resp.text.strip().splitlines()
        data = {}
        for line in lines:
            if line.startswith("int_"):
                metric, rest = line.split("{", 1)
                labels, value = rest.split("} ")
                value = float(value)
                parts = {kv.split("=")[0]: kv.split("=")[1].strip('"') for kv in labels.split(",")}
                idx = int(parts["index"])
                if idx not in data:
                    data[idx] = {}
                data[idx][metric] = value
        return data
    except Exception as e:
        print("❌ Error fetching metrics:", e)
        return {}


print("🚀 Real-time CNN detection started...")

while True:
    try:
        metrics = fetch_metrics()
        if not metrics:
            time.sleep(1)
            continue

        for idx, hop in metrics.items():
            # Ambil 3 fitur utama
            features = [
                hop.get("int_hop_latency", 0),
                hop.get("int_queue_occupancy", 0),
                hop.get("int_egress_tx_util", 0),
            ]

            # Normalisasi dengan scaler hasil training
            features = scaler.transform([features])[0]
            buffer.append(features)

        # Prediksi kalau buffer penuh
        if len(buffer) >= BUFFER_SIZE:
            X = np.array(buffer)[-BUFFER_SIZE:]  # ambil window terakhir (50 langkah)

            # Reshape sesuai input training (samples, 50, 3, 1)
            X = np.reshape(X, (1, BUFFER_SIZE, 3, 1))

            y_pred = model.predict(X, verbose=0)
            ddos_score = float(y_pred[0][0])

            if ddos_score > 0.7:
                print("⚠️  DDoS Detected! score={:.2f}".format(ddos_score))
            else:
                print("✅ Normal traffic score={:.2f}".format(ddos_score))

        time.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Stopped by user")
        break
    except Exception as e:
        print("❌ Runtime error:", e)
        time.sleep(2)


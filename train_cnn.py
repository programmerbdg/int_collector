import os
import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import Conv2D, Flatten, Dense

DATA_FILE = "int_dataset.csv"

# === Check dataset existence ===
if not os.path.exists(DATA_FILE):
    print("❌ Dataset file '{}' not found. Exiting...".format(DATA_FILE))
    sys.exit(1)

try:
    # Load dataset
    data = pd.read_csv(DATA_FILE)

    # Check minimal columns
    required_cols = {"hop_latency", "queue_occupancy", "egress_tx_util", "label"}
    if not required_cols.issubset(data.columns):
        print("❌ Dataset missing required columns. Found: {}".format(list(data.columns)))
        sys.exit(1)

    # Features & labels
    X = data[["hop_latency", "queue_occupancy", "egress_tx_util"]].values
    y = data["label"].values

    # Normalization
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Reshape for CNN input (format: channels_last → (samples, rows, cols, channels))
    X = X.reshape((X.shape[0], 3, 1, 1))

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # CNN Model
    model = Sequential()
    model.add(Conv2D(16, (2, 1), activation='relu', input_shape=(3, 1, 1)))
    model.add(Flatten())
    model.add(Dense(32, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Training
    print("🚀 Training started...")
    model.fit(X_train, y_train, epochs=20, batch_size=16, validation_split=0.1, verbose=1)

    # Evaluation
    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print("✅ Test Accuracy:", acc)

    # Save model
    model.save("cnn_int_model.h5")
    print("✅ Model saved as cnn_int_model.h5")

except KeyboardInterrupt:
    print("\n⚠️ Training interrupted by user. Exiting gracefully...")
    sys.exit(1)

except Exception as e:
    print("❌ Error during training: {}".format(str(e)))
    sys.exit(1)


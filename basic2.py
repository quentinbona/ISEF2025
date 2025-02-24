import numpy as np
import tensorflow as tf
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical


# ------------------- Step 1: Extract Features from PCAP -------------------
def extract_features(packets):
    data = []
    labels = []

    for packet in packets:
        if IP in packet:  # Ensure it's an IP packet
            features = []

            # Extract basic IP-level features
            features.append(len(packet))  # Packet size
            features.append(packet[IP].ttl)  # Time-to-Live (TTL)
            features.append(packet[IP].proto)  # Protocol number (TCP=6, UDP=17, etc.)

            # Extract TCP/UDP-specific features
            if TCP in packet:
                features.append(packet[TCP].sport)  # Source port
                features.append(packet[TCP].dport)  # Destination port
                features.append(packet[TCP].flags)  # TCP flags
            elif UDP in packet:
                features.append(packet[UDP].sport)
                features.append(packet[UDP].dport)
                features.append(0)  # Placeholder for TCP flags

            # Label heuristic (0 = benign, 1 = suspect)
            label = 1 if (features[3] in [4444, 6667, 31337] or features[4] in [4444, 6667, 31337]) else 0

            data.append(features)
            labels.append(label)

    return np.array(data), np.array(labels)


# ------------------- Step 2: Train a Simple Deep Learning Model -------------------
def train_model(X, y):
    # Normalize feature values
    X = X / np.max(X, axis=0)

    # Split data into training & testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Convert labels to categorical
    y_train = to_categorical(y_train, num_classes=2)
    y_test = to_categorical(y_test, num_classes=2)

    # Define a simple neural network
    model = Sequential([
        Dense(32, activation='relu', input_shape=(X.shape[1],)),
        Dropout(0.2),
        Dense(16, activation='relu'),
        Dropout(0.2),
        Dense(2, activation='softmax')  # Binary classification (benign vs malicious)
    ])

    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

    # Train the model
    model.fit(X_train, y_train, epochs=20, batch_size=16, validation_data=(X_test, y_test))

    # Evaluate the model
    loss, accuracy = model.evaluate(X_test, y_test)
    print(f"Model Accuracy: {accuracy:.4f}")

    return model


# ------------------- Step 3: Detect Malicious Packets -------------------
def detect_malicious_traffic(model, file_path):
    packets = rdpcap(file_path)
    X, _ = extract_features(packets)
    X = X / np.max(X, axis=0)  # Normalize

    predictions = model.predict(X)
    suspect_indices = np.where(np.argmax(predictions, axis=1) == 1)[0]

    print("\n---- Potential Malicious Packets ----")
    for idx in suspect_indices:
        print(f"Packet {idx + 1}: Possible Malicious Activity Detected")
    print("--------------------------------------\n")


# ------------------- Main Execution -------------------
if __name__ == "__main__":
    pcap_file = "sample.pcap"  # Replace with actual file path
    packets = rdpcap(pcap_file)

    # Extract Features & Labels
    X, y = extract_features(packets)

    if len(X) > 0:
        model = train_model(X, y)
        detect_malicious_traffic(model, pcap_file)
    else:
        print("No valid packets found in the capture.")

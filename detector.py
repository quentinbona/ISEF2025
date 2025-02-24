import numpy as np
import tensorflow as tf
from scapy.all import rdpcap
from feature_extractor import extract_features

def detect_malicious_traffic(model, file_path):
    """
    Loads a PCAP file, extracts features, and uses a trained model to detect malicious packets.
    """
    packets = rdpcap(file_path)
    X, _ = extract_features(packets)

    # Normalize feature values
    X = X / np.max(X, axis=0)

    # Make predictions
    predictions = model.predict(X)
    suspect_indices = np.where(np.argmax(predictions, axis=1) == 1)[0]

    print("\n---- Potential Malicious Packets ----")
    for idx in suspect_indices:
        print(f"Packet {idx+1}: Possible Malicious Activity Detected")
    print("--------------------------------------\n")

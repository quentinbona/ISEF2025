import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def extract_features(packets):
    """
    Extracts numerical features from packets for machine learning.

    Returns:
        X (numpy array): Feature matrix
        y (numpy array): Labels (0 = benign, 1 = potentially malicious)
    """
    data = []
    labels = []

    for packet in packets:
        if IP in packet:
            features = []

            # Feature Extraction
            features.append(len(packet))  # Packet Size
            features.append(packet[IP].ttl)  # TTL (Time-To-Live)
            features.append(packet[IP].proto)  # Protocol Type (TCP=6, UDP=17, ICMP=1)

            # TCP/UDP Features
            if TCP in packet:
                features.append(packet[TCP].sport)  # Source Port
                features.append(packet[TCP].dport)  # Destination Port
                features.append(int(packet[TCP].flags))  # TCP Flags
            elif UDP in packet:
                features.append(packet[UDP].sport)
                features.append(packet[UDP].dport)
                features.append(0)  # Placeholder for TCP Flags (UDP has none)
            else:
                features.extend([0, 0, 0])  # No TCP/UDP fields

            # Heuristic-based labeling (you can improve this with real attack datasets)
            label = 1 if features[3] in [4444, 6667, 31337] or features[4] in [4444, 6667, 31337] else 0

            data.append(features)
            labels.append(label)

    return np.array(data), np.array(labels)

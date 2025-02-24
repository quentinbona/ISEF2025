from scapy.all import rdpcap
from feature_extractor import extract_features
from model import train_model
from detector import detect_malicious_traffic
from utils import save_model, load_model

if __name__ == "__main__":
    pcap_file = "datasets/sample.pcap"  # Replace with actual capture file

    print("[+] Extracting features from PCAP...")
    packets = rdpcap(pcap_file)
    X, y = extract_features(packets)

    if len(X) > 0:
        # Train or load the model
        model = load_model()
        if model is None:
            print("[+] Training model...")
            model = train_model(X, y)
            save_model(model)

        print("[+] Detecting malicious traffic...")
        detect_malicious_traffic(model, pcap_file)
    else:
        print("[!] No valid packets found in the capture.")

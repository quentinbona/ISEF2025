import pyshark
import sys


def detect_malicious(packet):
    """
    Applies a few simple heuristics to a packet:
      - Flags packets that are destined for uncommon ports.
      - Flags packets with HTTP user agents that might indicate automated tools.
      - Flags malformed packets if detected.
    Returns a tuple (is_malicious, reasons) where:
      is_malicious: Boolean indicating if the packet meets any criteria.
      reasons: A list of strings describing why the packet was flagged.
    """
    suspicious = False
    reasons = []

    # Heuristic 1: Check for TCP packets going to uncommon or suspect ports.
    try:
        if 'TCP' in packet:
            tcp_layer = packet.tcp
            # If a destination port is available, convert it to int.
            if hasattr(tcp_layer, 'dstport'):
                port = int(tcp_layer.dstport)
                # Example list of ports that could be considered suspect.
                if port in [4444, 6667, 31337]:
                    suspicious = True
                    reasons.append(f"Connection to uncommon/suspect TCP port: {port}")
    except Exception as e:
        # If there's an error accessing TCP fields, skip this heuristic.
        pass

    # Heuristic 2: Check for HTTP packets with potentially unusual user agents.
    try:
        if 'HTTP' in packet:
            http_layer = packet.http
            if hasattr(http_layer, 'user_agent'):
                user_agent = http_layer.user_agent.lower()
                # For demonstration, flag user agents from command-line tools.
                if "curl" in user_agent or "wget" in user_agent:
                    suspicious = True
                    reasons.append(f"HTTP packet with uncommon user agent: {http_layer.user_agent}")
    except Exception as e:
        pass

    # Heuristic 3: Check for malformed packets (if the capture provides such a flag).
    try:
        # Some captures may mark malformed packets – this is illustrative.
        if hasattr(packet, 'malformed') and packet.malformed == "1":
            suspicious = True
            reasons.append("Packet marked as malformed")
    except Exception as e:
        pass

    return suspicious, reasons


def analyze_pcap(file_path):
    """
    Loads the pcap/pcapng file and processes each packet.
    If any packet meets the heuristics for suspicious activity, its details and reasons are printed.
    """
    print(f"Analyzing file: {file_path}")
    try:
        cap = pyshark.FileCapture(file_path, keep_packets=False)
    except Exception as e:
        print(f"Error opening file: {e}")
        sys.exit(1)

    for packet in cap:
        try:
            is_malicious, reasons = detect_malicious(packet)
            if is_malicious:
                print("---- Malicious Packet Detected ----")
                try:
                    print("Timestamp:", packet.sniff_time)
                except Exception:
                    print("Timestamp not available")
                # You could expand here to print more detailed information.
                for reason in reasons:
                    print("Reason:", reason)
                print("-----------------------------------\n")
        except Exception as e:
            # Handle any packet parsing errors gracefully.
            continue
    cap.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcapng_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])

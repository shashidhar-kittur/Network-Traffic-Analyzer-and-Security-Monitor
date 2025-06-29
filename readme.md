Network Traffic Analyzer and Security Monitor
Overview
The Network Traffic Analyzer and Security Monitor is a Python-based tool for capturing, analyzing, and visualizing network traffic in real-time. It uses Scapy to sniff packets, SQLite to log packet data, and Matplotlib to visualize traffic patterns. The project focuses on monitoring TCP, UDP, and ICMP traffic over Wi-Fi, enabling users to detect anomalies, track network activity, and store data for further analysis.
Features

Real-Time Packet Capture: Captures TCP, UDP, and ICMP packets on a specified Wi-Fi interface using Scapy.
Data Logging: Stores packet details (timestamp, source/destination IPs, protocol, ports) in an SQLite database.
Visualization: Generates bar charts of packet counts by protocol (TCP, UDP, ICMP) using Matplotlib.
Security Monitoring: Supports detection of suspicious traffic (e.g., external IP connections).
Efficient Processing: Uses store=0 in Scapy to minimize memory usage during continuous captures.

Requirements

Python: Version 3.12 or 3.13 (tested with 3.13.3).
Npcap: Required for packet sniffing on Windows (download from npcap.com).
Dependencies:
Scapy (for packet capture and analysis)
Matplotlib (for visualization)
SQLite3 (built-in with Python, for data storage)



Installation

Clone the Repository:
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer


Create a Virtual Environment:
python -m venv virenv


Activate the Virtual Environment:

On Windows (PowerShell):.\virenv\Scripts\activate


On Linux/Mac:source virenv/bin/activate




Install Dependencies:
pip install -r requirements.txt


Install Npcap (Windows only):

Download and install Npcap from npcap.com.
Ensure "WinPcap API-compatible mode" is enabled during installation.
Run the script as Administrator for packet sniffing.



Usage

Identify Your Wi-Fi Interface:

Run the following to list network interfaces:python -c "from scapy.all import conf; print(conf.ifaces)"


Note the GUID for your Wi-Fi adapter (e.g., \\Device\\NPF_{44CA...}).


Update test.py:

Open test.py and set the interface variable to your Wi-Fi interface GUID:interface = "\\Device\\NPF_{44CA...}"  # Replace with your Wi-Fi GUID




Run the Script:

Open a terminal (PowerShell as Administrator on Windows):cd "path/to/network-traffic-analyzer"
.\virenv\Scripts\activate
python test.py


The script captures 10 packets, logs them to network_traffic.db, and displays a Matplotlib bar chart of protocol counts.


View Logged Data:

Query the SQLite database:sqlite3 network_traffic.db "SELECT * FROM traffic LIMIT 5;"


Example query for frequent destinations:sqlite3 network_traffic.db "SELECT dst_ip, COUNT(*) FROM traffic GROUP BY dst_ip;"





Example Script (test.py)
import sqlite3
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import matplotlib.pyplot as plt

# Initialize SQLite database
conn = sqlite3.connect("network_traffic.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        src_port INTEGER,
        dst_port INTEGER
    )
""")
conn.commit()

# Track packet counts for visualization
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}

def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"Unknown({proto_num})")
        src_port = dst_port = None

        if packet.haslayer("TCP"):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_counts["TCP"] += 1
        elif packet.haslayer("UDP"):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_counts["UDP"] += 1
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
            packet_counts["ICMP"] += 1

        # Log to SQLite
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO traffic (timestamp, src_ip, dst_ip, protocol, src_port, dst_port) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port)
        )
        conn.commit()

        # Print packet details
        print(f"{timestamp} | {protocol} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def plot_traffic():
    plt.bar(packet_counts.keys(), packet_counts.values())
    plt.title("Network Traffic by Protocol")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.show()

# Replace with your Wi-Fi interface GUID
interface = "\\Device\\NPF_{44CA...}"

# Sniff packets
sniff(iface=interface, filter="tcp or udp or icmp", prn=packet_callback, store=0, count=10)

# Plot results
plot_traffic()

# Close database connection
conn.close()

Project Structure
network-traffic-analyzer/
├── test.py              # Main script for packet capture and analysis
├── requirements.txt     # Python dependencies
├── .gitignore           # Excludes virenv, database, and cache files
└── network_traffic.db   # SQLite database (generated, not in repo)

.gitignore
The virenv folder and SQLite database are excluded to keep the repository lightweight:
virenv/
network_traffic.db
__pycache__/
*.pyc
*.pyo
*.pyd
.mpl-cache/

Notes

Run as Administrator: Packet sniffing requires administrative privileges. Run VS Code or PowerShell as Administrator.
Wi-Fi Interface: Replace \\Device\\NPF_{44CA...} in test.py with your Wi-Fi interface GUID.
Extending the Project:
Add anomaly detection (e.g., flag external IPs):if not packet[IP].dst.startswith("192.168."):
    print(f"ALERT: External traffic to {packet[IP].dst}")


Visualize time-based trends with Matplotlib:import pandas as pd
df = pd.read_sql_query("SELECT timestamp, protocol FROM traffic", conn)
df['timestamp'] = pd.to_datetime(df['timestamp'])
df.groupby(df['timestamp'].dt.minute).count().plot(kind='line')
plt.show()





Contributing
Contributions are welcome! Please submit a pull request or open an issue for suggestions, bug reports, or enhancements.
License
This project is licensed under the MIT License.
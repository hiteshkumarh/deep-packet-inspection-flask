# DPI Engine - Deep Packet Inspection Analyzer Documentation

## 1. Problem Statement
Traditional firewalls typically operate at the transport layer (Layer 4), filtering traffic based purely on IP addresses and port numbers. While effective for basic networking, this approach struggles in modern environments where multiple applications (e.g., YouTube, Facebook, WhatsApp) all share the same standard ports (like TCP 443 for HTTPS). 

Administrators face the challenge of blocking specific services that utilize encrypted transport tunnels without breaking other legitimate traffic, a process made difficult by modern TLS/SSL encryption. Standard IP-based blocking is an ineffective game of "whack-a-mole" due to dynamic CDNs and cloud hosting environments constantly changing the underlying IPs of these services.

## 2. Solution
This **Deep Packet Inspection (DPI) Engine** inspects the payload portion of network packets traversing the network. Instead of just looking at IP and Port combinations, the engine dives into the Application Layer (Layer 7). 

By passively dissecting network traffic, it identifies metadata *before* the encrypted tunnel is fully established:
- **TLS Client Hello Parsing**: Natively extracts the **Server Name Indication (SNI)** field, revealing the true requested domain (e.g., `youtube.com`) even though the subsequent payload will be encrypted.
- **HTTP Header Parsing**: Extracts the standard `Host` HTTP header for unencrypted traffic.
- **DNS Parsing**: Analyzes standard DNS requests.

This allows the engine to accurately identity the application layer protocol and apply rule-based filtering (Domain, Application Name, or IP) to drop unwanted packets and allow authorized traffic, presenting the results locally via a Flask web dashboard.

---

## 3. Project Architecture

The project utilizes a decoupled architecture split into two main components:
1. **Core DPI Engine (Backend Data Processor)**: Written in Python 3, this engine is responsible for the heavy lifting. It ingests raw network packets (from `.pcap` files), parses the internal protocols (Ethernet, IPv4, TCP, UDP) completely from scratch, performs deep inspection (SNI, HTTP), and filters the traffic based on provided rules.
2. **Web Dashboard (Full-Stack UI Layer)**: A Flask web server that presents a graphical interface to the user. It allows users to upload network captures, select blocking rules through a clean UI, executes the Python engine securely in the background using `subprocess.run`, and displays the filtering results.

---

## 4. Flowchart (Analysis Workflow)

```mermaid
graph TD
    A[User accesses Web Frontend] -->|Uploads PCAP & Selects Rules| B(Flask Web Server)
    B -->|Saves PCAP to /uploads| C{Execute Python DPI Engine}
    C -->|Spawns Subprocess| D[Python: main.py]
    
    D --> E[Read next packet from PCAP]
    E --> F[Parse Ethernet Frame]
    F --> G[Parse IPv4 Header]
    
    G --> H{Protocol?}
    H -->|TCP| I[Parse TCP Header]
    H -->|UDP| J[Parse UDP Header]
    H -->|Other| K[Ignore/Forward]
    
    I --> L{Payload Type?}
    L -->|TLS Client Hello| M[Extract SNI Domain]
    L -->|HTTP| N[Extract Host Header]
    
    M --> O[Match against Blocking Rules]
    N --> O
    
    O -->|Matches Rule| P[Mark as Blocked/Dropped]
    O -->|No Match| Q[Mark as Allowed]
    
    P --> R[Log filtering result]
    Q --> R
    
    R --> S{More packets?}
    S -->|Yes| E
    S -->|No| T[Generate CLI ASCII Output & JSON Report]
    
    T --> U[Flask receives standard output]
    U --> V[Frontend displays Visualization/Results]
```

---

## 5. Project Structure

```text
packet_analyzer/
├── backend/                   # Python Backend & API Logic
│   ├── app.py                 # Main Flask Application Entry Point
│   ├── routes/
│   │   └── analyze.py         # File upload & subprocess execution handling
│   ├── packet_analyzer_py/    # Python DPI Engine (Core Logic Layer)
│   │   ├── core/
│   │   │   ├── packet_parser.py
│   │   │   ├── pcap_reader.py
│   │   │   ├── rule_manager.py
│   │   │   ├── sni_extractor.py
│   │   │   └── types.py
│   │   └── main.py            # CLI entry point
│   └── uploads/               # Temporary storage for uploaded PCAP files
│
├── frontend/                  # Web Interface (Presentation Layer)
│   ├── templates/             # HTML Templates
│   │   └── index.html         # Main dashboard markup
│   └── static/                # Static UI assets served to the browser
│       ├── css/style.css
│       └── js/app.js
│
├── test_dpi.pcap              # Sample network traffic file containing varied L7 protocols
└── generate_test_pcap.py      # Simulation script to cleanly generate synthetic network flows
```

---

## 6. Detailed Project Explanation

### Python DPI Engine (`packet_analyzer_py`)
Unlike systems that rely on external C-bindings like `libpcap`, this engine processes raw binary directly using Python's standard `struct` module. 
- **`pcap_reader.py`**: Reads the global PCAP file header (identifying endianness and link-type) and iteratively unpacks the timestamps and raw bytes of individual packet headers.
- **`packet_parser.py`**: Takes the raw bytes and slices them into protocol fields. For example, it extracts the Source/Destination MAC from the first 14 bytes (Ethernet), extracts IPs from the IPv4 header, and identifies the transport layer protocol (TCP/UDP).
- **`sni_extractor.py`**: This is the "Deep" part of the DPI. It looks specifically for the signature of a TLS `Client Hello` handshake. By navigating through the TLS Record, Handshake Protocol, and TLS Extensions, it isolates the `Server Name Indication` string, effectively identifying the web service being accessed despite the encryption.
- **Stateful Analysis**: The engine associates individual packets into flows (using the standard 5-Tuple: Source IP, Dest IP, Source Port, Dest Port, Protocol) to maintain context over a continuous streaming session.

### Flask Web Server (`backend/` & `frontend/`)
- **`routes/analyze.py`**: Exposes a RESTful POST endpoint (`/api/analyze`). When a multi-part form payload (PCAP file + comma-separated blocking rules) hits this endpoint, it safely writes the file to disk and uses Python's standard `subprocess.run` to execute the core `main.py` script. It securely captures the standard output, ensures robust UTF-8 decoding, parses it for the UI, and returns the metadata alongside a file download link.
- **`frontend/`**: The static frontend (HTML/CSS/JS) provides an intuitive way for a user to interact with the system without needing command-line knowledge. It visualizes the JSON report generated by the backend, detailing how many packets were inspected, stripped, or validated, and provides a direct download link for the filtered `.pcap` capture.

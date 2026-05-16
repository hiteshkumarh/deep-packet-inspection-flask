# DPI Engine - Deep Packet Inspection Analyzer

A powerful Deep Packet Inspection (DPI) system designed to identify and filter network traffic by parsing the internal payloads of network packets. This engine can intercept TLS Client Hellos to extract Server Name Indications (SNI) and HTTP Host headers without decryption, enabling you to identify and block specific applications (like YouTube, TikTok, Facebook) regardless of encryption.

This project is fully powered by **Python 3**, featuring a high-performance core engine and a sleek, accessible **Flask** Web Dashboard.

---

## 🚀 Features

- **Raw PCAP Parsing**: Decodes Ethernet, IPv4, TCP, and UDP completely from scratch in Python.
- **Deep Packet Inspection**:
  - Extracts SNI from TLS 1.0-1.3 Client Hello messages natively.
  - Extracts `Host` headers from standard HTTP traffic.
  - Parses standard DNS requests.
- **Flow Tracking**: Stateful analysis associating multiple packets with a single unified conversation stream (Five-Tuple tracking).
- **Rule-Based Filtering**: Block outgoing access dynamically by Application Name, Domain, or Source IP.
- **Web Interface**: A sleek Flask-powered web UI to upload captures, configure rules, and generate real-time processing reports.
- **Export Filtered Traffic**: Download the resulting PCAP file containing only the forwarded (non-blocked) packets.

---

## 📦 Project Structure

```text
packet_analyzer/
├── backend/
│   ├── app.py                     # Main Flask Application Entry Point
│   ├── requirements.txt           # Python dependencies (Flask, Werkzeug)
│   ├── Dockerfile                 # Docker build configuration
│   ├── routes/                    # API Routes
│   │   └── analyze.py             # File upload & subprocess execution handling
│   ├── uploads/                   # Temporary directory for uploaded PCAPs
│   └── packet_analyzer_py/        # Python DPI Engine (Untouched Core)
│       ├── core/                  # Core parsing modules
│       └── main.py                # Python CLI Entry Point
│
├── frontend/
│   ├── templates/                 # HTML Templates
│   │   └── index.html             # Main dashboard UI
│   └── static/                    # Static Assets
│       ├── css/style.css
│       └── js/app.js
│
├── README.md
├── test_dpi.pcap              # Sample network traffic file
└── generate_test_pcap.py      # Script to generate sample PCAP
```

---

## 🛠️ Installation & Setup (Windows / macOS / Linux)

You will need **Python 3.10+** installed on your machine.

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/packet_analyzer.git
cd packet_analyzer
```

### 2. Create a Virtual Environment

It is highly recommended to isolate your project dependencies using a Python virtual environment.

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

Install the required backend dependencies (Flask, Werkzeug):

```bash
pip install -r backend/requirements.txt
```

---

## 🖥️ Running the Application

### Option 1: Web Dashboard (Recommended)

1. Start the Flask Web Server:
   ```bash
   python backend/app.py
   ```
2. Open your browser to `http://127.0.0.1:5000`
3. Upload a PCAP file (e.g., `test_dpi.pcap` from the root folder).
4. Select applications to block or pass and view your DPI filtering results instantly.
5. Click **Download Filtered PCAP** to retrieve the processed traffic file.

### Option 2: Command Line Interface (CLI)

You can run the DPI engine manually from the terminal for faster scripting flows without using the web dashboard:

```bash
# Basic Run
python backend/packet_analyzer_py/main.py test_dpi.pcap output.pcap

# With Blocking Rules
python backend/packet_analyzer_py/main.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

---

## 🐳 Docker Support

You can also run the web dashboard completely containerized. A minimal `python:3.12-slim` Docker image is provided.

```bash
# Build the image from the project root
docker build -f backend/Dockerfile -t dpi-analyzer .

# Run the container (Map port 5000)
docker run -p 5000:5000 dpi-analyzer
```
Navigate to `http://localhost:5000` to use the app.

---

## 🧪 Generating Test Data

If you need a mock `.pcap` capture file to experiment on, use the included Python script:

```bash
python generate_test_pcap.py
```
This generates a realistic network flow containing simulated TLS, HTTP, and DNS traffic routed to standard applications.

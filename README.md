# App 1: Automated Vulnerability Scanner & Report Generator

## Step 1: Set Up Environment
```bash
mkdir app1
python -m venv venv
venv\Scripts\activate   
cd app1 
```
And Install these requirements:
```bash
pip install python-nmap requests matplotlib jinja2 fpdf pip install scapy
```

## Step 2: Configuration File 
Make a new file and name it **config.json**
```bash
{
  "targets": ["50.6.160.47"],
  "report_format": "html",
  "output_file": "vulnerability_report.html"
}
```

## Step 3: Scanning Script 
Make a new file and name it **scanner.py**
```python
import json
import nmap
import requests

def scan_target(target):
    print(f"[+] Scanning {target}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV')
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', '')
                results.append({
                    'host': host,
                    'port': port,
                    'service': service,
                    'version': version
                })
    return results

def run_scans():
    with open('config.json') as f:
        config = json.load(f)

    report_data = []
    for target in config['targets']:
        result = scan_target(target)
        report_data.append({
            'target': target,
            'findings': result
        })

    return report_data

if __name__ == "__main__":
    from report_generator import generate_report
    data = run_scans()
    generate_report(data)

try:
    with open("discovered_targets.json") as f:
        config["targets"] = json.load(f)
except FileNotFoundError:
    pass
```

## Step 4: Report Generator 
Make a new file and name it **report_generator.py**
```python
from jinja2 import Template

def generate_report(results):
    with open('template.html', 'r', encoding='utf-8') as f:
        template = Template(f.read())
    rendered = template.render(results=results)
    with open('report.html', 'w', encoding='utf-8') as f:
        f.write(rendered)
    print("[+] Report generated as report.html")
```

## Step 5: HTML Template 
Make a new file and name it **template.html**
```bash
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f0f;
            color: #e0e0e0;
            margin: 0;
            padding: 30px;
            animation: fadeIn 1s ease-in-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        h1 {
            font-size: 36px;
            color: #00ffe7;
            text-align: center;
            margin-bottom: 50px;
            text-shadow: 0 0 10px #00ffe7;
        }

        .target {
            background: #1a1a1a;
            border: 2px solid;
            border-image: linear-gradient(to right, #00ffe7, #ff00cc) 1;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 40px;
            box-shadow: 0 0 20px rgba(0, 255, 231, 0.2);
        }

        h2 {
            color: #ff00cc;
            margin-bottom: 15px;
            text-shadow: 0 0 5px #ff00cc;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #2b2b2b;
            border-radius: 8px;
            overflow: hidden;
        }

        th, td {
            padding: 12px 16px;
            border: 1px solid #444;
            text-align: left;
        }

        th {
            background: linear-gradient(to right, #00ffe7, #ff00cc);
            color: #000;
        }

        tr:hover {
            background-color: #333;
            transition: background 0.3s ease;
        }

        @media (max-width: 768px) {
            table, th, td {
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <h1>🚨 Vulnerability Scan Report</h1>
    {% for entry in results %}
    <div class="target">
        <h2>📍 Target: {{ entry.target }}</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {% for item in entry.findings %}
                <tr>
                    <td>{{ item.host }}</td>
                    <td>{{ item.port }}</td>
                    <td>{{ item.service }}</td>
                    <td>{{ item.version }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endfor %}
</body>
</html>
```

## Step 6: Create a new file and name it vulnerability_report.html
```bash
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial; margin: 20px; background-color: #f5f5f5; }
        h1 { color: darkred; }
        .target { margin-bottom: 40px; background: white; padding: 20px; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border: 1px solid #ddd; }
        th { background: #333; color: white; }
    </style>
</head>
<body>
    <h1>🔒 Vulnerability Scan Report</h1>
    
    <div class="target">
        <h2>Target: scanme.nmap.org</h2>
        <table>
            <thead>
                <tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr>
            </thead>
            <tbody>
                
                <tr>
                    <td>8.8.8.8</td>
                    <td>22</td>
                    <td>ssh</td>
                    <td>6.6.1p1 Ubuntu 2ubuntu2.13</td>
                </tr>
                
                <tr>
                    <td>1.1.1.1</td>
                    <td>25</td>
                    <td>smtp</td>
                    <td></td>
                </tr>
                
                <tr>
                    <td>50.6.160.47</td>
                    <td>80</td>
                    <td>http</td>
                    <td>2.4.7</td>
                </tr>
                
                <tr>
                    <td>45.33.32.156</td>
                    <td>9929</td>
                    <td>nping-echo</td>
                    <td></td>
                </tr>
                
                <tr>
                    <td>45.33.32.156</td>
                    <td>31337</td>
                    <td>tcpwrapped</td>
                    <td></td>
                </tr>
                
            </tbody>
        </table>
    </div>
    
    <div class="target">
        <h2>Target: example.com</h2>
        <table>
            <thead>
                <tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr>
            </thead>
            <tbody>
                
                <tr>
                    <td>23.215.0.136</td>
                    <td>80</td>
                    <td>http</td>
                    <td></td>
                </tr>
                
                <tr>
                    <td>23.215.0.136</td>
                    <td>113</td>
                    <td>ident</td>
                    <td></td>
                </tr>
                
                <tr>
                    <td>23.215.0.136</td>
                    <td>443</td>
                    <td>http</td>
                    <td></td>
                </tr>
                
            </tbody>
        </table>
    </div>
    
</body>
</html>
```

## Step 7: Run It!
On the terminal, paste this code:
```bash
python scanner.py
```

## Step 8: Open report (after generating)
open report.html in your file explorer folder


--

# App 2: Intruder Alert System with Email Notification

## Step 1: Set Up Environment
Create a project folder:
```bash
cd ..
mkdir app2
cd app2
```
Install dependencies:
```bash
pip install opencv-python cvlib numpy tensorflow email-validator
```
- Download Haar Cascade XML for Face Detection:
OpenCV provides pre-trained Haar Cascade classifiers for face detection, and they can be found in the OpenCV GitHub repository or your local OpenCV installation: https://github.com/opencv/opencv/blob/master/data/haarcascades/haarcascade_frontalface_default.xml

## Step 2: Email Sender 
Create a new file and name it **email_sender.py**
```python
import cv2
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime
import time

# Function to send an email with the image attachment
def send_email(image_path, to_email):
    sender_email = "valeriejaneuba.uba@cvsu.edu.ph"
    sender_pass = "appe zvdg calg uvkw"  # App password

    msg = EmailMessage()
    msg['Subject'] = '🔔 Person Detected!'
    msg['From'] = sender_email
    msg['To'] = to_email
    msg.set_content('Motion detected. See attached image.')

    with open(image_path, 'rb') as img:
        msg.add_attachment(img.read(), maintype='image', subtype='jpeg', filename='intruder.jpg')

    context = ssl.create_default_context()
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls(context=context)
        server.login(sender_email, sender_pass)
        server.send_message(msg)
        print("[+] Email sent.")

# Load the Haar Cascade classifier
face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')  # Ensure this file is in your directory

# Start video capture
cap = cv2.VideoCapture(0)

# Check if the webcam is opened correctly
if not cap.isOpened():
    print("[ERROR] Could not open video device")
    exit()

# Track time and captures
start_time = time.time()
capture_count = 0
max_captures = 2
duration_seconds = 10

while True:
    if time.time() - start_time > duration_seconds:
        print("[INFO] 10 seconds passed. Exiting...")
        break

    ret, frame = cap.read()
    if not ret:
        break

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    if len(faces) > 0 and capture_count < max_captures:
        for (x, y, w, h) in faces:
            cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)

        image_path = f"detected_face_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        cv2.imwrite(image_path, frame)
        print(f"[+] Face detected. Sending capture #{capture_count + 1}...")
        send_email(image_path, "valeriejane020703@gmail.com")
        capture_count += 1
        time.sleep(1)  # Optional: delay to avoid rapid multiple detections

    cv2.imshow('Face Detection', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        print("[INFO] Quitting manually.")
        break

# Clean up
cap.release()
cv2.destroyAllWindows()
```

## Step 3: Detection with Camera 
Create a new file and name it **main.py**
```python
import cv2
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime
import time
import os

# --- Email sending function ---
def send_email(image_path, to_email):
    sender_email = "valeriejaneuba.uba@cvsu.edu.ph"
    sender_pass = "appe zvdg calg uvkw"

    msg = EmailMessage()
    msg['Subject'] = '🔔 Person Detected!'
    msg['From'] = sender_email
    msg['To'] = to_email
    msg.set_content('Motion detected. See attached image.')

    with open(image_path, 'rb') as img:
        msg.add_attachment(img.read(), maintype='image', subtype='jpeg', filename='intruder.jpg')

    context = ssl.create_default_context()
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls(context=context)
        server.login(sender_email, sender_pass)
        server.send_message(msg)
        print("[+] Email sent.")

# --- Main detection logic ---
def main():
    face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("[ERROR] Could not open video device")
        return

    # Create folder for detected images if it doesn't exist
    output_dir = "image_detected"
    os.makedirs(output_dir, exist_ok=True)

    start_time = time.time()
    sent = 0
    MAX_CAPTURES = 2
    DURATION = 10  # seconds

    while time.time() - start_time < DURATION and sent < MAX_CAPTURES:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        if len(faces) > 0:
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 0), 2)

            image_filename = f"detected_face_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
            image_path = os.path.join(output_dir, image_filename)
            cv2.imwrite(image_path, frame)
            print(f"[+] Face detected. Sending capture #{sent + 1}...")
            send_email(image_path, "valeriejane020703@gmail.com")
            sent += 1
            time.sleep(1.5)  # Optional delay to avoid spamming

        cv2.imshow("Face Detection", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("[INFO] Quitting manually.")
            break

    print("[INFO] 10 seconds passed. Exiting...")
    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    main()
```

## Step 4: To run enter in your terminal
```bash
python main.py
```


--


# App 3:Real-Time Network Threat Visualizer with Audio Alerts

## Step 1: Set Up Environment
Create a project folder:
```bash
cd ..
mkdir app3
cd app3
```
Install dependencies:
```bash
pip install scapy matplotlib PyQt5 pyqtgraph pyaudio requests folium geopy
```

## Step 2: Configuration File
Create a **config.json** file with default settings like the network interface, alert thresholds, etc.
```bash
{
  "interface": "eth0",
  "alert_threshold": 5,
  "target_ip": "192.168.1.1"
}
```

## Step 3: Network Traffic Analysis and Threat Detection
Create a file called **threat_detector.py** to analyze network packets and detect suspicious behavior.
```python
import scapy.all as scapy
from visualizer import global_data
from audio_alert import play_alert

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        print(f"[+] Source IP: {src_ip}")
        global_data['packet_count'] += 1
        play_alert()  # 🔊 Play sound on every packet

def start_sniffing():
    print("[+] Starting packet sniffing...")
    scapy.sniff(prn=packet_callback, store=0, iface="Wi-Fi", timeout=15)
    print("[+] Packet sniffing stopped.")
```

## Step 4: Real-Time Visualization
Create **visualizer.py** to display live traffic statistics and threat activity in real-time.
```python
import pyqtgraph as pg
from PyQt5.QtWidgets import QWidget, QVBoxLayout
import sys
from collections import deque

# Global variable to store packet counts
global_data = {
    'packet_count': 0
}

class TrafficVisualizer(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Threat Visualizer")
        self.layout = QVBoxLayout(self)
        
        self.plot = pg.PlotWidget(self)
        self.layout.addWidget(self.plot)

        self.plot.setTitle("Network Traffic Over Time")
        self.plot.setLabel('left', 'Packet Count')
        self.plot.setLabel('bottom', 'Time (Seconds)')

        self.data = deque(maxlen=100)  # Store last 100 data points
        self.time = deque(maxlen=100)
        
        self.counter = 0  # Used for time

    def update_graph(self, new_data):
        self.counter += 1
        self.time.append(self.counter)  # Time increases by 1 for each update
        self.data.append(new_data)

        self.plot.plot(self.time, self.data, clear=True)  # Update the graph with new data
        self.plot.setYRange(0, max(self.data)+1)

def update_visualizer_data(window):
    global global_data
    window.update_graph(global_data['packet_count'])  # Pass packet count to the visualizer

# Function to start the visualization (already defined earlier)
def start_visualizing():
    app = QApplication(sys.argv)
    window = TrafficVisualizer()
    window.show()
    sys.exit(app.exec_())
```

## Step 5: Audio Alerts
Create a file **audio_alert.py** to trigger sound notifications when a potential threat is detected.
```python
import pyaudio
import wave

def play_alert():
    chunk = 1024
    file = "alert.wav"  # Ensure this file exists in the same directory

    try:
        wf = wave.open(file, 'rb')
    except FileNotFoundError:
        print(f"[!] Alert sound file not found: {file}")
        return

    p = pyaudio.PyAudio()

    stream = p.open(format=p.get_format_from_width(wf.getsampwidth()),
                    channels=wf.getnchannels(),
                    rate=wf.getframerate(),
                    output=True)

    data = wf.readframes(chunk)

    while data:
        stream.write(data)
        data = wf.readframes(chunk)

    stream.stop_stream()
    stream.close()
    p.terminate()
```

## Step 6: Main Script to Combine Everything
Create a main script **main.py** to tie everything together.
```python
import json
import time
from threading import Thread
from threat_detector import start_sniffing
from visualizer import TrafficVisualizer, update_visualizer_data
from audio_alert import play_alert
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer

def load_config():
    with open('config.json') as f:
        config = json.load(f)
    return config


def start_visualizing_in_main_thread():
    app = QApplication([])  # Create QApplication instance in the main thread
    window = TrafficVisualizer()
    window.show()
    
    # Update visualizer periodically using QTimer (or another mechanism)
    timer = QTimer()
    timer.timeout.connect(lambda: update_visualizer_data(window))
    timer.start(1000)  # Update every 1000ms (1 second)
    
    app.exec_()  # Start the event loop


def main():
    config = load_config()

    # Start network sniffing in a separate thread
    sniffing_thread = Thread(target=start_sniffing)
    sniffing_thread.start()

    # Start visualizing in the main thread
    start_visualizing_in_main_thread()

    # Run for 15 seconds
    time.sleep(15)

    # Stop sniffing after 15 seconds
    print("[+] Stopping packet sniffing...")
    sniffing_thread.join()  # Ensure the sniffing thread finishes

    print("[+] Network threat visualizer has stopped.")


if __name__ == "__main__":
    main()
```

## Step 7: Run the Project
You can now run the project by executing the main.py script.
```bash
python main.py
```






























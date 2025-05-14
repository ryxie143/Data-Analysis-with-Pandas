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

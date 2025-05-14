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

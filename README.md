## Extending Tool Capabilities with Python Libraries and Frameworks Using Pandas

### 1. Create a Project Folder
First, open your terminal or command prompt and run the following command to create the project folder:
```bash
mkdir Pandas_SecurityAutomation
```
Then, navigate into the project directory:
```bash
cd Pandas_SecurityAutomation
```

### 2. Create a Data Folder
Create a folder named data to store your CSV file:
```bash
mkdir data
```
Then, navigate into the data folder:
```bash
cd data
```

### 3. Create the security_incidents.csv file inside the data folder.
Still inside the data folder, run the following command in your terminal to create the CSV file:
```bash
@"
Timestamp,Category,Severity,SourceIP,DestinationIP,Duration
2025-05-12 14:23:11,Firewall,High,192.168.1.10,10.0.0.5,120
2025-05-12 15:01:34,IDS,Medium,192.168.1.22,10.0.0.8,45
2025-05-12 15:45:09,Authentication,High,192.168.1.35,10.0.0.15,180
2025-05-12 16:05:56,Firewall,Low,192.168.1.44,10.0.0.20,30
2025-05-12 17:15:10,IDS,High,192.168.1.11,10.0.0.25,95
"@ | Out-File -Encoding utf8 .\data\security_incidents.csv
```

### 4. Return to the Main Directory and Create the Python File
Go back to the main project directory:
```bash
cd ..
```
Now, create the Python script file analyze_security.py:
```bash
New-Item analyze_security.py -ItemType File
```
Next, open the analyze_security.py file and paste the following Python code inside it:
```python
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the CSV file into a DataFrame
df = pd.read_csv('data/security_incidents.csv')

# Visualization: Incident Count by Severity
plt.figure(figsize=(8, 6))
sns.countplot(data=df, x='Severity', palette='viridis')
plt.title("Incident Count by Severity")
plt.show()

# Real-time Alerts: Send an email if there's a High Severity incident
if 'High' in df['Severity'].values:
    print("High Severity Incident Detected!")
    # Code for sending email alert would go here (e.g., using smtplib)
```

### 5. Install virtual environment 
Create a virtual environment for your project:
```bash
python -m venv venv
```
Activate the Virtual Environment:
```bash
venv\Scripts\Activate
```

### 6. Install pandas in the Virtual Environment
Install the pandas library within your virtual environment:
```bash
pip install pandas matplotlib seaborn
```

### 7. Run the Python Script
Now, run your Python script to analyze the data:
```bash
python analyze_security.py
```

### 8. Deactivate the Virtual Environment (when done)
Once you're done working, deactivate the virtual environment:
```bash
deactivate
```

import pandas as pd

# Load the CSV file into a DataFrame
df = pd.read_csv('data/security_incidents.csv')

# Analyze total number of incidents by severity
incident_count_by_severity = df['Severity'].value_counts()

# Filter incidents with High severity
high_severity_incidents = df[df['Severity'] == 'High']

# Summary statistics by Category
incident_summary_by_category = df.groupby('Category').agg({
    'Severity': 'count',
    'Duration': 'mean'
})

# Print results
print("Incident Count by Severity:")
print(incident_count_by_severity)

print("\nHigh Severity Incidents:")
print(high_severity_incidents)

print("\nIncident Summary by Category:")
print(incident_summary_by_category)
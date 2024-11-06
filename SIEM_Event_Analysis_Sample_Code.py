import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from sklearn.preprocessing import LabelEncoder
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt

class SIEMAnalyzer:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        
    def parse_log_entry(self, log_line):
        """Parse a raw log entry into structured format"""
        try:
            return json.loads(log_line)
        except:
            # Basic parsing for common log formats
            parts = log_line.split('|')
            return {
                'timestamp': parts[0],
                'source_ip': parts[1],
                'event_type': parts[2],
                'severity': parts[3],
                'message': parts[4]
            }
    
    def load_logs(self, log_file):
        """Load and structure log data"""
        logs = []
        with open(log_file, 'r') as f:
            for line in f:
                logs.append(self.parse_log_entry(line))
        return pd.DataFrame(logs)
    
    def enrich_events(self, df):
        """Enrich events with additional context"""
        # Add timestamp-based features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Encode categorical variables
        df['event_type_encoded'] = self.label_encoder.fit_transform(df['event_type'])
        
        # Calculate time differences between events
        df['time_delta'] = df['timestamp'].diff().dt.total_seconds()
        
        return df
    
    def detect_anomalies(self, df, eps=300, min_samples=5):
        """Detect anomalous events using DBSCAN clustering"""
        # Prepare features for clustering
        features = df[['hour', 'event_type_encoded', 'time_delta']].fillna(0)
        
        # Normalize features
        features = (features - features.mean()) / features.std()
        
        # Perform clustering
        clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(features)
        
        # Add cluster labels to dataframe
        df['anomaly'] = clustering.labels_ == -1
        
        return df
    
    def analyze_security_events(self, df):
        """Perform security analysis on events"""
        analysis = {
            'total_events': len(df),
            'unique_sources': df['source_ip'].nunique(),
            'severity_distribution': df['severity'].value_counts(),
            'anomalous_events': df['anomaly'].sum(),
            'top_event_types': df['event_type'].value_counts().head(10),
            'events_by_hour': df.groupby('hour')['event_type'].count()
        }
        
        # Identify potential attack patterns
        potential_attacks = df[
            (df['anomaly'] == True) & 
            (df['time_delta'] < 60)  # Events occurring within 60 seconds
        ]
        
        analysis['potential_attacks'] = len(potential_attacks)
        
        return analysis
    
    def generate_alerts(self, df, threshold_config):
        """Generate alerts based on defined thresholds"""
        alerts = []
        
        # Check for rapid succession events
        rapid_events = df[df['time_delta'] < threshold_config['rapid_event_threshold']]
        if len(rapid_events) > threshold_config['rapid_event_count']:
            alerts.append({
                'type': 'Rapid Event Succession',
                'severity': 'High',
                'events': len(rapid_events)
            })
        
        # Check for authentication failures
        auth_failures = df[
            (df['event_type'] == 'authentication_failure') & 
            (df['timestamp'] > datetime.now() - timedelta(hours=1))
        ]
        if len(auth_failures) > threshold_config['auth_failure_threshold']:
            alerts.append({
                'type': 'Authentication Failure Surge',
                'severity': 'High',
                'source_ips': auth_failures['source_ip'].unique()
            })
            
        return alerts
    
    def visualize_events(self, df):
        """Create visualizations for event analysis"""
        # Event distribution over time
        plt.figure(figsize=(12, 6))
        df['timestamp'].hist(bins=50)
        plt.title('Event Distribution Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Events')
        
        # Severity distribution
        plt.figure(figsize=(8, 6))
        df['severity'].value_counts().plot(kind='bar')
        plt.title('Event Severity Distribution')
        plt.xlabel('Severity Level')
        plt.ylabel('Count')
        
        plt.tight_layout()
        return plt

# Example usage
def analyze_sample_logs():
    analyzer = SIEMAnalyzer()
    
    # Create sample log data
    sample_logs = [
        {
            'timestamp': '2024-01-01 10:00:00',
            'source_ip': '192.168.1.100',
            'event_type': 'authentication_failure',
            'severity': 'high',
            'message': 'Failed login attempt'
        },
        # Add more sample logs as needed
    ]
    
    # Convert to DataFrame
    df = pd.DataFrame(sample_logs)
    
    # Perform analysis
    df = analyzer.enrich_events(df)
    df = analyzer.detect_anomalies(df)
    
    # Generate analysis results
    analysis = analyzer.analyze_security_events(df)
    
    # Configure and generate alerts
    threshold_config = {
        'rapid_event_threshold': 5,  # seconds
        'rapid_event_count': 10,
        'auth_failure_threshold': 5
    }
    alerts = analyzer.generate_alerts(df, threshold_config)
    
    return analysis, alerts

if __name__ == "__main__":
    analysis, alerts = analyze_sample_logs()

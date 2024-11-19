```python
#!/usr/bin/python3
"""
Security Log Analyzer
Author: Timin Thaver
Purpose: Analyzes security logs for suspicious activities like failed logins and suspicious IPs
Usage: python3 log_analyzer.py <path_to_log_file>
"""

import sys
import re
from collections import Counter
import datetime

class SecurityLogAnalyzer:
    def __init__(self, log_file):
        """Initialize with path to log file"""
        self.log_file = log_file
        self.failed_attempts = []
        self.ip_addresses = []
        self.suspicious_ips = []
        
    def analyze_failed_logins(self):
        """Analyze failed login attempts and identify potential brute force attacks"""
        pattern = r'Failed password for .* from ((?:\d{1,3}\.){3}\d{1,3})'
        
        with open(self.log_file, 'r') as file:
            for line in file:
                if 'Failed password' in line:
                    match = re.search(pattern, line)
                    if match:
                        self.failed_attempts.append({
                            'ip': match.group(1),
                            'timestamp': self._extract_timestamp(line)
                        })
                        self.ip_addresses.append(match.group(1))
                        
    def identify_suspicious_ips(self, threshold=5):
        """Identify IPs with login attempts above threshold"""
        ip_counts = Counter(self.ip_addresses)
        self.suspicious_ips = {ip: count for ip, count in ip_counts.items() 
                             if count >= threshold}
    
    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        timestamp_pattern = r'\b\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\b'
        match = re.search(timestamp_pattern, line)
        return match.group(0) if match else None
    
    def generate_report(self):
        """Generate security analysis report"""
        report = "\nSecurity Log Analysis Report\n"
        report += "=" * 30 + "\n"
        report += f"Total Failed Login Attempts: {len(self.failed_attempts)}\n"
        report += f"Unique IPs: {len(set(self.ip_addresses))}\n\n"
        
        report += "Suspicious IPs (>5 attempts):\n"
        for ip, count in self.suspicious_ips.items():
            report += f"IP: {ip} - Attempts: {count}\n"
            
        return report

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 log_analyzer.py <path_to_log_file>")
        sys.exit(1)
        
    analyzer = SecurityLogAnalyzer(sys.argv[1])
    analyzer.analyze_failed_logins()
    analyzer.identify_suspicious_ips()
    print(analyzer.generate_report())

if __name__ == "__main__":
    main()
```

import sqlite3
import json
import time
from datetime import datetime, timedelta
import statistics
import os

class SecurityEventAnalyzer:
    """
    Security Event Analyzer class for detecting anomalies and attack patterns in security events.
    Performs statistical analysis and pattern matching to identify potential security issues.
    """
    def __init__(self, db_path="security_events.db", output_path="analysis_results.json"):
        """
        Initialize the security event analyzer.
        
        Features:
        - Connects to the security events database
        - Loads known attack patterns for matching
        - Sets up output path for analysis results
        
        Args:
            db_path: Path to the SQLite database containing security events
            output_path: Path where analysis results will be saved as JSON
        """
        self.db_path = db_path
        self.output_path = output_path
        self.known_patterns = self._load_known_patterns()
        
    def _load_known_patterns(self):
        """
        Load known attack patterns from a predefined list.
        
        Features:
        - Defines signature-based patterns for common attack types
        - Specifies conditions for pattern matching
        - Assigns severity levels to different attack patterns
        
        Returns:
            List of dictionaries representing attack patterns with matching rules
        """
        # In a real system, these could be loaded from a file or external database
        return [
            {
                "name": "Brute Force Login",
                "pattern": {
                    "event_type": "login_attempt",
                    "conditions": {
                        "min_count": 5,
                        "time_window": 300,  # seconds
                        "success": False
                    }
                },
                "severity": 3
            },
            {
                "name": "Sensitive File Access",
                "pattern": {
                    "event_type": "file_access",
                    "conditions": {
                        "paths": ["/etc/passwd", "/etc/shadow", "/opt/sensitive_data"],
                        "operations": ["read", "write", "delete"]
                    }
                },
                "severity": 4
            },
            {
                "name": "Suspicious Network Connection",
                "pattern": {
                    "event_type": "network_connection",
                    "conditions": {
                        "ports": [4444, 9999, 8888],
                        "direction": "outbound"
                    }
                },
                "severity": 3
            },
            {
                "name": "Privilege Escalation",
                "pattern": {
                    "event_type": "privilege_escalation",
                    "conditions": {
                        "target": "root"
                    }
                },
                "severity": 5
            },
            {
                "name": "Suspicious Process",
                "pattern": {
                    "event_type": "process_creation",
                    "conditions": {
                        "processes": ["nc", "netcat", "wireshark", "nmap"],
                        "users": ["www-data", "guest"]
                    }
                },
                "severity": 3
            }
        ]
    
    def detect_anomalies(self, time_window=300, threshold_factor=2.0):
        """
        Detect anomalies by identifying event frequencies that exceed typical patterns.
        
        Features:
        - Compares current event rates against historical averages
        - Uses standard deviation to identify statistical outliers
        - Calculates appropriate severity levels based on deviation
        - Records anomalies in the analysis_results table
        
        Args:
            time_window: Time window in seconds to analyze
            threshold_factor: Multiplier for standard deviation to determine threshold
            
        Returns:
            List of detected anomalies with details
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Calculate the time window
        time_limit = (datetime.now() - timedelta(seconds=time_window)).isoformat()
        
        # Get event counts by type within time window
        cursor.execute('''
        SELECT event_type, COUNT(*) as count
        FROM security_events
        WHERE timestamp > ?
        GROUP BY event_type
        ''', (time_limit,))
        
        current_counts = {event_type: count for event_type, count in cursor.fetchall()}
        
        # Get historical averages and standard deviations
        anomalies = []
        for event_type, current_count in current_counts.items():
            # Get historical data for this event type
            cursor.execute('''
            SELECT COUNT(*) as count
            FROM security_events
            WHERE event_type = ?
            GROUP BY strftime('%Y-%m-%d %H', timestamp)
            ''', (event_type,))
            
            historical_counts = [count for count, in cursor.fetchall()]
            
            if len(historical_counts) < 2:
                continue  # Not enough historical data
                
            avg_count = statistics.mean(historical_counts)
            try:
                std_dev = statistics.stdev(historical_counts)
            except statistics.StatisticsError:
                std_dev = 1  # Default if not enough data points
                
            threshold = avg_count + (threshold_factor * std_dev)
            
            if current_count > threshold:
                anomaly = {
                    "timestamp": datetime.now().isoformat(),
                    "analysis_type": "anomaly_detection",
                    "event_type": event_type,
                    "current_count": current_count,
                    "average_count": avg_count,
                    "threshold": threshold,
                    "severity": self._calculate_anomaly_severity(current_count, threshold)
                }
                
                anomalies.append(anomaly)
                
                # Log the anomaly to the analysis_results table
                cursor.execute('''
                INSERT INTO analysis_results
                (timestamp, event_id, analysis_type, result, severity)
                VALUES (?, NULL, ?, ?, ?)
                ''', (
                    anomaly["timestamp"],
                    "anomaly_detection",
                    json.dumps(anomaly),
                    anomaly["severity"]
                ))
        
        conn.commit()
        conn.close()
        return anomalies
    
    def _calculate_anomaly_severity(self, current_count, threshold):
        """
        Calculate severity of an anomaly based on how much it exceeds the threshold.
        
        Features:
        - Assigns severity level based on the ratio of current count to threshold
        - Higher deviations result in higher severity scores
        - Uses a scale from 2 (low) to 5 (critical)
        
        Args:
            current_count: Current event count in the time window
            threshold: Calculated threshold for normal activity
            
        Returns:
            Integer severity score from 2-5
        """
        ratio = current_count / threshold
        
        if ratio > 5:
            return 5  # Critical
        elif ratio > 3:
            return 4  # High
        elif ratio > 2:
            return 3  # Medium
        else:
            return 2  # Low
    
    def match_patterns(self):
        """
        Match recent events against known attack patterns.
        
        Features:
        - Compares events against predefined attack signatures
        - Handles different types of pattern matching (frequency, property-based)
        - Records matched patterns in the analysis_results table
        - Assigns appropriate severity levels to matches
        
        Returns:
            List of matched patterns with details
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        matched_patterns = []
        
        for pattern in self.known_patterns:
            event_type = pattern["pattern"]["event_type"]
            conditions = pattern["pattern"]["conditions"]
            
            if "min_count" in conditions and "time_window" in conditions:
                # Pattern based on frequency in a time window
                time_limit = (datetime.now() - timedelta(seconds=conditions["time_window"])).isoformat()
                
                query = f'''
                SELECT COUNT(*) as count
                FROM security_events
                WHERE event_type = ? AND timestamp > ?
                '''
                params = [event_type, time_limit]
                
                # Add additional filters based on raw_data field
                if event_type == "login_attempt" and "success" in conditions:
                    query += f" AND raw_data LIKE ?"
                    params.append(f"%success={str(conditions['success']).lower()}%")
                
                cursor.execute(query, params)
                
                count = cursor.fetchone()["count"]
                
                if count >= conditions["min_count"]:
                    match = {
                        "timestamp": datetime.now().isoformat(),
                        "analysis_type": "pattern_matching",
                        "pattern_name": pattern["name"],
                        "event_count": count,
                        "severity": pattern["severity"]
                    }
                    matched_patterns.append(match)
                    
                    # Log the pattern match to the analysis_results table
                    cursor.execute('''
                    INSERT INTO analysis_results
                    (timestamp, event_id, analysis_type, result, severity)
                    VALUES (?, NULL, ?, ?, ?)
                    ''', (
                        match["timestamp"],
                        "pattern_matching",
                        json.dumps(match),
                        match["severity"]
                    ))
            
            else:
                # Pattern based on specific event properties
                time_limit = (datetime.now() - timedelta(minutes=5)).isoformat()
                
                query = f'''
                SELECT id, timestamp, event_type, description, source, raw_data
                FROM security_events
                WHERE event_type = ? AND timestamp > ?
                '''
                params = [event_type, time_limit]
                
                cursor.execute(query, params)
                events = cursor.fetchall()
                
                for event in events:
                    matched = True
                    
                    # Check specific conditions based on event type
                    if event_type == "file_access" and "paths" in conditions:
                        raw_data = event["raw_data"]
                        if not any(f"path={path}" in raw_data for path in conditions["paths"]):
                            matched = False
                            
                        if "operations" in conditions and matched:
                            if not any(f"operation={op}" in raw_data for op in conditions["operations"]):
                                matched = False
                    
                    elif event_type == "network_connection" and "ports" in conditions:
                        raw_data = event["raw_data"]
                        if not any(f"port={port}" in raw_data for port in conditions["ports"]):
                            matched = False
                            
                        if "direction" in conditions and matched:
                            if f"direction={conditions['direction']}" not in raw_data:
                                matched = False
                    
                    elif event_type == "privilege_escalation" and "target" in conditions:
                        raw_data = event["raw_data"]
                        if f"target={conditions['target']}" not in raw_data:
                            matched = False
                            
                    elif event_type == "process_creation":
                        raw_data = event["raw_data"]
                        
                        if "processes" in conditions:
                            if not any(f"process={proc}" in raw_data for proc in conditions["processes"]):
                                matched = False
                                
                        if "users" in conditions and matched:
                            if not any(f"user={user}" in raw_data for user in conditions["users"]):
                                matched = False
                    
                    if matched:
                        match = {
                            "timestamp": datetime.now().isoformat(),
                            "analysis_type": "pattern_matching",
                            "pattern_name": pattern["name"],
                            "event_id": event["id"],
                            "event_timestamp": event["timestamp"],
                            "severity": pattern["severity"]
                        }
                        matched_patterns.append(match)
                        
                        # Log the pattern match to the analysis_results table
                        cursor.execute('''
                        INSERT INTO analysis_results
                        (timestamp, event_id, analysis_type, result, severity)
                        VALUES (?, ?, ?, ?, ?)
                        ''', (
                            match["timestamp"],
                            event["id"],
                            "pattern_matching",
                            json.dumps(match),
                            match["severity"]
                        ))
        
        conn.commit()
        conn.close()
        return matched_patterns
    
    def update_event_severity(self):
        """
        Update event severity based on analysis results.
        
        Features:
        - Increases severity of events involved in detected patterns
        - Ensures events reflect their security significance
        - Uses the highest severity level when multiple analyses affect an event
        
        Returns:
            Number of events with updated severity
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get events with analysis results
        cursor.execute('''
        SELECT DISTINCT event_id, MAX(severity) as max_severity
        FROM analysis_results
        WHERE event_id IS NOT NULL
        GROUP BY event_id
        ''')
        
        updates = 0
        for row in cursor.fetchall():
            event_id = row["event_id"]
            max_severity = row["max_severity"]
            
            # Update the event severity if the analysis severity is higher
            cursor.execute('''
            UPDATE security_events
            SET severity = MAX(severity, ?)
            WHERE id = ?
            ''', (max_severity, event_id))
            
            if cursor.rowcount > 0:
                updates += 1
        
        conn.commit()
        conn.close()
        return updates
    
    def save_results_to_file(self):
        """
        Save analysis results to a JSON file for persistence and external analysis.
        
        Features:
        - Exports all analysis results to a structured JSON file
        - Preserves historical analysis data for trend analysis
        - Supports external tools and reporting systems
        - Creates the output directory if it doesn't exist
        
        Returns:
            Boolean indicating success or failure
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all analysis results
        cursor.execute('''
        SELECT * FROM analysis_results
        ORDER BY timestamp DESC
        ''')
        
        results = []
        for row in cursor.fetchall():
            result = {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "event_id": row["event_id"],
                "analysis_type": row["analysis_type"],
                "severity": row["severity"]
            }
            
            # Parse the result JSON if possible
            try:
                result["result"] = json.loads(row["result"])
            except:
                result["result"] = row["result"]
                
            results.append(result)
            
        conn.close()
        
        # Ensure the directory exists
        output_dir = os.path.dirname(self.output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Write to file
        try:
            with open(self.output_path, 'w') as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "count": len(results),
                    "results": results
                }, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving results to file: {str(e)}")
            return False
    
    def run_analysis(self):
        """
        Run the complete security analysis process.
        
        Features:
        - Performs anomaly detection on event frequencies
        - Matches events against known attack patterns
        - Updates event severity levels based on findings
        - Saves analysis results to a JSON file
        - Returns comprehensive analysis results
        
        Returns:
            Dictionary containing anomalies and pattern matches
        """
        # Detect anomalies
        anomalies = self.detect_anomalies()
        
        # Match patterns
        pattern_matches = self.match_patterns()
        
        # Update event severities
        updated_count = self.update_event_severity()
        
        # Save results to file
        self.save_results_to_file()
        
        # Return the results
        return {
            "anomalies": anomalies,
            "pattern_matches": pattern_matches,
            "updated_events": updated_count
        }

if __name__ == "__main__":
    # Basic test
    analyzer = SecurityEventAnalyzer()
    results = analyzer.run_analysis()
    print(f"Found {len(results['anomalies'])} anomalies and {len(results['pattern_matches'])} pattern matches") 
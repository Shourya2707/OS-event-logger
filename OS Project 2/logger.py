import sqlite3
import time
import random
import os
import yaml
from datetime import datetime

class SecurityEventLogger:
    """
    Security Event Logger class for capturing, storing, and retrieving OS-level security events.
    Handles database operations and event simulation for testing purposes.
    """
    def __init__(self, db_path="security_events.db", config_path="config.yaml"):
        """
        Initialize the security event logger with database connection and configuration.
        
        Features:
        - Loads event type configuration from YAML file
        - Sets up the SQLite database for storing events
        - Establishes database tables and schema
        
        Args:
            db_path: Path to the SQLite database file
            config_path: Path to the YAML configuration file
        """
        self.db_path = db_path
        self.config_path = config_path
        self.event_types = self._load_config()
        self.setup_database()
        
    def _load_config(self):
        """
        Load event types from configuration file.
        
        Features:
        - Reads the YAML configuration file
        - Extracts enabled event types
        - Provides default configuration if file not found
        
        Returns:
            Dictionary of event types with boolean values indicating if they are enabled
        """
        if not os.path.exists(self.config_path):
            # Default config if file doesn't exist
            return {
                "login_attempt": True,
                "file_access": True,
                "process_creation": True,
                "network_connection": True,
                "privilege_escalation": True
            }
        
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('monitored_events', {})
    
    def setup_database(self):
        """
        Set up the SQLite database for storing security events.
        
        Features:
        - Creates security_events table if it doesn't exist
        - Creates analysis_results table if it doesn't exist
        - Establishes schema with appropriate fields and relationships
        - Sets up foreign key constraints
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create events table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            description TEXT,
            source TEXT,
            severity INTEGER DEFAULT 0,
            raw_data TEXT
        )
        ''')
        
        # Create analysis_results table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id INTEGER,
            analysis_type TEXT,
            result TEXT,
            severity INTEGER,
            FOREIGN KEY (event_id) REFERENCES security_events (id)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_event(self, event_type, description, source, raw_data=None, severity=0):
        """
        Log a security event to the database.
        
        Features:
        - Validates that the event type is enabled in configuration
        - Stores event with timestamp, type, description, source, and severity
        - Records additional raw data for detailed analysis
        - Returns the ID of the newly created event
        
        Args:
            event_type: Type of security event (must be in configured event_types)
            description: Human-readable description of the event
            source: Source of the event (process, user, system component)
            raw_data: Additional structured data about the event
            severity: Initial severity rating (0-5)
            
        Returns:
            Integer ID of the newly created event or False if event type is disabled
        """
        if event_type not in self.event_types or not self.event_types[event_type]:
            return False
        
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO security_events 
        (timestamp, event_type, description, source, severity, raw_data)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, event_type, description, source, severity, raw_data))
        
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return event_id
    
    def get_recent_events(self, limit=100):
        """
        Retrieve the most recent security events.
        
        Features:
        - Fetches events ordered by ID (most recent first)
        - Limits number of results to prevent memory issues
        - Returns all event details for display and analysis
        
        Args:
            limit: Maximum number of events to retrieve
            
        Returns:
            List of event tuples containing all event fields
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id, timestamp, event_type, description, source, severity
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
        ''', (limit,))
        
        events = cursor.fetchall()
        conn.close()
        
        return events
    
    def get_events_by_type(self, event_type, limit=100):
        """
        Retrieve events of a specific type.
        
        Features:
        - Filters events by specified event type
        - Orders results by ID (most recent first)
        - Limits number of results to prevent memory issues
        
        Args:
            event_type: Type of events to retrieve
            limit: Maximum number of events to retrieve
            
        Returns:
            List of event tuples containing all event fields
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id, timestamp, event_type, description, source, severity
        FROM security_events
        WHERE event_type = ?
        ORDER BY id DESC
        LIMIT ?
        ''', (event_type, limit))
        
        events = cursor.fetchall()
        conn.close()
        
        return events

    def simulate_events(self, num_events=10, interval=0.5):
        """
        Simulate security events for demonstration purposes.
        
        Features:
        - Generates realistic security events of various types
        - Randomizes event parameters and severity levels
        - Creates events with appropriate relationships between fields
        - Simulates both normal and suspicious activities
        
        Args:
            num_events: Number of events to simulate
            interval: Time interval between events in seconds
            
        Returns:
            List of IDs of the newly created events
        """
        event_types = list(filter(lambda x: self.event_types.get(x, False), self.event_types.keys()))
        if not event_types:
            return []
        
        event_ids = []
        for _ in range(num_events):
            event_type = random.choice(event_types)
            
            # Generate realistic details based on event type
            if event_type == "login_attempt":
                users = ["admin", "user", "root", "guest", "system"]
                ips = [f"192.168.1.{random.randint(1, 255)}", "10.0.0.1", "127.0.0.1"]
                user = random.choice(users)
                ip = random.choice(ips)
                success = random.choice([True, False])
                
                description = f"{'Successful' if success else 'Failed'} login attempt for user '{user}'"
                source = ip
                severity = 1 if success else random.choice([2, 3])
                raw_data = f"user={user} ip={ip} success={success}"
                
            elif event_type == "file_access":
                paths = ["/etc/passwd", "/var/log/syslog", "/home/user/documents", "/opt/sensitive_data"]
                users = ["admin", "user1", "system", "www-data"]
                operations = ["read", "write", "delete", "chmod"]
                
                path = random.choice(paths)
                user = random.choice(users)
                operation = random.choice(operations)
                
                description = f"File {operation} on {path} by {user}"
                source = f"process_{random.randint(1000, 9999)}"
                severity = 2 if path.startswith("/etc") or "sensitive" in path else 1
                raw_data = f"path={path} user={user} operation={operation}"
                
            elif event_type == "process_creation":
                processes = ["bash", "python", "systemctl", "nc", "wget", "curl"]
                users = ["root", "user", "www-data"]
                
                process = random.choice(processes)
                user = random.choice(users)
                pid = random.randint(1000, 50000)
                
                description = f"Process '{process}' started by {user} with PID {pid}"
                source = f"kernel"
                severity = 3 if process in ["nc"] and user == "www-data" else 1
                raw_data = f"process={process} user={user} pid={pid}"
                
            elif event_type == "network_connection":
                ports = [22, 80, 443, 8080, 3306, 4444, 9999]
                directions = ["inbound", "outbound"]
                
                port = random.choice(ports)
                direction = random.choice(directions)
                ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                
                description = f"{direction.capitalize()} connection on port {port} from {ip}"
                source = "firewall"
                severity = 3 if port in [4444, 9999] else 1
                raw_data = f"port={port} direction={direction} ip={ip}"
                
            elif event_type == "privilege_escalation":
                methods = ["sudo", "su", "setuid", "buffer overflow"]
                users = ["user", "www-data", "guest"]
                targets = ["root", "admin", "system"]
                
                method = random.choice(methods)
                user = random.choice(users)
                target = random.choice(targets)
                
                description = f"Privilege escalation attempt from {user} to {target} using {method}"
                source = "kernel_audit"
                severity = 4
                raw_data = f"method={method} user={user} target={target}"
                
            else:
                description = f"Generic {event_type} event"
                source = "system"
                severity = 1
                raw_data = None
            
            event_id = self.log_event(
                event_type=event_type,
                description=description,
                source=source,
                raw_data=raw_data,
                severity=severity
            )
            event_ids.append(event_id)
            time.sleep(interval)
            
        return event_ids

if __name__ == "__main__":
    # Basic test
    logger = SecurityEventLogger()
    logger.simulate_events(20, 0.1)
    print("Recent events:", logger.get_recent_events(5)) 
# Real-Time OS Security Event Logger

A comprehensive system that captures OS-level security events, analyzes them for anomalies and patterns, and presents results through a graphical user interface. This tool helps system administrators monitor, detect, and respond to potential security threats.

## Features

- **Event Logging:** 
  - Captures various security events including login attempts, file access, process creation, network connections, and privilege escalation
  - Stores all events in a SQLite database with timestamps and severity ratings
  - Real-time monitoring of system events
  
- **Event Analysis:** 
  - Detects anomalies based on statistical analysis of event frequencies
  - Identifies known attack patterns from predefined signatures
  - Assigns severity scores to events based on threat level
  - Updates event severity based on analysis results
  
- **Visualization:** 
  - Displays real-time event logs with filtering capabilities
  - Shows charts of event frequency by type and over time
  - Color-coded severity indicators for quick threat assessment
  - Detailed event inspection for forensic analysis
  
- **Persistence:** 
  - Logs analysis results to JSON for auditing and historical review
  - Configurable database management with backup options
  - Maintains comprehensive event history for trend analysis

## Use Cases

- **Security Monitoring:** Continuous monitoring of system activities to detect suspicious behavior
- **Threat Detection:** Identification of potential security threats through pattern matching and anomaly detection
- **Forensic Analysis:** Historical data review for security incident investigation
- **Compliance:** Event logging for regulatory compliance requirements
- **System Administration:** Monitoring of system health and user activities

## Installation

1. Clone the repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the main interface:

```bash
python interface.py
```

### User Interface

The application consists of the following main components:

1. **Control Panel**
   - Start/Stop Simulation: Toggle event simulation
   - Run Analysis: Analyze events for anomalies and patterns
   - Refresh: Manually refresh the data display
   - Clear DB: Clear all events from the database
   - Event Type filter: Filter events by type
   - Auto-refresh toggle: Enable/disable automatic data refresh

2. **Event Logs Tab**
   - Displays a list of security events with details
   - Double-click an event to view full details
   - Color-coded by severity for quick identification

3. **Analysis Results Tab**
   - Shows the results of security analysis
   - Highlights potential security issues and their severity
   - Provides insights into detected anomalies and attack patterns

4. **Event Charts Tab**
   - Bar chart of event counts by type
   - Line chart showing event frequency over time
   - Visual representation of security event trends

## Components

### interface.py
Main GUI application that provides the user interface for monitoring and analyzing security events.

#### Key Functions:
- `__init__`: Initializes the GUI and connects to the logger and analyzer
- `_create_control_panel`: Creates the control panel with buttons and filters
- `_create_notebook`: Creates tabs for logs, charts, and analysis
- `_create_logs_tab`: Displays event logs in a treeview
- `_create_analysis_tab`: Shows analysis results
- `_create_charts_tab`: Displays event visualization charts
- `_toggle_simulation`: Starts/stops the event simulation
- `_run_analysis`: Triggers the security analysis
- `_refresh_data`: Updates displayed data
- `_update_charts`: Renders event charts
- `_show_event_details`: Displays detailed information about a selected event

### logger.py
Handles event monitoring, logging, and simulation for demonstration purposes.

#### Key Functions:
- `__init__`: Initializes the logger and database connection
- `setup_database`: Creates required database tables
- `log_event`: Records a security event in the database
- `get_recent_events`: Retrieves the most recent events
- `get_events_by_type`: Retrieves events filtered by type
- `simulate_events`: Generates simulated security events for testing and demonstration

### analyzer.py
Implements security analysis algorithms for anomaly detection and pattern matching.

#### Key Functions:
- `__init__`: Initializes the analyzer with database connection
- `_load_known_patterns`: Loads predefined attack signature patterns
- `detect_anomalies`: Identifies statistical anomalies in event frequencies
- `match_patterns`: Matches events against known attack patterns
- `update_event_severity`: Updates event severity based on analysis
- `save_results_to_file`: Persists analysis results to JSON
- `run_analysis`: Main function that performs all analysis steps

### config.yaml
Configuration file that controls various aspects of the application.

#### Key Sections:
- `monitored_events`: Configures which event types to monitor
- `database`: Database settings and management options
- `analysis`: Parameters for anomaly detection and pattern matching
- `simulation`: Settings for the event simulation feature
- `gui`: User interface configuration options
- `logging`: Log file management settings

## Database Schema

### security_events
- `id`: Unique identifier for each event
- `timestamp`: When the event occurred
- `event_type`: Type of security event
- `description`: Human-readable description
- `source`: Source of the event
- `severity`: Numerical severity rating (0-5)
- `raw_data`: Additional event details in string format

### analysis_results
- `id`: Unique identifier for each analysis result
- `timestamp`: When the analysis was performed
- `event_id`: Reference to the related event (if applicable)
- `analysis_type`: Type of analysis performed
- `result`: Analysis results in JSON format
- `severity`: Numerical severity rating (0-5)

## Extending the System

For real OS monitoring (instead of simulation):

1. Implement platform-specific event capturing in `logger.py`
2. Add additional event types in `config.yaml`
3. Extend analysis patterns in `analyzer.py`
4. Add additional visualization options in `interface.py`

### Adding New Event Types
1. Update the `monitored_events` section in `config.yaml`
2. Add event-specific simulation logic in `simulate_events` method
3. Create pattern matching rules in `_load_known_patterns` method

## Requirements

- Python 3.6+
- matplotlib (>=3.5.0): For data visualization
- pyyaml (>=6.0): For configuration file parsing
- sqlite3 (>=2.6.0): For database management

## License

[MIT License](LICENSE) 
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading
import time
import sqlite3
from datetime import datetime, timedelta
import json
import os

from logger import SecurityEventLogger
from analyzer import SecurityEventAnalyzer

class SecurityEventLoggerGUI:
    """
    Main GUI class for the Real-Time OS Security Event Logger application.
    Provides interface for monitoring, visualizing, and analyzing security events.
    """
    def __init__(self, root):
        """
        Initialize the GUI and establish connections to the logger and analyzer.
        
        Features:
        - Sets up the main window and components
        - Initializes the logger and analyzer objects
        - Creates the GUI layout with control panel, notebook, and status bar
        - Starts the auto-refresh thread for real-time updates
        
        Args:
            root: The tkinter root window
        """
        self.root = root
        self.root.title("Real-Time OS Security Event Logger")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Initialize logger and analyzer
        self.logger = SecurityEventLogger()
        self.analyzer = SecurityEventAnalyzer()
        
        # Set up variables
        self.simulation_running = False
        self.analysis_running = False
        self.event_types = self.logger.event_types
        self.selected_event_type = tk.StringVar(value="All")
        self.severity_colors = {
            0: "#80c080",  # Light green
            1: "#a0e860",  # Green
            2: "#ffff80",  # Yellow
            3: "#ffc000",  # Orange
            4: "#ff8080",  # Red
            5: "#ff0000",  # Bright red
        }
        
        # Create the main sections
        self._create_control_panel()
        self._create_notebook()
        self._create_status_bar()
        
        # Set up auto-refresh
        self.auto_refresh = True
        self.refresh_rate = 2  # seconds
        
        # Load existing data
        self._refresh_data()
        self._load_latest_analysis_results()
        
        # Start the auto-refresh thread
        self.refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        self.refresh_thread.start()
    
    def _create_control_panel(self):
        """
        Create the control panel with buttons and filters.
        
        Features:
        - Start/Stop Simulation button to toggle event simulation
        - Run Analysis button to trigger security analysis
        - Refresh button for manual data updates
        - Clear DB button to reset the database
        - Event Type filter to show specific event categories
        - Auto-refresh toggle for real-time updates
        """
        control_frame = ttk.LabelFrame(self.root, text="Control Panel")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Create a frame for the buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(side="left", padx=10, pady=5)
        
        # Simulation control
        self.sim_btn = ttk.Button(btn_frame, text="Start Simulation", command=self._toggle_simulation)
        self.sim_btn.pack(side="left", padx=5)
        
        # Analysis control
        self.analysis_btn = ttk.Button(btn_frame, text="Run Analysis", command=self._run_analysis)
        self.analysis_btn.pack(side="left", padx=5)
        
        # Refresh button
        refresh_btn = ttk.Button(btn_frame, text="Refresh", command=self._refresh_data)
        refresh_btn.pack(side="left", padx=5)
        
        # Clear button
        clear_btn = ttk.Button(btn_frame, text="Clear DB", command=self._clear_database)
        clear_btn.pack(side="left", padx=5)
        
        # Create a frame for the filters
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(side="right", padx=10, pady=5)
        
        # Event type filter
        ttk.Label(filter_frame, text="Event Type:").pack(side="left", padx=5)
        event_types = ["All"] + list(self.event_types.keys())
        event_type_cb = ttk.Combobox(filter_frame, textvariable=self.selected_event_type, values=event_types, width=15)
        event_type_cb.pack(side="left", padx=5)
        event_type_cb.bind("<<ComboboxSelected>>", lambda _: self._refresh_data())
        
        # Auto-refresh toggle
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_cb = ttk.Checkbutton(
            filter_frame, 
            text="Auto-refresh", 
            variable=self.auto_refresh_var,
            command=self._toggle_auto_refresh
        )
        auto_refresh_cb.pack(side="left", padx=10)
    
    def _create_notebook(self):
        """
        Create a notebook with tabs for logs, charts, and analysis.
        
        Features:
        - Event Logs tab for displaying and filtering security events
        - Analysis Results tab for viewing security analysis findings
        - Event Charts tab for visualizing event data graphically
        """
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Logs Tab
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Event Logs")
        self._create_logs_tab(logs_frame)
        
        # Analysis Tab
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="Analysis Results")
        self._create_analysis_tab(analysis_frame)
        
        # Charts Tab
        charts_frame = ttk.Frame(self.notebook)
        self.notebook.add(charts_frame, text="Event Charts")
        self._create_charts_tab(charts_frame)
    
    def _create_logs_tab(self, parent):
        """
        Create the logs tab with a treeview for displaying events.
        
        Features:
        - Treeview display with columns for event details
        - Color-coded rows based on event severity
        - Double-click functionality to view detailed event information
        - Scrollbars for easy navigation
        
        Args:
            parent: Parent frame where the tab content will be placed
        """
        # Create a frame for the treeview
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create the treeview with scrollbars
        columns = ("ID", "Timestamp", "Type", "Description", "Source", "Severity")
        self.log_tree = ttk.Treeview(
            tree_frame, 
            columns=columns, 
            show="headings", 
            selectmode="browse"
        )
        
        # Configure the columns
        self.log_tree.heading("ID", text="ID")
        self.log_tree.heading("Timestamp", text="Timestamp")
        self.log_tree.heading("Type", text="Event Type")
        self.log_tree.heading("Description", text="Description")
        self.log_tree.heading("Source", text="Source")
        self.log_tree.heading("Severity", text="Severity")
        
        self.log_tree.column("ID", width=50, anchor="center")
        self.log_tree.column("Timestamp", width=180, anchor="w")
        self.log_tree.column("Type", width=150, anchor="w")
        self.log_tree.column("Description", width=350, anchor="w")
        self.log_tree.column("Source", width=120, anchor="w")
        self.log_tree.column("Severity", width=80, anchor="center")
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.log_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.log_tree.xview)
        self.log_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Pack the treeview and scrollbars
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.log_tree.pack(side="left", fill="both", expand=True)
        
        # Bind double-click to show event details
        self.log_tree.bind("<Double-1>", self._show_event_details)
    
    def _create_analysis_tab(self, parent):
        """
        Create the analysis tab with results display.
        
        Features:
        - Treeview display for analysis results
        - Color-coded rows based on severity
        - Detailed information about detected anomalies and attack patterns
        
        Args:
            parent: Parent frame where the tab content will be placed
        """
        # Create a frame for the analysis results
        analysis_frame = ttk.Frame(parent)
        analysis_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create the treeview with scrollbars for analysis results
        columns = ("Timestamp", "Type", "Result", "Severity")
        self.analysis_tree = ttk.Treeview(
            analysis_frame, 
            columns=columns, 
            show="headings", 
            selectmode="browse"
        )
        
        # Configure the columns
        self.analysis_tree.heading("Timestamp", text="Timestamp")
        self.analysis_tree.heading("Type", text="Analysis Type")
        self.analysis_tree.heading("Result", text="Result")
        self.analysis_tree.heading("Severity", text="Severity")
        
        self.analysis_tree.column("Timestamp", width=180, anchor="w")
        self.analysis_tree.column("Type", width=150, anchor="w")
        self.analysis_tree.column("Result", width=450, anchor="w")
        self.analysis_tree.column("Severity", width=80, anchor="center")
        
        # Add scrollbars
        vsb = ttk.Scrollbar(analysis_frame, orient="vertical", command=self.analysis_tree.yview)
        hsb = ttk.Scrollbar(analysis_frame, orient="horizontal", command=self.analysis_tree.xview)
        self.analysis_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Pack the treeview and scrollbars
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.analysis_tree.pack(side="left", fill="both", expand=True)
    
    def _create_charts_tab(self, parent):
        """
        Create the charts tab with visualizations.
        
        Features:
        - Bar chart showing event counts by type
        - Line chart displaying event frequency over time
        - Interactive matplotlib integration with pan/zoom capabilities
        
        Args:
            parent: Parent frame where the tab content will be placed
        """
        # Create a frame for the charts
        charts_frame = ttk.Frame(parent)
        charts_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create a matplotlib figure
        self.fig = Figure(figsize=(10, 6), dpi=100)
        
        # Create subplots
        self.ax1 = self.fig.add_subplot(211)  # Event frequency by type
        self.ax2 = self.fig.add_subplot(212)  # Event count over time
        
        # Embed the figure in the tkinter window
        self.canvas = FigureCanvasTkAgg(self.fig, charts_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Add a toolbar
        from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk
        toolbar = NavigationToolbar2Tk(self.canvas, charts_frame)
        toolbar.update()
    
    def _create_status_bar(self):
        """
        Create a status bar at the bottom of the window.
        
        Features:
        - Displays current application status
        - Shows operation results and error messages
        - Provides feedback on background processes
        """
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var, 
            relief="sunken", 
            anchor="w"
        )
        status_bar.pack(side="bottom", fill="x")
    
    def _toggle_simulation(self):
        """
        Toggle the event simulation on/off.
        
        Features:
        - Starts or stops the event simulation thread
        - Updates the button text and status bar
        - Runs simulation in a separate thread to avoid blocking the UI
        """
        if self.simulation_running:
            self.simulation_running = False
            self.sim_btn.config(text="Start Simulation")
            self.status_var.set("Simulation stopped")
        else:
            self.simulation_running = True
            self.sim_btn.config(text="Stop Simulation")
            self.status_var.set("Simulation running...")
            
            # Start simulation in a separate thread
            threading.Thread(target=self._run_simulation, daemon=True).start()
    
    def _run_simulation(self):
        """
        Run the event simulation.
        
        Features:
        - Continuously generates simulated security events
        - Varies event types and parameters randomly
        - Updates the UI with new events
        - Continues until simulation is turned off
        """
        while self.simulation_running:
            try:
                # Use the logger to simulate events
                self.logger.simulate_events(1)
                
                # Update the display if auto-refresh is on
                if self.auto_refresh:
                    self.root.after(0, self._refresh_data)
                    
                # Sleep to control simulation rate
                time.sleep(1)
            except Exception as e:
                self.status_var.set(f"Error in simulation: {str(e)}")
                self.simulation_running = False
                self.sim_btn.config(text="Start Simulation")
                break
    
    def _run_analysis(self):
        """
        Trigger the security analysis process.
        
        Features:
        - Runs the analyzer on the current event database
        - Detects anomalies and matches attack patterns
        - Updates the analysis results display
        - Runs in a separate thread to keep the UI responsive
        """
        if self.analysis_running:
            messagebox.showinfo("Analysis", "Analysis is already running")
            return
            
        self.analysis_running = True
        self.analysis_btn.config(text="Analysis Running...", state="disabled")
        self.status_var.set("Running security analysis...")
        
        # Run analysis in a separate thread
        threading.Thread(target=self._perform_analysis, daemon=True).start()
    
    def _perform_analysis(self):
        """
        Perform the actual security analysis.
        
        Features:
        - Calls the analyzer to detect anomalies and patterns
        - Updates the severity of existing events based on findings
        - Saves results to file for persistence
        - Updates the UI with analysis results
        """
        try:
            results = self.analyzer.run_analysis()
            self.root.after(0, lambda: self._update_analysis_results(results))
        except Exception as e:
            self.status_var.set(f"Error in analysis: {str(e)}")
        finally:
            self.root.after(0, self._reset_analysis_button)
    
    def _reset_analysis_button(self):
        """Reset the analysis button state after analysis completes."""
        self.analysis_running = False
        self.analysis_btn.config(text="Run Analysis", state="normal")
    
    def _update_analysis_results(self, results):
        """
        Update the analysis results display.
        
        Features:
        - Clears existing results and populates with new data
        - Color-codes results based on severity
        - Formats results for readability
        - Updates status bar with analysis summary
        
        Args:
            results: Dictionary of analysis results from the analyzer
        """
        # Clear existing items
        for item in self.analysis_tree.get_children():
            self.analysis_tree.delete(item)
            
        # Insert anomalies
        for anomaly in results.get("anomalies", []):
            timestamp = anomaly["timestamp"]
            analysis_type = "Anomaly Detection"
            
            event_type = anomaly["event_type"]
            current = anomaly["current_count"]
            average = round(anomaly["average_count"], 2)
            threshold = round(anomaly["threshold"], 2)
            
            result = f"Unusual frequency of '{event_type}' events: {current} (avg: {average}, threshold: {threshold})"
            severity = anomaly["severity"]
            
            item_id = self.analysis_tree.insert("", "end", values=(timestamp, analysis_type, result, severity))
            
            # Set background color based on severity
            self.analysis_tree.tag_configure(f"severity_{severity}", background=self.severity_colors.get(severity, "#ffffff"))
            self.analysis_tree.item(item_id, tags=(f"severity_{severity}",))
            
        # Insert pattern matches
        for match in results.get("pattern_matches", []):
            timestamp = match["timestamp"]
            analysis_type = "Pattern Matching"
            pattern_name = match["pattern_name"]
            severity = match["severity"]
            
            # Handle different types of pattern matches
            if "event_count" in match:
                # Frequency-based pattern match
                count = match["event_count"]
                result = f"Detected attack pattern: '{pattern_name}' ({count} matching events)"
            else:
                # Property-based pattern match (individual event)
                event_id = match.get("event_id", "Unknown")
                result = f"Detected attack pattern: '{pattern_name}' on event ID {event_id}"
            
            item_id = self.analysis_tree.insert("", "end", values=(timestamp, analysis_type, result, severity))
            
            # Set background color based on severity
            self.analysis_tree.tag_configure(f"severity_{severity}", background=self.severity_colors.get(severity, "#ffffff"))
            self.analysis_tree.item(item_id, tags=(f"severity_{severity}",))
            
        # Update status
        total_results = len(results.get("anomalies", [])) + len(results.get("pattern_matches", []))
        self.status_var.set(f"Analysis complete: Found {total_results} potential security issues")
        
        # Refresh other views to show updated severities
        self._update_event_logs()
            
    def _refresh_data(self):
        """
        Refresh all data displays.
        
        Features:
        - Updates event logs with the latest events
        - Refreshes chart visualizations
        - Maintains current filter selections
        """
        self._update_event_logs()
        self._update_charts()
        self.status_var.set("Data refreshed")
    
    def _update_event_logs(self):
        """
        Update the event logs display.
        
        Features:
        - Retrieves the latest events from the database
        - Applies event type filtering
        - Color-codes events based on severity
        - Maintains sort order and selection
        """
        # Clear existing items
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
            
        # Get events from database
        conn = sqlite3.connect(self.logger.db_path)
        cursor = conn.cursor()
        
        if self.selected_event_type.get() == "All":
            cursor.execute('''
            SELECT id, timestamp, event_type, description, source, severity
            FROM security_events
            ORDER BY id DESC
            LIMIT 100
            ''')
        else:
            cursor.execute('''
            SELECT id, timestamp, event_type, description, source, severity
            FROM security_events
            WHERE event_type = ?
            ORDER BY id DESC
            LIMIT 100
            ''', (self.selected_event_type.get(),))
            
        events = cursor.fetchall()
        conn.close()
        
        # Insert events into treeview
        for event in events:
            event_id, timestamp, event_type, description, source, severity = event
            item_id = self.log_tree.insert("", "end", values=(event_id, timestamp, event_type, description, source, severity))
            
            # Set background color based on severity
            self.log_tree.tag_configure(f"severity_{severity}", background=self.severity_colors.get(severity, "#ffffff"))
            self.log_tree.item(item_id, tags=(f"severity_{severity}",))
    
    def _update_charts(self):
        """
        Update the charts with current event data.
        
        Features:
        - Creates a bar chart of event counts by type
        - Generates a line chart of event frequency over time
        - Customizes chart appearance for readability
        - Auto-scales axes based on data
        """
        conn = sqlite3.connect(self.logger.db_path)
        cursor = conn.cursor()
        
        # Clear previous charts
        self.ax1.clear()
        self.ax2.clear()
        
        # Chart 1: Event counts by type
        cursor.execute('''
        SELECT event_type, COUNT(*) as count
        FROM security_events
        GROUP BY event_type
        ORDER BY count DESC
        ''')
        
        event_types = []
        event_counts = []
        for event_type, count in cursor.fetchall():
            event_types.append(event_type)
            event_counts.append(count)
        
        if event_types:
            bars = self.ax1.bar(event_types, event_counts, color='skyblue')
            self.ax1.set_title('Event Counts by Type')
            self.ax1.set_xlabel('Event Type')
            self.ax1.set_ylabel('Count')
            self.ax1.tick_params(axis='x', rotation=45)
            
            # Add count labels on top of bars
            for bar in bars:
                height = bar.get_height()
                self.ax1.annotate(f'{height}',
                                xy=(bar.get_x() + bar.get_width() / 2, height),
                                xytext=(0, 3),  # 3 points vertical offset
                                textcoords="offset points",
                                ha='center', va='bottom')
        
        # Chart 2: Event frequency over time
        hours = 6
        time_limit = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
        SELECT strftime('%H:%M', timestamp) as time_period, COUNT(*) as count
        FROM security_events
        WHERE timestamp > ?
        GROUP BY time_period
        ORDER BY timestamp
        ''', (time_limit,))
        
        time_periods = []
        period_counts = []
        for time_period, count in cursor.fetchall():
            time_periods.append(time_period)
            period_counts.append(count)
        
        if time_periods:
            self.ax2.plot(time_periods, period_counts, marker='o', linestyle='-', color='green')
            self.ax2.set_title(f'Event Frequency (Last {hours} Hours)')
            self.ax2.set_xlabel('Time')
            self.ax2.set_ylabel('Event Count')
            self.ax2.tick_params(axis='x', rotation=45)
            self.ax2.grid(True, linestyle='--', alpha=0.7)
        
        # Adjust layout and redraw
        self.fig.tight_layout()
        self.canvas.draw()
        
        conn.close()
    
    def _show_event_details(self, event):
        """
        Display detailed information about a selected event.
        
        Features:
        - Shows a popup window with complete event details
        - Displays raw event data for detailed analysis
        - Formats data for readability
        
        Args:
            event: The tkinter event that triggered this function
        """
        # Get the selected item
        selected_item = self.log_tree.selection()[0]
        event_id = self.log_tree.item(selected_item)['values'][0]
        
        # Fetch the event details from the database
        conn = sqlite3.connect(self.logger.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT *
        FROM security_events
        WHERE id = ?
        ''', (event_id,))
        
        event_data = cursor.fetchone()
        
        # Fetch any analysis results for this event
        cursor.execute('''
        SELECT timestamp, analysis_type, result, severity
        FROM analysis_results
        WHERE event_id = ?
        ORDER BY timestamp DESC
        ''', (event_id,))
        
        analysis_results = cursor.fetchall()
        conn.close()
        
        if not event_data:
            return
        
        # Create a details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Event Details - ID: {event_id}")
        details_window.geometry("700x500")
        details_window.transient(self.root)
        details_window.grab_set()
        
        # Create a notebook for tabs
        details_nb = ttk.Notebook(details_window)
        details_nb.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Event Details Tab
        event_frame = ttk.Frame(details_nb)
        details_nb.add(event_frame, text="Event Details")
        
        # Format the event details
        details_text = f"""
Event ID: {event_data['id']}
Timestamp: {event_data['timestamp']}
Event Type: {event_data['event_type']}
Description: {event_data['description']}
Source: {event_data['source']}
Severity: {event_data['severity']}

Raw Data:
{event_data['raw_data']}
"""
        
        # Event details text area
        details_area = scrolledtext.ScrolledText(event_frame, wrap="word")
        details_area.pack(fill="both", expand=True, padx=5, pady=5)
        details_area.insert("1.0", details_text)
        details_area.config(state="disabled")
        
        # Analysis Results Tab (if any)
        if analysis_results:
            analysis_frame = ttk.Frame(details_nb)
            details_nb.add(analysis_frame, text="Analysis Results")
            
            analysis_text = "Analysis Results:\n\n"
            for result in analysis_results:
                analysis_text += f"Time: {result['timestamp']}\n"
                analysis_text += f"Type: {result['analysis_type']}\n"
                analysis_text += f"Severity: {result['severity']}\n"
                
                # Pretty-print the JSON result
                try:
                    result_json = json.loads(result['result'])
                    formatted_result = json.dumps(result_json, indent=2)
                    analysis_text += f"Result:\n{formatted_result}\n\n"
                except:
                    analysis_text += f"Result: {result['result']}\n\n"
                
                analysis_text += "-------------------\n\n"
            
            # Analysis results text area
            analysis_area = scrolledtext.ScrolledText(analysis_frame, wrap="word")
            analysis_area.pack(fill="both", expand=True, padx=5, pady=5)
            analysis_area.insert("1.0", analysis_text)
            analysis_area.config(state="disabled")
        
        # Close button
        close_btn = ttk.Button(details_window, text="Close", command=details_window.destroy)
        close_btn.pack(pady=10)
    
    def _toggle_auto_refresh(self):
        """
        Toggle automatic data refresh on/off.
        
        Features:
        - Enables or disables the periodic data refresh
        - Updates the status bar to indicate the current setting
        """
        self.auto_refresh = self.auto_refresh_var.get()
        if self.auto_refresh:
            self.status_var.set("Auto-refresh enabled")
        else:
            self.status_var.set("Auto-refresh disabled")
    
    def _auto_refresh(self):
        """
        Background thread for automatic data refresh.
        
        Features:
        - Periodically refreshes the data display
        - Respects the auto-refresh setting
        - Runs at the configured refresh rate
        """
        while True:
            if self.auto_refresh:
                self.root.after(0, self._refresh_data)
            time.sleep(self.refresh_rate)
    
    def _clear_database(self):
        """
        Clear all events from the database.
        
        Features:
        - Confirms with the user before deletion
        - Removes all events from the database
        - Resets the display after clearing
        - Provides status feedback
        """
        # Confirm with the user
        if messagebox.askyesno("Clear Database", "Are you sure you want to clear all events from the database?"):
            try:
                # Connect to the database
                conn = sqlite3.connect(self.logger.db_path)
                cursor = conn.cursor()
                
                # Clear the tables
                cursor.execute("DELETE FROM security_events")
                cursor.execute("DELETE FROM analysis_results")
                
                # Commit changes and close connection
                conn.commit()
                conn.close()
                
                # Refresh the display
                self._refresh_data()
                
                # Clear the analysis results display
                for item in self.analysis_tree.get_children():
                    self.analysis_tree.delete(item)
                
                self.status_var.set("Database cleared successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear database: {str(e)}")
                self.status_var.set("Error clearing database")
    
    def _load_latest_analysis_results(self):
        """
        Load the latest analysis results from the database to display in the UI.
        
        Features:
        - Retrieves the most recent analysis results
        - Populates the analysis tree with existing results
        - Handles both anomaly detection and pattern matching results
        """
        # Connect to the database
        conn = sqlite3.connect(self.logger.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Clear existing items
        for item in self.analysis_tree.get_children():
            self.analysis_tree.delete(item)
            
        # Get the latest analysis results
        cursor.execute('''
        SELECT timestamp, analysis_type, result, severity
        FROM analysis_results
        ORDER BY timestamp DESC
        LIMIT 100
        ''')
        
        for row in cursor.fetchall():
            timestamp = row["timestamp"]
            analysis_type = row["analysis_type"]
            severity = row["severity"]
            
            try:
                # Parse the result JSON
                result_data = json.loads(row["result"])
                
                if analysis_type == "anomaly_detection":
                    # Format anomaly detection results
                    event_type = result_data.get("event_type", "Unknown")
                    current = result_data.get("current_count", 0)
                    average = round(result_data.get("average_count", 0), 2)
                    threshold = round(result_data.get("threshold", 0), 2)
                    display_text = f"Unusual frequency of '{event_type}' events: {current} (avg: {average}, threshold: {threshold})"
                
                elif analysis_type == "pattern_matching":
                    # Format pattern matching results
                    pattern_name = result_data.get("pattern_name", "Unknown")
                    if "event_count" in result_data:
                        # Frequency-based pattern
                        count = result_data.get("event_count", 0)
                        display_text = f"Detected attack pattern: '{pattern_name}' ({count} matching events)"
                    else:
                        # Property-based pattern
                        event_id = result_data.get("event_id", "Unknown")
                        display_text = f"Detected attack pattern: '{pattern_name}' on event ID {event_id}"
                
                else:
                    # Generic format for other analysis types
                    display_text = f"Analysis: {str(result_data)}"
                    
            except Exception as e:
                # Fallback for invalid JSON
                display_text = f"Analysis result: {row['result']}"
            
            # Insert into treeview
            item_id = self.analysis_tree.insert("", "end", values=(timestamp, analysis_type, display_text, severity))
            
            # Set background color based on severity
            self.analysis_tree.tag_configure(f"severity_{severity}", background=self.severity_colors.get(severity, "#ffffff"))
            self.analysis_tree.item(item_id, tags=(f"severity_{severity}",))
        
        conn.close()


def main():
    """
    Main entry point for the application.
    
    Features:
    - Creates the root tkinter window
    - Initializes the main application GUI
    - Starts the tkinter event loop
    """
    # Check for required packages and dependencies
    try:
        root = tk.Tk()
        app = SecurityEventLoggerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Error starting application: {str(e)}")
        
if __name__ == "__main__":
    main() 
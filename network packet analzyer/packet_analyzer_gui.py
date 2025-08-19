#!/usr/bin/env python3
"""
Network Packet Analyzer - Scientific GUI Version
===============================================

A professional scientific interface for network packet analysis
with real-time visualizations, statistics, and data export capabilities.

ETHICAL USE WARNING:
- Only use on networks you own or have explicit permission to monitor
- Do not capture sensitive or personal information
- This tool is for educational and research purposes only
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
import datetime
import json
import csv
from collections import defaultdict, deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from scapy.all import *
import numpy as np
import pandas as pd
from PIL import Image, ImageTk
import queue
import sys
import os

class ScientificPacketAnalyzer:
    def __init__(self, root):
        """Initialize the scientific packet analyzer GUI."""
        self.root = root
        self.root.title("Network Packet Analyzer - Scientific Edition")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1e1e1e')
        
        # Initialize variables
        self.is_capturing = False
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.packet_history = deque(maxlen=1000)
        self.interface_list = []
        self.selected_interface = tk.StringVar()
        self.capture_queue = queue.Queue()
        
        # Data storage for analysis
        self.time_series_data = deque(maxlen=100)
        self.protocol_data = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.destination_ips = defaultdict(int)
        self.port_data = defaultdict(int)
        
        # Setup UI
        self.setup_ui()
        self.load_interfaces()
        self.display_ethical_warning()
        
        # Start update loop
        self.update_ui()
    
    def setup_ui(self):
        """Setup the scientific GUI interface."""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Scientific.TFrame', background='#2d2d2d')
        style.configure('Scientific.TLabel', background='#2d2d2d', foreground='#ffffff')
        style.configure('Scientific.TButton', background='#007acc', foreground='#ffffff')
        
        # Main container
        main_frame = ttk.Frame(self.root, style='Scientific.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, text="🔬 Network Packet Analyzer - Scientific Edition", 
                              font=('Arial', 16, 'bold'), bg='#2d2d2d', fg='#ffffff')
        title_label.pack(pady=(0, 20))
        
        # Control Panel
        self.setup_control_panel(main_frame)
        
        # Main content area
        content_frame = ttk.Frame(main_frame, style='Scientific.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Setup tabs
        self.setup_realtime_tab()
        self.setup_statistics_tab()
        self.setup_visualization_tab()
        self.setup_packet_details_tab()
        self.setup_export_tab()
    
    def setup_control_panel(self, parent):
        """Setup the control panel with scientific controls."""
        control_frame = ttk.Frame(parent, style='Scientific.TFrame')
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Interface selection
        interface_frame = ttk.Frame(control_frame, style='Scientific.TFrame')
        interface_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        tk.Label(interface_frame, text="📡 Interface:", bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.selected_interface, 
                                           width=20, state='readonly')
        self.interface_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        # Capture controls
        capture_frame = ttk.Frame(control_frame, style='Scientific.TFrame')
        capture_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        self.start_button = tk.Button(capture_frame, text="▶️ Start Capture", 
                                     command=self.start_capture, bg='#28a745', fg='white',
                                     font=('Arial', 10, 'bold'))
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = tk.Button(capture_frame, text="⏹️ Stop Capture", 
                                    command=self.stop_capture, bg='#dc3545', fg='white',
                                    font=('Arial', 10, 'bold'), state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.clear_button = tk.Button(capture_frame, text="🗑️ Clear Data", 
                                     command=self.clear_data, bg='#ffc107', fg='black',
                                     font=('Arial', 10, 'bold'))
        self.clear_button.pack(side=tk.LEFT)
        
        # Status display
        status_frame = ttk.Frame(control_frame, style='Scientific.TFrame')
        status_frame.pack(side=tk.RIGHT)
        
        self.status_label = tk.Label(status_frame, text="⏸️ Ready", bg='#2d2d2d', fg='#ffffff',
                                    font=('Arial', 10))
        self.status_label.pack(side=tk.RIGHT)
        
        self.packet_count_label = tk.Label(status_frame, text="Packets: 0", bg='#2d2d2d', fg='#ffffff',
                                          font=('Arial', 10))
        self.packet_count_label.pack(side=tk.RIGHT, padx=(0, 10))
    
    def setup_realtime_tab(self):
        """Setup the real-time packet display tab."""
        realtime_frame = ttk.Frame(self.notebook, style='Scientific.TFrame')
        self.notebook.add(realtime_frame, text="📊 Real-time Analysis")
        
        # Packet display
        packet_frame = ttk.Frame(realtime_frame, style='Scientific.TFrame')
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(packet_frame, text="🔍 Live Packet Analysis", bg='#2d2d2d', fg='#ffffff',
                font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        # Packet list with scrollbar
        list_frame = ttk.Frame(packet_frame, style='Scientific.TFrame')
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create Treeview for packet display
        columns = ('Time', 'Protocol', 'Source', 'Destination', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click for packet details
        self.packet_tree.bind('<Double-1>', self.show_packet_details)
    
    def setup_statistics_tab(self):
        """Setup the statistics tab."""
        stats_frame = ttk.Frame(self.notebook, style='Scientific.TFrame')
        self.notebook.add(stats_frame, text="📈 Statistics")
        
        # Statistics grid
        stats_grid = ttk.Frame(stats_frame, style='Scientific.TFrame')
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Protocol statistics
        protocol_frame = ttk.LabelFrame(stats_grid, text="Protocol Distribution", 
                                       style='Scientific.TFrame')
        protocol_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.protocol_text = scrolledtext.ScrolledText(protocol_frame, height=8, bg='#1e1e1e', fg='#ffffff')
        self.protocol_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top IP addresses
        ip_frame = ttk.LabelFrame(stats_grid, text="Top IP Addresses", style='Scientific.TFrame')
        ip_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.ip_text = scrolledtext.ScrolledText(ip_frame, height=8, bg='#1e1e1e', fg='#ffffff')
        self.ip_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Port statistics
        port_frame = ttk.LabelFrame(stats_grid, text="Port Analysis", style='Scientific.TFrame')
        port_frame.pack(fill=tk.BOTH, expand=True)
        
        self.port_text = scrolledtext.ScrolledText(port_frame, height=8, bg='#1e1e1e', fg='#ffffff')
        self.port_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_visualization_tab(self):
        """Setup the visualization tab with charts."""
        viz_frame = ttk.Frame(self.notebook, style='Scientific.TFrame')
        self.notebook.add(viz_frame, text="📊 Visualizations")
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(12, 8), facecolor='#2d2d2d')
        self.canvas = FigureCanvasTkAgg(self.fig, viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create subplots
        self.ax1 = self.fig.add_subplot(2, 2, 1)  # Protocol pie chart
        self.ax2 = self.fig.add_subplot(2, 2, 2)  # Time series
        self.ax3 = self.fig.add_subplot(2, 2, 3)  # Top IPs bar chart
        self.ax4 = self.fig.add_subplot(2, 2, 4)  # Port distribution
        
        # Configure plot styles
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.set_facecolor('#1e1e1e')
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['top'].set_color('white')
            ax.spines['left'].set_color('white')
            ax.spines['right'].set_color('white')
        
        self.fig.tight_layout()
    
    def setup_packet_details_tab(self):
        """Setup the packet details tab."""
        details_frame = ttk.Frame(self.notebook, style='Scientific.TFrame')
        self.notebook.add(details_frame, text="🔍 Packet Details")
        
        # Packet details display
        details_label = tk.Label(details_frame, text="📦 Packet Analysis Details", 
                                bg='#2d2d2d', fg='#ffffff', font=('Arial', 12, 'bold'))
        details_label.pack(anchor=tk.W, padx=10, pady=(10, 0))
        
        # Details text area
        self.details_text = scrolledtext.ScrolledText(details_frame, height=25, bg='#1e1e1e', fg='#ffffff')
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def setup_export_tab(self):
        """Setup the export tab."""
        export_frame = ttk.Frame(self.notebook, style='Scientific.TFrame')
        self.notebook.add(export_frame, text="💾 Export Data")
        
        # Export controls
        export_controls = ttk.Frame(export_frame, style='Scientific.TFrame')
        export_controls.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(export_controls, text="📊 Export Options:", bg='#2d2d2d', fg='#ffffff',
                font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        # Export buttons
        button_frame = ttk.Frame(export_controls, style='Scientific.TFrame')
        button_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(button_frame, text="📄 Export to CSV", command=self.export_csv,
                 bg='#007acc', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="📊 Export to JSON", command=self.export_json,
                 bg='#007acc', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="📈 Export Charts", command=self.export_charts,
                 bg='#007acc', fg='white', font=('Arial', 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(button_frame, text="📋 Export Report", command=self.export_report,
                 bg='#007acc', fg='white', font=('Arial', 10)).pack(side=tk.LEFT)
        
        # Export status
        self.export_status = tk.Label(export_frame, text="", bg='#2d2d2d', fg='#ffffff')
        self.export_status.pack(pady=10)
    
    def load_interfaces(self):
        """Load available network interfaces."""
        try:
            self.interface_list = get_if_list()
            self.interface_combo['values'] = self.interface_list
            if self.interface_list:
                self.interface_combo.set(self.interface_list[0])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load interfaces: {e}")
    
    def display_ethical_warning(self):
        """Display ethical use warning."""
        warning = """
🔬 NETWORK PACKET ANALYZER - SCIENTIFIC EDITION

ETHICAL USE WARNING:
This tool is for EDUCATIONAL AND RESEARCH PURPOSES ONLY.

✅ DO:
   • Use on networks you own or have permission to monitor
   • Use for learning network protocols and traffic analysis
   • Respect privacy and legal requirements

❌ DON'T:
   • Capture sensitive or personal information
   • Monitor networks without permission
   • Use for malicious purposes

By using this tool, you agree to use it ethically and responsibly.
        """
        
        result = messagebox.askyesno("Ethical Use Agreement", warning)
        if not result:
            self.root.quit()
    
    def start_capture(self):
        """Start packet capture."""
        if not self.selected_interface.get():
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        self.is_capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="🔴 Capturing...")
        
        # Start capture thread
        capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="⏸️ Stopped")
    
    def capture_packets(self):
        """Capture packets in a separate thread."""
        try:
            sniff(iface=self.selected_interface.get(), prn=self.process_packet, 
                  store=0, stop_filter=lambda x: not self.is_capturing)
        except Exception as e:
            self.capture_queue.put(('error', str(e)))
    
    def process_packet(self, packet):
        """Process captured packet."""
        try:
            packet_info = self.extract_packet_info(packet)
            self.capture_queue.put(('packet', packet_info))
        except Exception as e:
            self.capture_queue.put(('error', str(e)))
    
    def extract_packet_info(self, packet):
        """Extract information from packet."""
        info = {
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'length': len(packet),
            'payload': None,
            'raw_packet': packet
        }
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
        
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                payload_str = ''.join(char for char in payload_str if char.isprintable())
                info['payload'] = payload_str[:100] + ('...' if len(payload_str) > 100 else '')
            except:
                info['payload'] = f"[Binary data: {len(payload)} bytes]"
        
        return info
    
    def update_ui(self):
        """Update the UI with new data."""
        try:
            while not self.capture_queue.empty():
                msg_type, data = self.capture_queue.get_nowait()
                
                if msg_type == 'packet':
                    self.add_packet_to_ui(data)
                elif msg_type == 'error':
                    messagebox.showerror("Capture Error", data)
            
            # Update statistics
            self.update_statistics()
            
            # Update visualizations
            self.update_visualizations()
            
        except Exception as e:
            print(f"UI update error: {e}")
        
        # Schedule next update
        self.root.after(100, self.update_ui)
    
    def add_packet_to_ui(self, packet_info):
        """Add packet to the UI display."""
        self.packet_count += 1
        self.protocol_stats[packet_info['protocol']] += 1
        
        # Add to packet history
        self.packet_history.append(packet_info)
        
        # Update data structures
        self.time_series_data.append((time.time(), packet_info['length']))
        self.protocol_data[packet_info['protocol']] += 1
        self.source_ips[packet_info['src_ip']] += 1
        self.destination_ips[packet_info['dst_ip']] += 1
        
        if packet_info['src_port']:
            self.port_data[packet_info['src_port']] += 1
        if packet_info['dst_port']:
            self.port_data[packet_info['dst_port']] += 1
        
        # Add to treeview
        info_text = f"{packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}"
        self.packet_tree.insert('', 0, values=(
            packet_info['timestamp'],
            packet_info['protocol'],
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['length'],
            info_text
        ))
        
        # Limit treeview items
        if len(self.packet_tree.get_children()) > 100:
            self.packet_tree.delete(self.packet_tree.get_children()[-1])
        
        # Update packet count
        self.packet_count_label.config(text=f"Packets: {self.packet_count}")
    
    def update_statistics(self):
        """Update statistics displays."""
        # Protocol statistics
        protocol_text = "Protocol Distribution:\n"
        for protocol, count in sorted(self.protocol_data.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / max(sum(self.protocol_data.values()), 1)) * 100
            protocol_text += f"{protocol}: {count} ({percentage:.1f}%)\n"
        
        self.protocol_text.delete(1.0, tk.END)
        self.protocol_text.insert(1.0, protocol_text)
        
        # IP statistics
        ip_text = "Top Source IPs:\n"
        for ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
            ip_text += f"{ip}: {count}\n"
        
        ip_text += "\nTop Destination IPs:\n"
        for ip, count in sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
            ip_text += f"{ip}: {count}\n"
        
        self.ip_text.delete(1.0, tk.END)
        self.ip_text.insert(1.0, ip_text)
        
        # Port statistics
        port_text = "Top Ports:\n"
        for port, count in sorted(self.port_data.items(), key=lambda x: x[1], reverse=True)[:15]:
            port_text += f"Port {port}: {count}\n"
        
        self.port_text.delete(1.0, tk.END)
        self.port_text.insert(1.0, port_text)
    
    def update_visualizations(self):
        """Update charts and visualizations."""
        try:
            # Clear previous plots
            for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
                ax.clear()
                ax.set_facecolor('#1e1e1e')
                ax.tick_params(colors='white')
            
            # Protocol pie chart
            if self.protocol_data:
                protocols = list(self.protocol_data.keys())
                counts = list(self.protocol_data.values())
                colors = plt.cm.Set3(np.linspace(0, 1, len(protocols)))
                
                self.ax1.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors)
                self.ax1.set_title('Protocol Distribution', color='white')
            
            # Time series
            if self.time_series_data:
                times, lengths = zip(*list(self.time_series_data))
                self.ax2.plot(times, lengths, 'b-', alpha=0.7)
                self.ax2.set_title('Packet Length Over Time', color='white')
                self.ax2.set_xlabel('Time', color='white')
                self.ax2.set_ylabel('Packet Length (bytes)', color='white')
            
            # Top IPs bar chart
            if self.source_ips:
                top_ips = sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                ips, counts = zip(*top_ips)
                self.ax3.bar(range(len(ips)), counts, color='green', alpha=0.7)
                self.ax3.set_title('Top Source IPs', color='white')
                self.ax3.set_xlabel('IP Address', color='white')
                self.ax3.set_ylabel('Packet Count', color='white')
                self.ax3.set_xticks(range(len(ips)))
                self.ax3.set_xticklabels(ips, rotation=45, ha='right')
            
            # Port distribution
            if self.port_data:
                top_ports = sorted(self.port_data.items(), key=lambda x: x[1], reverse=True)[:10]
                ports, counts = zip(*top_ports)
                self.ax4.bar(range(len(ports)), counts, color='orange', alpha=0.7)
                self.ax4.set_title('Top Ports', color='white')
                self.ax4.set_xlabel('Port Number', color='white')
                self.ax4.set_ylabel('Packet Count', color='white')
                self.ax4.set_xticks(range(len(ports)))
                self.ax4.set_xticklabels(ports)
            
            self.fig.tight_layout()
            self.canvas.draw()
            
        except Exception as e:
            print(f"Visualization error: {e}")
    
    def show_packet_details(self, event):
        """Show detailed packet information."""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        # Get packet from history
        item = self.packet_tree.item(selection[0])
        timestamp = item['values'][0]
        
        # Find packet in history
        for packet in self.packet_history:
            if packet['timestamp'] == timestamp:
                self.display_packet_details(packet)
                break
    
    def display_packet_details(self, packet_info):
        """Display detailed packet information."""
        details = f"""
🔍 PACKET ANALYSIS DETAILS
{'='*50}

📊 Basic Information:
   Timestamp: {packet_info['timestamp']}
   Protocol: {packet_info['protocol']}
   Length: {packet_info['length']} bytes

🌐 Network Information:
   Source IP: {packet_info['src_ip']}
   Destination IP: {packet_info['dst_ip']}
   Source Port: {packet_info['src_port']}
   Destination Port: {packet_info['dst_port']}

📄 Payload Analysis:
{packet_info['payload'] if packet_info['payload'] else 'No payload data'}

🔬 Raw Packet Analysis:
{packet_info['raw_packet'].show(dump=True) if hasattr(packet_info, 'raw_packet') else 'Raw packet data not available'}
        """
        
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details)
    
    def clear_data(self):
        """Clear all captured data."""
        self.packet_count = 0
        self.protocol_stats.clear()
        self.packet_history.clear()
        self.time_series_data.clear()
        self.protocol_data.clear()
        self.source_ips.clear()
        self.destination_ips.clear()
        self.port_data.clear()
        
        # Clear UI
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        self.packet_count_label.config(text="Packets: 0")
        self.status_label.config(text="🗑️ Data Cleared")
    
    def export_csv(self):
        """Export packet data to CSV."""
        if not self.packet_history:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".csv", 
                                              filetypes=[("CSV files", "*.csv")])
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['timestamp', 'protocol', 'src_ip', 'dst_ip', 
                                'src_port', 'dst_port', 'length', 'payload']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for packet in self.packet_history:
                        writer.writerow(packet)
                
                self.export_status.config(text=f"✅ Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def export_json(self):
        """Export packet data to JSON."""
        if not self.packet_history:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".json", 
                                              filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                # Convert packet history to serializable format
                export_data = []
                for packet in self.packet_history:
                    packet_copy = packet.copy()
                    if 'raw_packet' in packet_copy:
                        del packet_copy['raw_packet']
                    export_data.append(packet_copy)
                
                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    json.dump(export_data, jsonfile, indent=2)
                
                self.export_status.config(text=f"✅ Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def export_charts(self):
        """Export charts as images."""
        filename = filedialog.asksaveasfilename(defaultextension=".png", 
                                              filetypes=[("PNG files", "*.png")])
        if filename:
            try:
                self.fig.savefig(filename, facecolor='#2d2d2d', bbox_inches='tight')
                self.export_status.config(text=f"✅ Charts exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export charts: {e}")
    
    def export_report(self):
        """Export comprehensive analysis report."""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", 
                                              filetypes=[("Text files", "*.txt")])
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as report:
                    report.write("NETWORK PACKET ANALYSIS REPORT\n")
                    report.write("=" * 50 + "\n\n")
                    report.write(f"Generated: {datetime.datetime.now()}\n")
                    report.write(f"Total Packets: {self.packet_count}\n\n")
                    
                    report.write("PROTOCOL STATISTICS:\n")
                    for protocol, count in self.protocol_data.items():
                        percentage = (count / max(sum(self.protocol_data.values()), 1)) * 100
                        report.write(f"  {protocol}: {count} ({percentage:.1f}%)\n")
                    
                    report.write("\nTOP SOURCE IPs:\n")
                    for ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                        report.write(f"  {ip}: {count}\n")
                    
                    report.write("\nTOP DESTINATION IPs:\n")
                    for ip, count in sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                        report.write(f"  {ip}: {count}\n")
                    
                    report.write("\nTOP PORTS:\n")
                    for port, count in sorted(self.port_data.items(), key=lambda x: x[1], reverse=True)[:15]:
                        report.write(f"  Port {port}: {count}\n")
                
                self.export_status.config(text=f"✅ Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export report: {e}")

def main():
    """Main function to run the scientific GUI."""
    try:
        root = tk.Tk()
        app = ScientificPacketAnalyzer(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Application error: {e}")

if __name__ == "__main__":
    main() 
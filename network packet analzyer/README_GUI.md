# Network Packet Analyzer - Scientific GUI Edition

A professional scientific interface for network packet analysis with advanced visualization, statistical analysis, and real-time monitoring capabilities.

## 🔬 Scientific Features

### Advanced Analysis Capabilities
- **Real-time Packet Visualization** - Live charts and graphs
- **Statistical Analysis** - Comprehensive network statistics
- **Anomaly Detection** - Machine learning-based anomaly detection
- **Traffic Pattern Analysis** - Pattern recognition algorithms
- **Performance Metrics** - Network performance calculations
- **Data Export** - Multiple export formats (CSV, JSON, PNG)

### Scientific Visualization
- **Protocol Distribution Charts** - Pie charts and bar graphs
- **Time Series Analysis** - Packet flow over time
- **Traffic Heatmaps** - Protocol transition matrices
- **Statistical Summaries** - Comprehensive data analysis
- **Real-time Updates** - Live data visualization

## ⚠️ ETHICAL USE WARNING

**This tool is for EDUCATIONAL AND RESEARCH PURPOSES ONLY!**

### ✅ DO:
- Use on networks you own or have permission to analyze
- Use for learning network protocols and traffic analysis
- Use for legitimate research and educational purposes
- Respect privacy and legal requirements

### ❌ DON'T:
- Capture sensitive or personal information
- Monitor networks without permission
- Use for malicious purposes
- Violate privacy or legal requirements

## 📋 Requirements

- Python 3.7+
- Administrator/root privileges (required for packet capture)
- Network interface access
- Scientific computing libraries (installed automatically)

## 🔧 Installation

### Quick Setup
```bash
# Run the scientific GUI setup
python setup_gui.py
```

### Manual Installation
```bash
# Install basic dependencies
pip install -r requirements.txt

# Install scientific analysis dependencies
pip install -r requirements_gui.txt

# Test the installation
python test_tools.py
```

## 🚀 Usage

### Running the Scientific GUI
```bash
# Start the scientific GUI (run as Administrator)
python packet_analyzer_gui.py
```

### Advanced Analysis Module
```bash
# Run advanced scientific analysis
python scientific_analysis.py
```

## 📊 GUI Interface

### Main Tabs

#### 1. 📊 Real-time Analysis
- Live packet capture display
- Real-time packet information
- Interactive packet selection
- Detailed packet analysis

#### 2. 📈 Statistics
- Protocol distribution analysis
- Top IP addresses
- Port analysis
- Traffic statistics

#### 3. 📊 Visualizations
- Protocol pie charts
- Time series graphs
- Traffic heatmaps
- Statistical summaries

#### 4. 🔍 Packet Details
- Detailed packet analysis
- Raw packet data
- Header information
- Payload analysis

#### 5. 💾 Export Data
- CSV export
- JSON export
- Chart export (PNG)
- Report generation

### Control Panel Features
- **Interface Selection** - Choose network interface
- **Start/Stop Capture** - Control packet capture
- **Clear Data** - Reset analysis data
- **Status Display** - Real-time status information

## 🔬 Scientific Analysis Features

### Statistical Analysis
- **Basic Statistics**
  - Mean, median, standard deviation
  - Packet size distribution
  - Protocol frequency analysis
  - Traffic volume calculations

- **Advanced Statistics**
  - Percentile analysis
  - Correlation analysis
  - Trend detection
  - Variance analysis

### Anomaly Detection
- **Large Packet Detection**
  - Statistical outlier detection
  - Threshold-based analysis
  - Unusual packet size identification

- **Protocol Anomalies**
  - Unusual protocol detection
  - Protocol frequency analysis
  - Suspicious pattern identification

- **Traffic Burst Detection**
  - Time-based burst analysis
  - Traffic intensity calculation
  - Anomalous traffic pattern detection

### Performance Metrics
- **Throughput Analysis**
  - Bits per second calculation
  - Packets per second analysis
  - Bandwidth utilization

- **Efficiency Metrics**
  - Protocol efficiency analysis
  - Packet size optimization
  - Network performance indicators

### Pattern Recognition
- **Protocol Transitions**
  - Protocol sequence analysis
  - Transition probability matrices
  - Traffic flow patterns

- **Temporal Patterns**
  - Time-based analysis
  - Interval analysis
  - Traffic timing patterns

## 📈 Visualization Features

### Real-time Charts
- **Protocol Distribution Pie Chart**
  - Real-time protocol percentages
  - Color-coded protocol types
  - Dynamic updates

- **Packet Size Time Series**
  - Packet size over time
  - Trend analysis
  - Anomaly highlighting

- **Traffic Heatmap**
  - Protocol transition matrix
  - Traffic flow visualization
  - Pattern recognition

- **Statistical Summary**
  - Key metrics display
  - Performance indicators
  - Analysis results

### Interactive Features
- **Double-click Packet Details**
  - Detailed packet analysis
  - Raw packet data
  - Header information

- **Real-time Updates**
  - Live data visualization
  - Dynamic chart updates
  - Continuous analysis

## 💾 Data Export

### Export Formats
- **CSV Export**
  - Packet data in CSV format
  - Statistical summaries
  - Analysis results

- **JSON Export**
  - Structured data export
  - Analysis metadata
  - Configuration settings

- **Chart Export (PNG)**
  - High-resolution charts
  - Scientific publication quality
  - Multiple chart formats

- **Report Generation**
  - Comprehensive analysis reports
  - Statistical summaries
  - Recommendations

## 🛠️ Troubleshooting

### Common Issues

#### Permission Errors
```
❌ ERROR: Permission denied. This tool requires administrator/root privileges.
```
**Solution:** Run with elevated privileges:
- Windows: Run as Administrator
- Linux/Mac: Use `sudo python packet_analyzer_gui.py`

#### GUI Not Starting
```
❌ ERROR: Tkinter not available
```
**Solution:** Install tkinter:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# CentOS/RHEL
sudo yum install tkinter

# macOS
brew install python-tk
```

#### Missing Dependencies
```
❌ ERROR: Module not found
```
**Solution:** Install scientific dependencies:
```bash
pip install -r requirements_gui.txt
```

#### No Packets Captured
- Ensure you have network activity
- Try different interfaces
- Check firewall settings
- Verify you have permission to capture

## 🔬 Advanced Usage

### Scientific Analysis Module
```python
from scientific_analysis import ScientificNetworkAnalyzer

# Create analyzer
analyzer = ScientificNetworkAnalyzer()

# Add packet data
analyzer.add_packet_data(packet_info)

# Generate comprehensive report
report = analyzer.generate_network_report()

# Create visualizations
analyzer.create_visualizations('analysis_charts.png')

# Export scientific data
analyzer.export_scientific_data('analysis_report.json')
```

### Custom Analysis
```python
# Custom anomaly detection
anomalies = analyzer.detect_anomalies()

# Traffic pattern analysis
patterns = analyzer.analyze_traffic_patterns()

# Performance metrics
metrics = analyzer.calculate_performance_metrics()
```

## 📚 Learning Resources

### Scientific Analysis
- [Network Traffic Analysis](https://en.wikipedia.org/wiki/Network_traffic_analysis)
- [Statistical Analysis](https://en.wikipedia.org/wiki/Statistical_analysis)
- [Anomaly Detection](https://en.wikipedia.org/wiki/Anomaly_detection)

### Visualization Libraries
- [Matplotlib Documentation](https://matplotlib.org/)
- [Seaborn Documentation](https://seaborn.pydata.org/)
- [Pandas Documentation](https://pandas.pydata.org/)

### Network Analysis
- [Wireshark](https://www.wireshark.org/) - Professional packet analyzer
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) - Network forensic tool

## 🤝 Contributing

This scientific tool welcomes contributions that improve:
- Scientific analysis algorithms
- Visualization capabilities
- Statistical analysis methods
- Educational value
- Code quality and documentation

## 📄 License

This project is for educational and research purposes. Please use responsibly and ethically.

## ⚡ Quick Start

1. **Setup Scientific GUI:**
   ```bash
   python setup_gui.py
   ```

2. **Run Scientific Analysis:**
   ```bash
   python packet_analyzer_gui.py
   ```

3. **Advanced Analysis:**
   ```bash
   python scientific_analysis.py
   ```

4. **Export Results:**
   - Use the Export tab in the GUI
   - Generate scientific reports
   - Save visualizations

---

**🔬 Remember: This scientific tool is for EDUCATIONAL AND RESEARCH PURPOSES ONLY. Use ethically and responsibly!** 
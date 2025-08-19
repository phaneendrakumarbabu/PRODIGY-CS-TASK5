#!/usr/bin/env python3
"""
Scientific Network Analysis Module
=================================

Advanced scientific analysis tools for network packet data including:
- Statistical analysis
- Anomaly detection
- Traffic pattern analysis
- Network behavior modeling
- Performance metrics calculation

ETHICAL USE WARNING:
- Only use on networks you own or have permission to analyze
- This module is for educational and research purposes only
"""

import numpy as np
import pandas as pd
from scipy import stats
from scipy.signal import find_peaks
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, deque
import datetime
import json
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class ScientificNetworkAnalyzer:
    def __init__(self):
        """Initialize the scientific network analyzer."""
        self.packet_data = []
        self.analysis_results = {}
        self.anomaly_threshold = 2.0  # Standard deviations for anomaly detection
        
    def add_packet_data(self, packet_info):
        """Add packet data for analysis."""
        self.packet_data.append(packet_info)
    
    def get_basic_statistics(self):
        """Calculate basic statistical measures."""
        if not self.packet_data:
            return {}
        
        lengths = [p['length'] for p in self.packet_data]
        protocols = [p['protocol'] for p in self.packet_data]
        
        stats = {
            'total_packets': len(self.packet_data),
            'unique_protocols': len(set(protocols)),
            'protocol_distribution': dict(pd.Series(protocols).value_counts()),
            'packet_length_stats': {
                'mean': np.mean(lengths),
                'median': np.median(lengths),
                'std': np.std(lengths),
                'min': np.min(lengths),
                'max': np.max(lengths),
                'q25': np.percentile(lengths, 25),
                'q75': np.percentile(lengths, 75)
            },
            'total_bytes': sum(lengths),
            'average_packet_size': np.mean(lengths)
        }
        
        return stats
    
    def detect_anomalies(self):
        """Detect anomalous network behavior."""
        if len(self.packet_data) < 10:
            return {"error": "Insufficient data for anomaly detection"}
        
        anomalies = {
            'large_packets': [],
            'unusual_protocols': [],
            'burst_traffic': [],
            'suspicious_patterns': []
        }
        
        # Analyze packet lengths
        lengths = [p['length'] for p in self.packet_data]
        mean_length = np.mean(lengths)
        std_length = np.std(lengths)
        
        for i, packet in enumerate(self.packet_data):
            # Detect unusually large packets
            if packet['length'] > mean_length + (self.anomaly_threshold * std_length):
                anomalies['large_packets'].append({
                    'index': i,
                    'packet': packet,
                    'reason': f"Packet size {packet['length']} bytes exceeds threshold"
                })
        
        # Detect unusual protocols
        protocol_counts = defaultdict(int)
        for packet in self.packet_data:
            protocol_counts[packet['protocol']] += 1
        
        total_packets = len(self.packet_data)
        for protocol, count in protocol_counts.items():
            if count / total_packets < 0.01:  # Less than 1% of traffic
                anomalies['unusual_protocols'].append({
                    'protocol': protocol,
                    'count': count,
                    'percentage': (count / total_packets) * 100
                })
        
        # Detect traffic bursts
        if len(self.packet_data) > 20:
            time_series = self._create_time_series()
            burst_indices = self._detect_bursts(time_series)
            anomalies['burst_traffic'] = burst_indices
        
        return anomalies
    
    def _create_time_series(self):
        """Create time series data for analysis."""
        timestamps = []
        for packet in self.packet_data:
            try:
                # Convert timestamp to seconds
                time_obj = datetime.datetime.strptime(packet['timestamp'], '%H:%M:%S.%f')
                seconds = time_obj.hour * 3600 + time_obj.minute * 60 + time_obj.second + time_obj.microsecond / 1000000
                timestamps.append(seconds)
            except:
                timestamps.append(len(timestamps))  # Fallback to index
        
        return timestamps
    
    def _detect_bursts(self, time_series, window_size=5):
        """Detect traffic bursts using sliding window analysis."""
        if len(time_series) < window_size * 2:
            return []
        
        bursts = []
        for i in range(len(time_series) - window_size + 1):
            window = time_series[i:i + window_size]
            window_mean = np.mean(window)
            window_std = np.std(window)
            
            # Check if this window has unusually high activity
            if window_std > np.mean(time_series) + np.std(time_series):
                bursts.append({
                    'start_index': i,
                    'end_index': i + window_size,
                    'intensity': window_std,
                    'time_range': f"{time_series[i]:.2f}s - {time_series[i + window_size - 1]:.2f}s"
                })
        
        return bursts
    
    def analyze_traffic_patterns(self):
        """Analyze traffic patterns and trends."""
        if len(self.packet_data) < 10:
            return {"error": "Insufficient data for pattern analysis"}
        
        patterns = {
            'protocol_trends': {},
            'size_distribution': {},
            'temporal_patterns': {},
            'correlation_analysis': {}
        }
        
        # Protocol trends over time
        protocols_over_time = []
        for packet in self.packet_data:
            protocols_over_time.append(packet['protocol'])
        
        # Calculate protocol transition probabilities
        protocol_transitions = defaultdict(lambda: defaultdict(int))
        for i in range(len(protocols_over_time) - 1):
            current = protocols_over_time[i]
            next_protocol = protocols_over_time[i + 1]
            protocol_transitions[current][next_protocol] += 1
        
        patterns['protocol_trends'] = dict(protocol_transitions)
        
        # Size distribution analysis
        lengths = [p['length'] for p in self.packet_data]
        patterns['size_distribution'] = {
            'histogram_bins': np.histogram(lengths, bins=20)[0].tolist(),
            'percentiles': {
                '10th': np.percentile(lengths, 10),
                '25th': np.percentile(lengths, 25),
                '50th': np.percentile(lengths, 50),
                '75th': np.percentile(lengths, 75),
                '90th': np.percentile(lengths, 90)
            }
        }
        
        # Temporal patterns
        time_series = self._create_time_series()
        if len(time_series) > 1:
            intervals = np.diff(time_series)
            patterns['temporal_patterns'] = {
                'mean_interval': np.mean(intervals),
                'interval_std': np.std(intervals),
                'min_interval': np.min(intervals),
                'max_interval': np.max(intervals)
            }
        
        return patterns
    
    def calculate_performance_metrics(self):
        """Calculate network performance metrics."""
        if not self.packet_data:
            return {}
        
        metrics = {
            'throughput': {},
            'latency_estimates': {},
            'efficiency_metrics': {},
            'quality_indicators': {}
        }
        
        # Calculate throughput
        total_bytes = sum(p['length'] for p in self.packet_data)
        if len(self.packet_data) > 1:
            time_series = self._create_time_series()
            duration = time_series[-1] - time_series[0]
            if duration > 0:
                throughput_bps = (total_bytes * 8) / duration  # bits per second
                metrics['throughput'] = {
                    'bits_per_second': throughput_bps,
                    'kilobits_per_second': throughput_bps / 1000,
                    'megabits_per_second': throughput_bps / 1000000,
                    'bytes_per_second': total_bytes / duration,
                    'packets_per_second': len(self.packet_data) / duration
                }
        
        # Efficiency metrics
        protocols = [p['protocol'] for p in self.packet_data]
        protocol_efficiency = {}
        for protocol in set(protocols):
            protocol_packets = [p for p in self.packet_data if p['protocol'] == protocol]
            avg_size = np.mean([p['length'] for p in protocol_packets])
            protocol_efficiency[protocol] = {
                'average_size': avg_size,
                'packet_count': len(protocol_packets),
                'total_bytes': sum(p['length'] for p in protocol_packets)
            }
        
        metrics['efficiency_metrics'] = protocol_efficiency
        
        return metrics
    
    def generate_network_report(self):
        """Generate a comprehensive network analysis report."""
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'analysis_summary': {},
            'statistics': {},
            'anomalies': {},
            'patterns': {},
            'performance': {},
            'recommendations': []
        }
        
        # Basic statistics
        report['statistics'] = self.get_basic_statistics()
        
        # Anomaly detection
        report['anomalies'] = self.detect_anomalies()
        
        # Pattern analysis
        report['patterns'] = self.analyze_traffic_patterns()
        
        # Performance metrics
        report['performance'] = self.calculate_performance_metrics()
        
        # Generate recommendations
        recommendations = []
        
        if report['anomalies']['large_packets']:
            recommendations.append({
                'type': 'warning',
                'message': f"Detected {len(report['anomalies']['large_packets'])} unusually large packets",
                'action': 'Investigate large packet sources and destinations'
            })
        
        if report['anomalies']['unusual_protocols']:
            recommendations.append({
                'type': 'info',
                'message': f"Found {len(report['anomalies']['unusual_protocols'])} unusual protocols",
                'action': 'Review unusual protocol usage'
            })
        
        if 'throughput' in report['performance']:
            throughput = report['performance']['throughput']
            if throughput.get('megabits_per_second', 0) > 100:
                recommendations.append({
                    'type': 'success',
                    'message': 'High network throughput detected',
                    'action': 'Network performance is good'
                })
        
        report['recommendations'] = recommendations
        
        return report
    
    def create_visualizations(self, save_path=None):
        """Create scientific visualizations of the network data."""
        if not self.packet_data:
            return {"error": "No data available for visualization"}
        
        # Create figure with subplots
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        fig.suptitle('Scientific Network Analysis', fontsize=16)
        
        # 1. Packet size distribution
        lengths = [p['length'] for p in self.packet_data]
        axes[0, 0].hist(lengths, bins=30, alpha=0.7, color='blue', edgecolor='black')
        axes[0, 0].set_title('Packet Size Distribution')
        axes[0, 0].set_xlabel('Packet Size (bytes)')
        axes[0, 0].set_ylabel('Frequency')
        
        # 2. Protocol distribution
        protocols = [p['protocol'] for p in self.packet_data]
        protocol_counts = pd.Series(protocols).value_counts()
        axes[0, 1].pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%')
        axes[0, 1].set_title('Protocol Distribution')
        
        # 3. Time series of packet sizes
        time_series = self._create_time_series()
        if len(time_series) > 1:
            axes[0, 2].scatter(time_series, lengths, alpha=0.6, s=20)
            axes[0, 2].set_title('Packet Size Over Time')
            axes[0, 2].set_xlabel('Time (seconds)')
            axes[0, 2].set_ylabel('Packet Size (bytes)')
        
        # 4. Cumulative bytes over time
        if len(time_series) > 1:
            cumulative_bytes = np.cumsum(lengths)
            axes[1, 0].plot(time_series, cumulative_bytes, 'g-', linewidth=2)
            axes[1, 0].set_title('Cumulative Bytes Over Time')
            axes[1, 0].set_xlabel('Time (seconds)')
            axes[1, 0].set_ylabel('Cumulative Bytes')
        
        # 5. Protocol transition matrix (heatmap)
        if len(set(protocols)) > 1:
            protocol_transitions = self.analyze_traffic_patterns()['protocol_trends']
            if protocol_transitions:
                # Create transition matrix
                unique_protocols = list(set(protocols))
                transition_matrix = np.zeros((len(unique_protocols), len(unique_protocols)))
                
                for i, protocol1 in enumerate(unique_protocols):
                    for j, protocol2 in enumerate(unique_protocols):
                        if protocol1 in protocol_transitions:
                            transition_matrix[i, j] = protocol_transitions[protocol1].get(protocol2, 0)
                
                im = axes[1, 1].imshow(transition_matrix, cmap='YlOrRd')
                axes[1, 1].set_title('Protocol Transition Matrix')
                axes[1, 1].set_xticks(range(len(unique_protocols)))
                axes[1, 1].set_yticks(range(len(unique_protocols)))
                axes[1, 1].set_xticklabels(unique_protocols, rotation=45)
                axes[1, 1].set_yticklabels(unique_protocols)
                plt.colorbar(im, ax=axes[1, 1])
        
        # 6. Statistical summary
        stats = self.get_basic_statistics()
        if stats:
            stats_text = f"""
Statistics Summary:
Total Packets: {stats.get('total_packets', 0)}
Total Bytes: {stats.get('total_bytes', 0):,}
Mean Packet Size: {stats.get('packet_length_stats', {}).get('mean', 0):.1f} bytes
Protocols: {stats.get('unique_protocols', 0)}
            """
            axes[1, 2].text(0.1, 0.5, stats_text, transform=axes[1, 2].transAxes, 
                           fontsize=10, verticalalignment='center',
                           bbox=dict(boxstyle="round,pad=0.3", facecolor="lightblue"))
            axes[1, 2].set_title('Statistical Summary')
            axes[1, 2].axis('off')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        
        return fig
    
    def export_scientific_data(self, filename):
        """Export scientific analysis data."""
        report = self.generate_network_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename

def main():
    """Example usage of the scientific analyzer."""
    analyzer = ScientificNetworkAnalyzer()
    
    # Example packet data
    sample_packets = [
        {'timestamp': '14:30:25.123', 'protocol': 'TCP', 'length': 1500, 'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8'},
        {'timestamp': '14:30:25.124', 'protocol': 'TCP', 'length': 1500, 'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.100'},
        {'timestamp': '14:30:25.125', 'protocol': 'UDP', 'length': 512, 'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8'},
        {'timestamp': '14:30:25.126', 'protocol': 'ICMP', 'length': 64, 'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8'},
    ]
    
    for packet in sample_packets:
        analyzer.add_packet_data(packet)
    
    # Generate analysis
    report = analyzer.generate_network_report()
    print("Scientific Network Analysis Report:")
    print(json.dumps(report, indent=2, default=str))
    
    # Create visualizations
    analyzer.create_visualizations()

if __name__ == "__main__":
    main() 
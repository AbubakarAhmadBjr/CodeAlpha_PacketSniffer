"""
Packet logger - saves captured packets to files in various formats.
"""

import json
import csv
import os
from datetime import datetime


class PacketLogger:
    """
    Log captured packets to files.
    
    Supports:
    - JSON format (detailed)
    - CSV format (tabular)
    - Plain text format (human readable)
    """

    def __init__(self, log_dir: str = 'captures'):
        self.log_dir = log_dir
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        self._ensure_log_dir()

        # Log file paths
        self.json_file = os.path.join(
            log_dir, f'capture_{self.session_id}.json')
        self.csv_file = os.path.join(log_dir, f'capture_{self.session_id}.csv')
        self.txt_file = os.path.join(log_dir, f'capture_{self.session_id}.txt')

        self.packet_buffer = []
        self.buffer_size = 50  # Write to disk every 50 packets

        # Initialize CSV file with headers
        self._init_csv()

    def _ensure_log_dir(self):
        """Create log directory if it doesn't exist."""
        os.makedirs(self.log_dir, exist_ok=True)

    def _init_csv(self):
        """Initialize CSV file with header row."""
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp', 'protocol', 'src_ip', 'dst_ip',
                'src_port', 'dst_port', 'service', 'size',
                'flags', 'payload', 'summary'
            ])
            writer.writeheader()

    def log_packet(self, packet_info: dict):
        """
        Log a single packet.
        
        Args:
            packet_info: Packet information dictionary
        """
        self.packet_buffer.append(packet_info)

        # Write text log immediately
        self._append_text_log(packet_info)

        # Batch write other formats
        if len(self.packet_buffer) >= self.buffer_size:
            self.flush()

    def _append_text_log(self, packet_info: dict):
        """Append packet info to text log file."""
        with open(self.txt_file, 'a') as f:
            timestamp = packet_info.get('timestamp', '')
            protocol = packet_info.get('protocol', 'Unknown')
            src = f"{packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', '')}"
            dst = f"{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', '')}"
            size = packet_info.get('size', 0)
            payload = packet_info.get('payload', '')

            f.write(
                f"[{timestamp}] {protocol:>6} | {src:<30} → {dst:<30} | {size:>6}B")
            if payload:
                f.write(f" | {payload[:100]}")
            f.write('\n')

    def flush(self):
        """Write buffered packets to JSON and CSV files."""
        if not self.packet_buffer:
            return

        # Write to JSON (append mode with proper array handling)
        try:
            existing = []
            if os.path.exists(self.json_file):
                with open(self.json_file, 'r') as f:
                    try:
                        existing = json.load(f)
                    except json.JSONDecodeError:
                        existing = []

            # Convert non-serializable objects
            serializable_packets = []
            for pkt in self.packet_buffer:
                clean_pkt = {}
                for k, v in pkt.items():
                    if isinstance(v, bytes):
                        clean_pkt[k] = v.hex()
                    elif isinstance(v, set):
                        clean_pkt[k] = list(v)
                    else:
                        clean_pkt[k] = v
                serializable_packets.append(clean_pkt)

            existing.extend(serializable_packets)
            with open(self.json_file, 'w') as f:
                json.dump(existing, f, indent=2, default=str)
        except Exception as e:
            print(f"JSON log error: {e}")

        # Write to CSV
        try:
            with open(self.csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp', 'protocol', 'src_ip', 'dst_ip',
                    'src_port', 'dst_port', 'service', 'size',
                    'flags', 'payload', 'summary'
                ])
                for pkt in self.packet_buffer:
                    row = {
                        'timestamp': pkt.get('timestamp', ''),
                        'protocol': pkt.get('protocol', ''),
                        'src_ip': pkt.get('src_ip', ''),
                        'dst_ip': pkt.get('dst_ip', ''),
                        'src_port': pkt.get('src_port', ''),
                        'dst_port': pkt.get('dst_port', ''),
                        'service': pkt.get('service', ''),
                        'size': pkt.get('size', 0),
                        'flags': ','.join(pkt.get('flags', []) or []),
                        'payload': str(pkt.get('payload', ''))[:200],
                        'summary': pkt.get('summary', ''),
                    }
                    writer.writerow(row)
        except Exception as e:
            print(f"CSV log error: {e}")

        self.packet_buffer.clear()

    def get_log_files(self) -> dict:
        """Get paths to all log files."""
        return {
            'json': self.json_file,
            'csv': self.csv_file,
            'text': self.txt_file
        }

    def __del__(self):
        """Flush remaining packets on cleanup."""
        try:
            self.flush()
        except Exception:
            pass

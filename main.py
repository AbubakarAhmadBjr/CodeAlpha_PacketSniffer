#!/usr/bin/env python3
"""
Network Packet Analyzer - Main Entry Point

Usage:
    sudo python3 main.py                           # Capture all traffic
    sudo python3 main.py --interface eth0          # Specific interface
    sudo python3 main.py --filter "tcp port 80"    # Filter HTTP
    sudo python3 main.py --count 100               # Capture 100 packets
    sudo python3 main.py --verbose                 # Detailed output
    sudo python3 main.py --mode http               # HTTP traffic only
    sudo python3 main.py --mode dns                # DNS traffic only
    sudo python3 main.py --log                     # Save to files
    sudo python3 main.py --list-interfaces         # Show interfaces

IMPORTANT: Requires root/administrator privileges!
"""

import argparse
import sys
import signal
import threading
import time
from colorama import Fore, Style, init
try:
    from tabulate import tabulate
except Exception:
    # Minimal fallback if 'tabulate' is not installed: simple table formatter
    def tabulate(rows, headers=None, tablefmt=None):
        out = []
        if headers:
            out.append(' | '.join(map(str, headers)))
            out.append('-' * (len(out[0])))
        for r in rows:
            out.append(' | '.join(map(str, r)))
        return '\n'.join(out)

from packet_analyzer import PacketAnalyzer
from packet_display import display_packet, display_statistics, display_header, display_interfaces
from packet_filter import PacketFilter
from packet_logger import PacketLogger
from protocol_analyzer import ConnectionTracker, DNSTracker

init(autoreset=True)


# ── Preset Capture Modes ──────────────────────────────────────────────────────
CAPTURE_MODES = {
    'all':   {'filter': None,                   'description': 'All traffic'},
    'http':  {'filter': 'tcp port 80',          'description': 'HTTP only'},
    'https': {'filter': 'tcp port 443',         'description': 'HTTPS only'},
    'dns':   {'filter': 'udp port 53',          'description': 'DNS only'},
    'icmp':  {'filter': 'icmp',                 'description': 'ICMP/Ping only'},
    'arp':   {'filter': 'arp',                  'description': 'ARP only'},
    'ssh':   {'filter': 'tcp port 22',          'description': 'SSH only'},
    'tcp':   {'filter': 'tcp',                  'description': 'All TCP'},
    'udp':   {'filter': 'udp',                  'description': 'All UDP'},
    'web':   {'filter': 'tcp port 80 or tcp port 443', 'description': 'All web traffic'},
}


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='🔍 Network Traffic Packet Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py
  sudo python3 main.py --interface eth0 --mode http --verbose
  sudo python3 main.py --filter "host 192.168.1.1 and tcp" --count 50
  sudo python3 main.py --mode dns --log --timeout 60
        """
    )

    parser.add_argument('--interface', '-i',
                        help='Network interface to capture on')
    parser.add_argument('--filter', '-f',
                        help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument('--count', '-c', type=int, default=0,
                        help='Number of packets to capture (0=unlimited)')
    parser.add_argument('--timeout', '-t', type=int,
                        help='Capture timeout in seconds')
    parser.add_argument('--mode', '-m', choices=CAPTURE_MODES.keys(), default='all',
                        help='Capture mode preset')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed packet information')
    parser.add_argument('--log', '-l', action='store_true',
                        help='Save packets to log files')
    parser.add_argument('--log-dir', default='captures',
                        help='Directory for log files (default: captures/)')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='List available network interfaces and exit')
    parser.add_argument('--stats-interval', type=int, default=30,
                        help='Display statistics every N seconds (0=disabled)')
    parser.add_argument('--connections', action='store_true',
                        help='Track and display TCP connections')

    return parser.parse_args()


class NetworkAnalyzerApp:
    """Main application orchestrating capture, analysis, and display."""

    def __init__(self, args):
        self.args = args
        self.packet_count = 0
        self.analyzer = None
        self.logger = None
        self.connection_tracker = ConnectionTracker() if args.connections else None
        self.dns_tracker = DNSTracker()
        self._running = True
        self._stats_thread = None

    def setup(self) -> str:
        """Configure the analyzer and determine the filter string."""
        # Determine filter
        filter_string = None
        if self.args.filter:
            filter_string = self.args.filter
        elif self.args.mode != 'all':
            filter_string = CAPTURE_MODES[self.args.mode]['filter']

        # Build analyzer
        self.analyzer = PacketAnalyzer(
            interface=self.args.interface,
            packet_count=self.args.count,
            timeout=self.args.timeout
        )

        # Add display callback
        self.analyzer.add_callback(self._on_packet)

        # Setup logger if requested
        if self.args.log:
            self.logger = PacketLogger(log_dir=self.args.log_dir)
            self.analyzer.add_callback(self.logger.log_packet)
            print(
                f"{Fore.GREEN}  📁 Logging to: {self.logger.get_log_files()}{Style.RESET_ALL}")

        return filter_string

    def _on_packet(self, packet_info: dict):
        """Callback invoked for each captured packet."""
        self.packet_count += 1

        # Display packet
        display_packet(packet_info, verbose=self.args.verbose,
                       packet_number=self.packet_count)

        # Update protocol trackers
        self.dns_tracker.update(packet_info)
        if self.connection_tracker:
            self.connection_tracker.update(packet_info)

    def _stats_worker(self):
        """Background thread that periodically prints statistics."""
        interval = self.args.stats_interval
        if interval <= 0:
            return

        while self._running:
            time.sleep(interval)
            if self._running and self.analyzer:
                stats = self.analyzer.get_statistics()
                print(
                    f"\n{Fore.LIGHTBLACK_EX}[Auto-Stats @ {interval}s interval]{Style.RESET_ALL}")
                display_statistics(stats)

    def _setup_signal_handler(self):
        """Handle Ctrl+C gracefully."""
        def handler(sig, frame):
            self._running = False
            if self.analyzer:
                self.analyzer.stop_capture()
        signal.signal(signal.SIGINT, handler)

    def display_column_headers(self):
        """Print column headers for compact display mode."""
        if not self.args.verbose:
            print(
                f"{Fore.LIGHTBLACK_EX}"
                f"{'#':<5} {'Timestamp':<23} {'Protocol':>8}  "
                f"{'Source':<25}   {'Destination':<25}  {'Size':>8}  Flags"
                f"{Style.RESET_ALL}"
            )
            print(f"{Fore.LIGHTBLACK_EX}{'─'*110}{Style.RESET_ALL}")

    def run(self):
        """Main application entry point."""
        display_header()

        # Just list interfaces and exit
        if self.args.list_interfaces:
            display_interfaces()
            return

        # Setup
        filter_string = self.setup()

        # Display mode info
        mode_info = CAPTURE_MODES.get(self.args.mode, {})
        print(
            f"{Fore.BLUE}  Mode: {mode_info.get('description', 'Custom')}{Style.RESET_ALL}")

        # Column headers
        self.display_column_headers()

        # Start stats thread
        if self.args.stats_interval > 0:
            self._stats_thread = threading.Thread(
                target=self._stats_worker, daemon=True
            )
            self._stats_thread.start()

        # Setup signal handler
        self._setup_signal_handler()

        # Start capture (blocking)
        self.analyzer.start_capture(filter_string=filter_string)

        # ── Post-capture output ──────────────────────────────────
        self._running = False
        self._show_final_report()

    def _show_final_report(self):
        """Display the final capture report."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  📋 FINAL CAPTURE REPORT")
        print(f"{'='*60}{Style.RESET_ALL}")

        # Statistics
        if self.analyzer:
            stats = self.analyzer.get_statistics()
            display_statistics(stats)

        # DNS Summary
        self.dns_tracker.display_summary()

        # TCP Connections
        if self.connection_tracker:
            connections = self.connection_tracker.get_all_connections()
            if connections:
                print(f"\n{Fore.CYAN}  TCP Connections Tracked:{Style.RESET_ALL}")
                conn_table = [
                    [
                        c['src_ip'], c['src_port'],
                        c['dst_ip'], c['dst_port'],
                        c.get('service', ''),
                        c['state'], c['packets'],
                        c['bytes']
                    ]
                    for c in connections[:20]  # Show top 20
                ]
                print(tabulate(conn_table,
                               headers=['Src IP', 'Sport', 'Dst IP', 'Dport',
                                        'Service', 'State', 'Pkts', 'Bytes'],
                               tablefmt='simple'))

        # Log file locations
        if self.logger:
            self.logger.flush()
            print(f"\n{Fore.GREEN}  📁 Log Files Saved:{Style.RESET_ALL}")
            for fmt, path in self.logger.get_log_files().items():
                print(f"    {fmt.upper()}: {path}")

        print(
            f"\n{Fore.CYAN}  ✅ Capture complete. Total packets: {self.packet_count}{Style.RESET_ALL}")


def main():
    """Application entry point."""
    args = parse_arguments()

    # Check for root privileges on Linux/Mac
    import os
    if os.name != 'nt' and os.geteuid() != 0:
        print(f"\n{Fore.RED}❌ Error: Root privileges required!")
        print(f"{Fore.YELLOW}   Run: sudo python3 main.py{Style.RESET_ALL}\n")
        sys.exit(1)

    app = NetworkAnalyzerApp(args)
    app.run()


if __name__ == '__main__':
    main()

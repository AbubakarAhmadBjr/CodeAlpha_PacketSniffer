"""
Core packet analysis engine using Scapy.
Captures and analyzes network traffic packets.
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
try:
    from scapy.all import (  # type: ignore[import]
        sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        ARP, DNS, DNSQR, DNSRR, Raw, Ether,
        get_if_list, conf
    )
    # type: ignore[import]
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError as exc:
    raise ImportError(
        "Scapy is required to run packet_analyzer.py. Install it with "
        "'pip install scapy'."
    ) from exc
from colorama import Fore, Back, Style, init

init(autoreset=True)


class PacketStatistics:
    """Track packet statistics across the capture session."""

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.destination_ips = defaultdict(int)
        self.port_activity = defaultdict(int)
        self.start_time = time.time()
        self.lock = threading.Lock()

    def update(self, packet_info: dict):
        """Thread-safe statistics update."""
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet_info.get('size', 0)
            self.protocol_counts[packet_info.get('protocol', 'Unknown')] += 1

            if packet_info.get('src_ip'):
                self.source_ips[packet_info['src_ip']] += 1
            if packet_info.get('dst_ip'):
                self.destination_ips[packet_info['dst_ip']] += 1
            if packet_info.get('dst_port'):
                self.port_activity[packet_info['dst_port']] += 1

    def get_summary(self) -> dict:
        """Get current statistics summary."""
        elapsed = time.time() - self.start_time
        with self.lock:
            return {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'elapsed_time': round(elapsed, 2),
                'packets_per_second': round(self.total_packets / elapsed, 2) if elapsed > 0 else 0,
                'protocol_counts': dict(self.protocol_counts),
                'top_sources': sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:5],
                'top_destinations': sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:5],
                'top_ports': sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:5],
            }


class PacketAnalyzer:
    """
    Main packet analyzer class that captures and processes network packets.

    Features:
    - Real-time packet capture
    - Protocol identification (TCP, UDP, ICMP, DNS, HTTP, ARP)
    - Payload extraction and display
    - Statistics tracking
    - Filtering support
    """

    # Well-known port mappings
    PORT_SERVICES = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client',
        69: 'TFTP', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        161: 'SNMP', 194: 'IRC', 443: 'HTTPS', 445: 'SMB',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }

    def __init__(self, interface=None, packet_count=0, timeout=None):
        """
        Initialize the PacketAnalyzer.

        Args:
            interface: Network interface to capture on (None = default)
            packet_count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds (None = no timeout)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout
        self.statistics = PacketStatistics()
        self.captured_packets = []
        self.callbacks = []
        self._stop_event = threading.Event()

    def add_callback(self, callback):
        """Add a callback function to be called for each packet."""
        self.callbacks.append(callback)

    def analyze_packet(self, packet) -> dict:
        """
        Comprehensive packet analysis.

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary containing packet information
        """
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'service': None,
            'flags': None,
            'ttl': None,
            'payload': None,
            'summary': packet.summary(),
            'layers': self._get_layers(packet),
        }

        # ── Ethernet Layer ──────────────────────────────────────
        if packet.haslayer(Ether):
            eth = packet[Ether]
            packet_info['src_mac'] = eth.src
            packet_info['dst_mac'] = eth.dst

        # ── ARP Layer ───────────────────────────────────────────
        if packet.haslayer(ARP):
            self._analyze_arp(packet, packet_info)

        # ── IPv4 Layer ──────────────────────────────────────────
        elif packet.haslayer(IP):
            self._analyze_ip(packet, packet_info)

        # ── IPv6 Layer ──────────────────────────────────────────
        elif packet.haslayer(IPv6):
            self._analyze_ipv6(packet, packet_info)

        return packet_info

    def _get_layers(self, packet) -> list:
        """Extract all protocol layers from a packet."""
        layers = []
        current = packet
        while current:
            layers.append(current.__class__.__name__)
            current = current.payload if current.payload else None
            if current and current.__class__.__name__ == 'NoPayload':
                break
        return layers

    def _analyze_arp(self, packet, info: dict):
        """Analyze ARP packets."""
        arp = packet[ARP]
        info['protocol'] = 'ARP'
        info['src_ip'] = arp.psrc
        info['dst_ip'] = arp.pdst

        operation_map = {1: 'ARP Request', 2: 'ARP Reply'}
        info['arp_operation'] = operation_map.get(
            arp.op, f'Unknown ({arp.op})')
        info['src_mac'] = arp.hwsrc
        info['dst_mac'] = arp.hwdst

        if arp.op == 1:
            info['payload'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            info['payload'] = f"{arp.psrc} is at {arp.hwsrc}"

    def _analyze_ip(self, packet, info: dict):
        """Analyze IPv4 packets and their transport layer."""
        ip = packet[IP]
        info['src_ip'] = ip.src
        info['dst_ip'] = ip.dst
        info['ttl'] = ip.ttl
        info['ip_version'] = 4
        info['ip_id'] = ip.id
        info['ip_flags'] = str(ip.flags)
        info['protocol'] = 'IPv4'

        # ── TCP ─────────────────────────────────────────────────
        if packet.haslayer(TCP):
            self._analyze_tcp(packet, info)

        # ── UDP ─────────────────────────────────────────────────
        elif packet.haslayer(UDP):
            self._analyze_udp(packet, info)

        # ── ICMP ────────────────────────────────────────────────
        elif packet.haslayer(ICMP):
            self._analyze_icmp(packet, info)

    def _analyze_ipv6(self, packet, info: dict):
        """Analyze IPv6 packets."""
        ipv6 = packet[IPv6]
        info['src_ip'] = ipv6.src
        info['dst_ip'] = ipv6.dst
        info['ip_version'] = 6
        info['protocol'] = 'IPv6'

        if packet.haslayer(TCP):
            self._analyze_tcp(packet, info)
        elif packet.haslayer(UDP):
            self._analyze_udp(packet, info)

    def _analyze_tcp(self, packet, info: dict):
        """Analyze TCP segment details."""
        tcp = packet[TCP]
        info['protocol'] = 'TCP'
        info['src_port'] = tcp.sport
        info['dst_port'] = tcp.dport
        info['service'] = self.PORT_SERVICES.get(tcp.dport) or \
            self.PORT_SERVICES.get(tcp.sport, '')
        info['seq'] = tcp.seq
        info['ack'] = tcp.ack
        info['window'] = tcp.window

        # Parse TCP flags
        flags = []
        flag_map = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST',
            'P': 'PSH', 'A': 'ACK', 'U': 'URG',
            'E': 'ECE', 'C': 'CWR'
        }
        for flag_char, flag_name in flag_map.items():
            if flag_char in str(tcp.flags):
                flags.append(flag_name)
        info['flags'] = flags

        # HTTP Analysis
        if packet.haslayer(HTTPRequest):
            self._analyze_http_request(packet, info)
        elif packet.haslayer(HTTPResponse):
            self._analyze_http_response(packet, info)
        elif packet.haslayer(Raw):
            self._extract_raw_payload(packet, info)

    def _analyze_udp(self, packet, info: dict):
        """Analyze UDP datagram details."""
        udp = packet[UDP]
        info['protocol'] = 'UDP'
        info['src_port'] = udp.sport
        info['dst_port'] = udp.dport
        info['service'] = self.PORT_SERVICES.get(udp.dport) or \
            self.PORT_SERVICES.get(udp.sport, '')
        info['length'] = udp.len

        # DNS Analysis
        if packet.haslayer(DNS):
            self._analyze_dns(packet, info)
        elif packet.haslayer(Raw):
            self._extract_raw_payload(packet, info)

    def _analyze_icmp(self, packet, info: dict):
        """Analyze ICMP messages."""
        icmp = packet[ICMP]
        info['protocol'] = 'ICMP'

        icmp_types = {
            0: 'Echo Reply', 3: 'Destination Unreachable',
            4: 'Source Quench', 5: 'Redirect',
            8: 'Echo Request', 11: 'Time Exceeded',
            12: 'Parameter Problem', 13: 'Timestamp Request',
            14: 'Timestamp Reply'
        }
        info['icmp_type'] = icmp_types.get(icmp.type, f'Type {icmp.type}')
        info['icmp_code'] = icmp.code
        info['icmp_id'] = icmp.id if hasattr(icmp, 'id') else None
        info['icmp_seq'] = icmp.seq if hasattr(icmp, 'seq') else None
        info['payload'] = f"{info['icmp_type']} (code={icmp.code})"

    def _analyze_dns(self, packet, info: dict):
        """Analyze DNS query and response packets – improved edge‑case handling."""
        dns = packet[DNS]
        info['protocol'] = 'DNS'

        # Safely extract query name
        query_name = ""
        if dns.qd:
            try:
                raw_name = dns.qd.qname
                if raw_name:
                    query_name = raw_name.decode(
                        'utf-8', errors='replace').rstrip('.')
            except Exception:
                query_name = ""

        if dns.qr == 0:  # Query
            info['dns_type'] = 'Query'
            if query_name:
                qtype_map = {1: 'A', 28: 'AAAA', 5: 'CNAME',
                             15: 'MX', 16: 'TXT', 2: 'NS'}
                qtype_str = qtype_map.get(dns.qd.qtype, f'Type{dns.qd.qtype}')
                info['payload'] = f"DNS Query: {query_name} ({qtype_str})"
                info['dns_query'] = query_name
                info['dns_query_type'] = qtype_str
            else:
                # Fallback for malformed queries
                info['payload'] = f"DNS Query (malformed): type={dns.qd.qtype if dns.qd else '?'}"
        else:  # Response
            info['dns_type'] = 'Response'
            answers = []
            if dns.an:
                current = dns.an
                while current:
                    if hasattr(current, 'rdata'):
                        rdata = current.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode('utf-8', errors='replace')
                        answers.append(str(rdata))
                    current = current.payload if hasattr(
                        current, 'payload') else None
                    if not hasattr(current, 'rdata'):
                        break

            info['payload'] = f"DNS Response: {query_name or '?'} → {', '.join(answers) if answers else 'No answers'}"
            if answers:
                info['dns_answers'] = answers
            if query_name:
                info['dns_query'] = query_name

    def _analyze_http_request(self, packet, info: dict):
        """Analyze HTTP request packets."""
        http = packet[HTTPRequest]
        info['protocol'] = 'HTTP'
        info['http_type'] = 'Request'

        method = http.Method.decode(
            'utf-8', errors='replace') if http.Method else '?'
        host = http.Host.decode(
            'utf-8', errors='replace') if http.Host else '?'
        path = http.Path.decode(
            'utf-8', errors='replace') if http.Path else '/'

        info['payload'] = f"HTTP {method} {host}{path}"
        info['http_method'] = method
        info['http_host'] = host
        info['http_path'] = path

        if http.User_Agent:
            info['http_user_agent'] = http.User_Agent.decode(
                'utf-8', errors='replace')

    def _analyze_http_response(self, packet, info: dict):
        """Analyze HTTP response packets."""
        http = packet[HTTPResponse]
        info['protocol'] = 'HTTP'
        info['http_type'] = 'Response'

        status_code = http.Status_Code.decode(
            'utf-8', errors='replace') if http.Status_Code else '?'
        reason = http.Reason_Phrase.decode(
            'utf-8', errors='replace') if http.Reason_Phrase else ''

        info['payload'] = f"HTTP Response: {status_code} {reason}"
        info['http_status'] = status_code

    def _extract_raw_payload(self, packet, info: dict):
        """Extract and display raw payload data."""
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                decoded = raw_data.decode('utf-8', errors='replace')
                # Limit display length
                if len(decoded) > 200:
                    decoded = decoded[:200] + '...'
                info['payload'] = decoded.replace(
                    '\n', '\\n').replace('\r', '')
                info['raw_bytes'] = raw_data[:32]  # First 32 bytes
            except Exception:
                info['payload'] = f"Binary data ({len(raw_data)} bytes)"
                info['raw_bytes'] = raw_data[:32]

    def packet_callback(self, packet):
        """
        Called for each captured packet by Scapy's sniff function.

        Args:
            packet: Captured Scapy packet
        """
        if self._stop_event.is_set():
            return

        # Analyze the packet
        packet_info = self.analyze_packet(packet)

        # Update statistics
        self.statistics.update(packet_info)

        # Store packet (keep last 1000 to avoid memory issues)
        self.captured_packets.append(packet_info)
        if len(self.captured_packets) > 1000:
            self.captured_packets.pop(0)

        # Execute callbacks
        for callback in self.callbacks:
            try:
                callback(packet_info)
            except Exception as e:
                print(f"{Fore.RED}Callback error: {e}")

    def start_capture(self, filter_string=None):
        """
        Start packet capture.

        Args:
            filter_string: BPF filter string (e.g., 'tcp port 80')
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}  🔍 Network Packet Analyzer Starting...")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}  Interface : {self.interface or 'Default'}")
        print(f"{Fore.GREEN}  Filter    : {filter_string or 'None (capture all)'}")
        print(f"{Fore.GREEN}  Count     : {self.packet_count or 'Unlimited'}")
        print(f"{Fore.GREEN}  Timeout   : {self.timeout or 'None'} seconds")
        print(f"{Fore.CYAN}{'='*60}\n")
        print(f"{Fore.WHITE}  Press Ctrl+C to stop capture\n")

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count,
                timeout=self.timeout,
                filter=filter_string,
                store=False  # Don't store raw packets in memory
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Capture stopped by user")
        except PermissionError:
            print(f"{Fore.RED}❌ Permission denied. Run as root/administrator!")
        except Exception as e:
            print(f"{Fore.RED}❌ Capture error: {e}")

    def stop_capture(self):
        """Signal the capture to stop."""
        self._stop_event.set()

    def get_statistics(self) -> dict:
        """Get capture statistics."""
        return self.statistics.get_summary()

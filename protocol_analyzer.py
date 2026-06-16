"""
Protocol analyzer - provides deep analysis for specific protocols.
"""

from collections import defaultdict
from typing import List, Dict


class ConnectionTracker:
    """
    Track TCP connections (flows) across multiple packets.
    
    A TCP connection is identified by the 4-tuple:
    (src_ip, src_port, dst_ip, dst_port)
    """

    def __init__(self):
        self.connections: Dict[tuple, dict] = {}
        self.completed_connections = []

    def _make_key(self, src_ip, src_port, dst_ip, dst_port) -> tuple:
        """Create a bidirectional connection key."""
        forward = (src_ip, src_port, dst_ip, dst_port)
        reverse = (dst_ip, dst_port, src_ip, src_port)
        return min(forward, reverse)

    def update(self, packet_info: dict):
        """Update connection tracking with a new packet."""
        if packet_info.get('protocol') != 'TCP':
            return

        src_ip = packet_info.get('src_ip')
        src_port = packet_info.get('src_port')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        flags = packet_info.get('flags', [])

        if not all([src_ip, src_port, dst_ip, dst_port]):
            return

        key = self._make_key(src_ip, src_port, dst_ip, dst_port)

        if key not in self.connections:
            self.connections[key] = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'state': 'UNKNOWN',
                'packets': 0,
                'bytes': 0,
                'start_time': packet_info.get('timestamp'),
                'last_seen': packet_info.get('timestamp'),
                'service': packet_info.get('service', ''),
            }

        conn = self.connections[key]
        conn['packets'] += 1
        conn['bytes'] += packet_info.get('size', 0)
        conn['last_seen'] = packet_info.get('timestamp')

        # Update TCP state machine
        self._update_state(conn, flags)

    def _update_state(self, connection: dict, flags: list):
        """Simple TCP state machine tracking."""
        state = connection.get('state', 'UNKNOWN')

        if 'RST' in flags:
            connection['state'] = 'RESET'
        elif state == 'UNKNOWN' and 'SYN' in flags and 'ACK' not in flags:
            connection['state'] = 'SYN_SENT'
        elif state == 'SYN_SENT' and 'SYN' in flags and 'ACK' in flags:
            connection['state'] = 'SYN_RECEIVED'
        elif state == 'SYN_RECEIVED' and 'ACK' in flags:
            connection['state'] = 'ESTABLISHED'
        elif 'FIN' in flags and state == 'ESTABLISHED':
            connection['state'] = 'FIN_WAIT'
        elif 'FIN' in flags and state == 'FIN_WAIT':
            connection['state'] = 'CLOSED'
        elif state == 'UNKNOWN' and 'ACK' in flags:
            connection['state'] = 'ESTABLISHED'

    def get_active_connections(self) -> List[dict]:
        """Get list of active (non-closed) connections."""
        return [
            conn for conn in self.connections.values()
            if conn['state'] not in ('CLOSED', 'RESET')
        ]

    def get_all_connections(self) -> List[dict]:
        """Get all tracked connections."""
        return list(self.connections.values())


class DNSTracker:
    """
    Track DNS queries and responses to build query-response pairs.
    
    Fixed: Normalizes domain names (lowercase, strips trailing dot) to ensure
    queries and responses match correctly.
    """

    def __init__(self):
        self.queries = {}          # normalized_query -> timestamp
        # normalized_query -> list of answer dicts
        self.resolved = defaultdict(list)

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize a DNS name: lowercase and remove trailing dot."""
        if not name:
            return ""
        name = name.lower().strip()
        if name.endswith('.'):
            name = name[:-1]
        return name

    def update(self, packet_info: dict):
        """Process a DNS packet."""
        if packet_info.get('protocol') != 'DNS':
            return

        dns_type = packet_info.get('dns_type')      # 'Query' or 'Response'
        raw_query = packet_info.get('dns_query', '')
        answers = packet_info.get('dns_answers', [])

        # Normalize the query name (if any)
        query = self._normalize_name(raw_query) if raw_query else ""

        if dns_type == 'Query' and query:
            # Store the query timestamp (overwrite if same query appears again)
            self.queries[query] = packet_info.get('timestamp')
        elif dns_type == 'Response' and query:
            # Even if there are no answers, we might still record something?
            # But we only care about successful resolutions (non-empty answers)
            if answers:
                # If we have the corresponding query timestamp, use it; otherwise mark as unknown
                query_time = self.queries.get(query, 'Unknown')
                for answer in answers:
                    # Avoid duplicate entries for the same answer (optional)
                    existing = any(
                        a['ip'] == answer and a['query_time'] == query_time
                        for a in self.resolved[query]
                    )
                    if not existing:
                        self.resolved[query].append({
                            'ip': answer,
                            'timestamp': packet_info.get('timestamp'),
                            'query_time': query_time
                        })
            # Optionally, we could also record that a response was seen even without answers,
            # but that's not a "resolution" per se.
            # If you want to track NXDOMAIN or empty responses, you could add another dict.

    def get_resolved_hosts(self) -> dict:
        """Get dictionary of resolved hostnames (normalized)."""
        return dict(self.resolved)

    def display_summary(self):
        """Display DNS resolution summary with original hostnames (best effort)."""
        from colorama import Fore, Style

        if not self.resolved:
            print(f"{Fore.YELLOW}  No DNS resolutions captured.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}  DNS Resolution Summary:{Style.RESET_ALL}")
        for hostname, resolutions in list(self.resolved.items())[:20]:
            # Show the original (normalized) hostname – it's fine
            ips = [r['ip'] for r in resolutions]
            print(
                f"  {Fore.GREEN}{hostname:<40}{Style.RESET_ALL} → {', '.join(set(ips))}")

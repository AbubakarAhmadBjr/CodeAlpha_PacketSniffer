class PacketFilter:
    """
    Helper class to build BPF (Berkeley Packet Filter) strings.
    
    Examples:
        filter = PacketFilter().tcp().port(80).build()
        # Returns: "tcp and port 80"
        
        filter = PacketFilter().host('192.168.1.1').udp().build()
        # Returns: "host 192.168.1.1 and udp"
    """
    
    def __init__(self):
        self._conditions = []
    
    def tcp(self):
        """Filter TCP packets only."""
        self._conditions.append('tcp')
        return self
    
    def udp(self):
        """Filter UDP packets only."""
        self._conditions.append('udp')
        return self
    
    def icmp(self):
        """Filter ICMP packets only."""
        self._conditions.append('icmp')
        return self
    
    def arp(self):
        """Filter ARP packets only."""
        self._conditions.append('arp')
        return self
    
    def port(self, port_number: int):
        """Filter by port number (source or destination)."""
        self._conditions.append(f'port {port_number}')
        return self
    
    def src_port(self, port_number: int):
        """Filter by source port."""
        self._conditions.append(f'src port {port_number}')
        return self
    
    def dst_port(self, port_number: int):
        """Filter by destination port."""
        self._conditions.append(f'dst port {port_number}')
        return self
    
    def host(self, ip_address: str):
        """Filter by IP address (source or destination)."""
        self._conditions.append(f'host {ip_address}')
        return self
    
    def src_host(self, ip_address: str):
        """Filter by source IP address."""
        self._conditions.append(f'src host {ip_address}')
        return self
    
    def dst_host(self, ip_address: str):
        """Filter by destination IP address."""
        self._conditions.append(f'dst host {ip_address}')
        return self
    
    def network(self, network: str):
        """Filter by network (e.g., '192.168.1.0/24')."""
        self._conditions.append(f'net {network}')
        return self
    
    def http(self):
        """Filter HTTP traffic (port 80)."""
        self._conditions.append('tcp port 80')
        return self
    
    def https(self):
        """Filter HTTPS traffic (port 443)."""
        self._conditions.append('tcp port 443')
        return self
    
    def dns(self):
        """Filter DNS traffic (UDP port 53)."""
        self._conditions.append('udp port 53')
        return self
    
    def ssh(self):
        """Filter SSH traffic (port 22)."""
        self._conditions.append('tcp port 22')
        return self
    
    def not_filter(self, condition: str):
        """Add a NOT condition."""
        self._conditions.append(f'not {condition}')
        return self
    
    def custom(self, bpf_string: str):
        """Add a custom BPF filter string."""
        self._conditions.append(bpf_string)
        return self
    
    def build(self) -> str:
        """Build the final BPF filter string."""
        return ' and '.join(self._conditions) if self._conditions else ''
    
    def __str__(self) -> str:
        return self.build()
    
    @staticmethod
    def preset_http_only() -> str:
        return 'tcp port 80'
    
    @staticmethod
    def preset_dns_only() -> str:
        return 'udp port 53'
    
    @staticmethod
    def preset_no_broadcast() -> str:
        return 'not broadcast and not multicast'
    
    @staticmethod
    def preset_exclude_local(local_ip: str) -> str:
        return f'not host {local_ip}'
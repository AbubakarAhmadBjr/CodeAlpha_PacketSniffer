from colorama import Fore, Back, Style, init
from tabulate import tabulate
from datetime import datetime

init(autoreset=True)


# Protocol color mapping
PROTOCOL_COLORS = {
    'TCP':   Fore.CYAN,
    'UDP':   Fore.YELLOW,
    'ICMP':  Fore.MAGENTA,
    'HTTP':  Fore.GREEN,
    'HTTPS': Fore.GREEN,
    'DNS':   Fore.BLUE,
    'ARP':   Fore.WHITE,
    'IPv4':  Fore.CYAN,
    'IPv6':  Fore.CYAN,
}

# Flag color mapping
FLAG_COLORS = {
    'SYN': Fore.GREEN,
    'ACK': Fore.CYAN,
    'FIN': Fore.RED,
    'RST': Fore.RED,
    'PSH': Fore.YELLOW,
    'URG': Fore.MAGENTA,
}


def get_protocol_color(protocol: str) -> str:
    """Get the display color for a protocol."""
    return PROTOCOL_COLORS.get(protocol, Fore.WHITE)


def format_flags(flags: list) -> str:
    """Format TCP flags with colors."""
    if not flags:
        return ''
    formatted = []
    for flag in flags:
        color = FLAG_COLORS.get(flag, Fore.WHITE)
        formatted.append(f"{color}[{flag}]{Style.RESET_ALL}")
    return ' '.join(formatted)


def format_bytes(byte_count: int) -> str:
    """Format byte count into human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if byte_count < 1024.0:
            return f"{byte_count:.1f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.1f} TB"


def display_packet(packet_info: dict, verbose: bool = False, packet_number: int = 0):
    """
    Display a single packet's information.
    
    Args:
        packet_info: Dictionary with packet details
        verbose: If True, show detailed packet information
        packet_number: Packet sequence number
    """
    protocol = packet_info.get('protocol', 'Unknown')
    color = get_protocol_color(protocol)
    
    # ── Basic One-Line Display ────────────────────────────────────
    if not verbose:
        _display_compact(packet_info, color, protocol, packet_number)
    else:
        _display_verbose(packet_info, color, protocol, packet_number)


def _display_compact(packet_info: dict, color: str, protocol: str, num: int):
    """Display a compact single-line packet summary."""
    timestamp = packet_info.get('timestamp', '')
    src_ip = packet_info.get('src_ip', 'N/A')
    dst_ip = packet_info.get('dst_ip', 'N/A')
    src_port = packet_info.get('src_port', '')
    dst_port = packet_info.get('dst_port', '')
    size = packet_info.get('size', 0)
    service = packet_info.get('service', '')
    flags = packet_info.get('flags', [])
    payload_preview = packet_info.get('payload', '')
    
    # Format addresses
    src = f"{src_ip}:{src_port}" if src_port else str(src_ip)
    dst = f"{dst_ip}:{dst_port}" if dst_port else str(dst_ip)
    
    # Format flags
    flag_str = ''
    if flags:
        flag_str = f" {Fore.YELLOW}[{','.join(flags)}]{Style.RESET_ALL}"
    
    # Service badge
    service_badge = f" {Fore.GREEN}({service}){Style.RESET_ALL}" if service else ""
    
    # Payload preview (first 60 chars)
    payload_str = ''
    if payload_preview:
        preview = str(payload_preview)[:60]
        if len(str(payload_preview)) > 60:
            preview += '...'
        payload_str = f"\n    {Fore.WHITE}↳ {Fore.LIGHTBLACK_EX}{preview}{Style.RESET_ALL}"
    
    print(
        f"{Fore.LIGHTBLACK_EX}#{num:04d}{Style.RESET_ALL} "
        f"{Fore.LIGHTBLACK_EX}{timestamp}{Style.RESET_ALL} "
        f"{color}[{protocol:>6}]{Style.RESET_ALL}"
        f"{service_badge}"
        f"  {Fore.WHITE}{src:<25}{Style.RESET_ALL}"
        f" {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} "
        f"{Fore.WHITE}{dst:<25}{Style.RESET_ALL}"
        f"  {Fore.LIGHTBLACK_EX}{size:>6}B{Style.RESET_ALL}"
        f"{flag_str}"
        f"{payload_str}"
    )


def _display_verbose(packet_info: dict, color: str, protocol: str, num: int):
    """Display detailed packet information in verbose mode."""
    print(f"\n{color}{'─'*70}")
    print(f"  Packet #{num} │ {protocol} │ {packet_info.get('timestamp', '')}")
    print(f"{'─'*70}{Style.RESET_ALL}")
    
    # Layer information
    layers = packet_info.get('layers', [])
    if layers:
        print(f"  {Fore.YELLOW}Layers:{Style.RESET_ALL} {' → '.join(layers)}")
    
    # Network information
    print(f"\n  {Fore.CYAN}【 Network Layer 】{Style.RESET_ALL}")
    if packet_info.get('src_mac'):
        print(f"    MAC: {packet_info.get('src_mac')} → {packet_info.get('dst_mac')}")
    if packet_info.get('src_ip'):
        print(f"    IP:  {packet_info.get('src_ip')} → {packet_info.get('dst_ip')}")
    if packet_info.get('ttl'):
        print(f"    TTL: {packet_info.get('ttl')}")
    
    # Transport information
    if packet_info.get('src_port'):
        print(f"\n  {Fore.CYAN}【 Transport Layer 】{Style.RESET_ALL}")
        print(f"    Port: {packet_info.get('src_port')} → {packet_info.get('dst_port')}")
        if packet_info.get('service'):
            print(f"    Service: {Fore.GREEN}{packet_info.get('service')}{Style.RESET_ALL}")
    
    # TCP-specific details
    if protocol == 'TCP':
        print(f"\n  {Fore.CYAN}【 TCP Details 】{Style.RESET_ALL}")
        flags = packet_info.get('flags', [])
        print(f"    Flags:  {format_flags(flags) or 'None'}")
        if packet_info.get('seq'):
            print(f"    Seq:    {packet_info.get('seq')}")
        if packet_info.get('ack'):
            print(f"    Ack:    {packet_info.get('ack')}")
        if packet_info.get('window'):
            print(f"    Window: {packet_info.get('window')}")
    
    # ICMP details
    if protocol == 'ICMP':
        print(f"\n  {Fore.CYAN}【 ICMP Details 】{Style.RESET_ALL}")
        print(f"    Type: {packet_info.get('icmp_type')}")
        print(f"    Code: {packet_info.get('icmp_code')}")
        if packet_info.get('icmp_id'):
            print(f"    ID:   {packet_info.get('icmp_id')}")
        if packet_info.get('icmp_seq'):
            print(f"    Seq:  {packet_info.get('icmp_seq')}")
    
    # DNS details
    if protocol == 'DNS':
        print(f"\n  {Fore.CYAN}【 DNS Details 】{Style.RESET_ALL}")
        print(f"    Type: {packet_info.get('dns_type', 'Unknown')}")
        if packet_info.get('dns_query'):
            print(f"    Query: {packet_info.get('dns_query')}")
        if packet_info.get('dns_answers'):
            print(f"    Answers: {', '.join(packet_info.get('dns_answers', []))}")
    
    # ARP details
    if protocol == 'ARP':
        print(f"\n  {Fore.CYAN}【 ARP Details 】{Style.RESET_ALL}")
        print(f"    Operation: {packet_info.get('arp_operation')}")
    
    # Payload
    if packet_info.get('payload'):
        print(f"\n  {Fore.CYAN}【 Payload 】{Style.RESET_ALL}")
        payload = str(packet_info.get('payload', ''))
        # Wrap long payloads
        if len(payload) > 100:
            chunks = [payload[i:i+80] for i in range(0, min(len(payload), 320), 80)]
            for chunk in chunks:
                print(f"    {Fore.LIGHTBLACK_EX}{chunk}{Style.RESET_ALL}")
        else:
            print(f"    {Fore.LIGHTBLACK_EX}{payload}{Style.RESET_ALL}")
    
    # Raw bytes (hex dump)
    if packet_info.get('raw_bytes'):
        print(f"\n  {Fore.CYAN}【 Hex Dump (first 32 bytes) 】{Style.RESET_ALL}")
        raw = packet_info['raw_bytes']
        hex_str = ' '.join(f'{b:02x}' for b in raw)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
        print(f"    {Fore.YELLOW}{hex_str:<48}{Style.RESET_ALL}  {Fore.GREEN}|{ascii_str}|{Style.RESET_ALL}")
    
    print(f"  {Fore.LIGHTBLACK_EX}Size: {packet_info.get('size', 0)} bytes{Style.RESET_ALL}")
    print(f"{color}{'─'*70}{Style.RESET_ALL}")


def display_statistics(stats: dict):
    """Display capture statistics in a formatted table."""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  📊 CAPTURE STATISTICS")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    print(f"\n  {Fore.YELLOW}Overview:{Style.RESET_ALL}")
    overview = [
        ['Total Packets',    stats.get('total_packets', 0)],
        ['Total Data',       format_bytes(stats.get('total_bytes', 0))],
        ['Duration',         f"{stats.get('elapsed_time', 0)}s"],
        ['Packets/Second',   stats.get('packets_per_second', 0)],
    ]
    print(tabulate(overview, tablefmt='simple', colalign=('right', 'left')))
    
    # Protocol breakdown
    if stats.get('protocol_counts'):
        print(f"\n  {Fore.YELLOW}Protocol Breakdown:{Style.RESET_ALL}")
        proto_data = sorted(
            stats['protocol_counts'].items(),
            key=lambda x: x[1], reverse=True
        )
        total = stats.get('total_packets', 1)
        proto_table = []
        for proto, count in proto_data:
            bar_len = int((count / total) * 30)
            bar = '█' * bar_len + '░' * (30 - bar_len)
            color = get_protocol_color(proto)
            proto_table.append([
                f"{color}{proto}{Style.RESET_ALL}",
                count,
                f"{(count/total)*100:.1f}%",
                f"{color}{bar}{Style.RESET_ALL}"
            ])
        print(tabulate(proto_table,
                       headers=['Protocol', 'Count', 'Percent', 'Distribution'],
                       tablefmt='simple'))
    
    # Top source IPs
    if stats.get('top_sources'):
        print(f"\n  {Fore.YELLOW}Top Source IPs:{Style.RESET_ALL}")
        src_table = [[ip, count] for ip, count in stats['top_sources']]
        print(tabulate(src_table, headers=['IP Address', 'Packets'], tablefmt='simple'))
    
    # Top destination IPs
    if stats.get('top_destinations'):
        print(f"\n  {Fore.YELLOW}Top Destination IPs:{Style.RESET_ALL}")
        dst_table = [[ip, count] for ip, count in stats['top_destinations']]
        print(tabulate(dst_table, headers=['IP Address', 'Packets'], tablefmt='simple'))
    
    # Top ports
    if stats.get('top_ports'):
        print(f"\n  {Fore.YELLOW}Top Destination Ports:{Style.RESET_ALL}")
        from packet_analyzer import PacketAnalyzer
        port_table = [
            [port, PacketAnalyzer.PORT_SERVICES.get(port, 'Unknown'), count]
            for port, count in stats['top_ports']
        ]
        print(tabulate(port_table,
                       headers=['Port', 'Service', 'Count'],
                       tablefmt='simple'))
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")


def display_header():
    """Display application header banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}  ____  __  ____ __                ___                          {Fore.CYAN}║
║  {Fore.YELLOW} / __ \/ / / / //_/__  _____      /   |  ____  ____ _/ /__  ____{Fore.CYAN}║
║  {Fore.YELLOW}/ /_/ / / / / ,< / _ \/ ___/     / /| | / __ \/ __ `/ / _ \/ __ \\{Fore.CYAN}║
║  {Fore.YELLOW}/ __  / /_/ / /| /  __/ /        / ___ |/ / / / /_/ / /  __/ /_/ /{Fore.CYAN}║
║  {Fore.YELLOW}/_/ /_/\____/_/ |_\___/_/        /_/  |_/_/ /_/\__,_/_/\___/\    / {Fore.CYAN}║
║  {Fore.YELLOW}                                                          /_/   {Fore.CYAN}║
║                                                              ║
║  {Fore.GREEN}Network Traffic Packet Analyzer v1.0                        {Fore.CYAN}║
║  {Fore.WHITE}Powered by Scapy | Educational Tool                        {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def display_interfaces():
    """Display available network interfaces."""
    from scapy.all import get_if_list, get_if_addr
    
    print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            interfaces.append([iface, ip])
        except Exception:
            interfaces.append([iface, 'N/A'])
    
    print(tabulate(interfaces, headers=['Interface', 'IP Address'], tablefmt='simple'))
    print()
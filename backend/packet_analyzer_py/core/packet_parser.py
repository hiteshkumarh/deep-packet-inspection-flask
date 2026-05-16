import struct
from dataclasses import dataclass
from typing import Optional
from .pcap_reader import RawPacket

# ============================================================================
# Protocol Constants
# ============================================================================
class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17

class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806

class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

# ============================================================================
# Parsed Packet Data Structure
# ============================================================================
@dataclass
class ParsedPacket:
    # Timestamps
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    
    # Ethernet layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    
    # IP layer (if present)
    has_ip: bool = False
    ip_version: int = 0
    src_ip_int: int = 0  # Stored as integer for five-tuple
    dest_ip_int: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0    # TCP=6, UDP=17, ICMP=1
    ttl: int = 0
    
    # Transport layer (if present)
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    
    # TCP-specific
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    
    # Payload
    payload_length: int = 0
    payload_data: Optional[bytes] = None

# ============================================================================
# Packet Parser
# ============================================================================
class PacketParser:
    
    @staticmethod
    def parse(raw: RawPacket) -> Optional[ParsedPacket]:
        parsed = ParsedPacket(
            timestamp_sec=raw.header.ts_sec,
            timestamp_usec=raw.header.ts_usec
        )
        
        data = raw.data
        length = len(data)
        offset = 0
        
        # 1. Parse Ethernet
        success, offset = PacketParser._parse_ethernet(data, length, parsed, offset)
        if not success:
            return None
            
        # 2. Parse IPv4
        if parsed.ether_type == EtherType.IPv4:
            success, offset = PacketParser._parse_ipv4(data, length, parsed, offset)
            if not success:
                return None
                
            # 3. Parse Transport Layer
            if parsed.protocol == Protocol.TCP:
                success, offset = PacketParser._parse_tcp(data, length, parsed, offset)
                if not success:
                    return None
            elif parsed.protocol == Protocol.UDP:
                success, offset = PacketParser._parse_udp(data, length, parsed, offset)
                if not success:
                    return None
                    
        # 4. Set Payload
        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_data = None
            
        return parsed

    @staticmethod
    def _parse_ethernet(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> tuple[bool, int]:
        ETH_HEADER_LEN = 14
        if length < offset + ETH_HEADER_LEN:
            return False, offset
            
        dest_mac_bytes = data[offset : offset+6]
        src_mac_bytes = data[offset+6 : offset+12]
        ether_type = struct.unpack(">H", data[offset+12 : offset+14])[0]
        
        parsed.dest_mac = PacketParser.mac_to_string(dest_mac_bytes)
        parsed.src_mac = PacketParser.mac_to_string(src_mac_bytes)
        parsed.ether_type = ether_type
        
        return True, offset + ETH_HEADER_LEN

    @staticmethod
    def _parse_ipv4(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> tuple[bool, int]:
        MIN_IP_HEADER_LEN = 20
        if length < offset + MIN_IP_HEADER_LEN:
            return False, offset
            
        version_ihl = data[offset]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        
        if parsed.ip_version != 4:
            return False, offset
            
        ip_header_len = ihl * 4
        if ip_header_len < MIN_IP_HEADER_LEN or length < offset + ip_header_len:
            return False, offset
            
        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]
        
        # The C++ code copies bytes directly to a uint32_t to be evaluated based on the machine ordering.
        # Commonly PCAP IP stores it in network byte order (Big Endian). 
        # But if we unpack using standard "<I" or ">I" we need to match the integer behavior defined in FiveTuple/Types.
        
        # We will parse the raw int using struct unpacking in native order since we emulate memory copy: 
        ip_src_int = struct.unpack("I", data[offset+12 : offset+16])[0]
        ip_dst_int = struct.unpack("I", data[offset+16 : offset+20])[0]
        
        parsed.src_ip_int = ip_src_int
        parsed.dest_ip_int = ip_dst_int
        parsed.src_ip = PacketParser.ip_to_string(ip_src_int)
        parsed.dest_ip = PacketParser.ip_to_string(ip_dst_int)
        
        parsed.has_ip = True
        return True, offset + ip_header_len

    @staticmethod
    def _parse_tcp(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> tuple[bool, int]:
        MIN_TCP_HEADER_LEN = 20
        if length < offset + MIN_TCP_HEADER_LEN:
            return False, offset
            
        # Parse fields (Big Endian)
        parsed.src_port = struct.unpack(">H", data[offset : offset+2])[0]
        parsed.dest_port = struct.unpack(">H", data[offset+2 : offset+4])[0]
        parsed.seq_number = struct.unpack(">I", data[offset+4 : offset+8])[0]
        parsed.ack_number = struct.unpack(">I", data[offset+8 : offset+12])[0]
        
        data_offset_byte = data[offset+12]
        tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4
        
        parsed.tcp_flags = data[offset+13]
        
        if tcp_header_len < MIN_TCP_HEADER_LEN or length < offset + tcp_header_len:
            return False, offset
            
        parsed.has_tcp = True
        return True, offset + tcp_header_len

    @staticmethod
    def _parse_udp(data: bytes, length: int, parsed: ParsedPacket, offset: int) -> tuple[bool, int]:
        UDP_HEADER_LEN = 8
        if length < offset + UDP_HEADER_LEN:
            return False, offset
            
        parsed.src_port = struct.unpack(">H", data[offset : offset+2])[0]
        parsed.dest_port = struct.unpack(">H", data[offset+2 : offset+4])[0]
        
        parsed.has_udp = True
        return True, offset + UDP_HEADER_LEN

    @staticmethod
    def mac_to_string(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @staticmethod
    def ip_to_string(ip: int) -> str:
        """Expects natively unpacked integer, mimics C++ shift formatting."""
        return f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        if protocol == Protocol.ICMP:
            return "ICMP"
        elif protocol == Protocol.TCP:
            return "TCP"
        elif protocol == Protocol.UDP:
            return "UDP"
        else:
            return f"Unknown({protocol})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        result = []
        if flags & TCPFlags.SYN: result.append("SYN")
        if flags & TCPFlags.ACK: result.append("ACK")
        if flags & TCPFlags.FIN: result.append("FIN")
        if flags & TCPFlags.RST: result.append("RST")
        if flags & TCPFlags.PSH: result.append("PSH")
        if flags & TCPFlags.URG: result.append("URG")
        return " ".join(result) if result else "none"

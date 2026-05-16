from enum import Enum
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import time

# ============================================================================
# Application Classification
# ============================================================================
class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    # Specific applications (detected via SNI)
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    # Add more as needed
    APP_COUNT = 23 # Keep this last for counting

def app_type_to_string(app_type: AppType) -> str:
    mapping = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return mapping.get(app_type, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
        
    lower_sni = sni.lower()
    
    # Google (including YouTube, which is owned by Google)
    if any(domain in lower_sni for domain in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return AppType.GOOGLE
        
    # YouTube
    if any(domain in lower_sni for domain in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
        
    # Facebook/Meta
    if any(domain in lower_sni for domain in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
        
    # Instagram (owned by Meta)
    if any(domain in lower_sni for domain in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM

    # WhatsApp (owned by Meta)
    if any(domain in lower_sni for domain in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
        
    # Twitter/X
    if any(domain in lower_sni for domain in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
        
    # Netflix
    if any(domain in lower_sni for domain in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
        
    # Amazon
    if any(domain in lower_sni for domain in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON

    # Microsoft
    if any(domain in lower_sni for domain in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT

    # Apple
    if any(domain in lower_sni for domain in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
        
    # Telegram
    if any(domain in lower_sni for domain in ["telegram", "t.me"]):
        return AppType.TELEGRAM

    # TikTok
    if any(domain in lower_sni for domain in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
        
    # Spotify
    if any(domain in lower_sni for domain in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
        
    # Zoom
    if "zoom" in lower_sni:
        return AppType.ZOOM
        
    # Discord
    if any(domain in lower_sni for domain in ["discord", "discordapp"]):
        return AppType.DISCORD
        
    # GitHub
    if any(domain in lower_sni for domain in ["github", "githubusercontent"]):
        return AppType.GITHUB

    # Cloudflare
    if any(domain in lower_sni for domain in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
        
    # If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType.HTTPS


# ============================================================================
# Connection State & Packet Action
# ============================================================================
class ConnectionState(Enum):
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4

class PacketAction(Enum):
    FORWARD = 0    # Send to internet
    DROP = 1       # Block/drop the packet
    INSPECT = 2    # Needs further inspection
    LOG_ONLY = 3   # Forward but log

# ============================================================================
# Five-Tuple: Uniquely identifies a connection/flow
# ============================================================================
@dataclass(frozen=True) # Frozen to be used as a dictionary key (hashable)
class FiveTuple:
    src_ip: int     # Stored as integer for fast comparison 
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int   # TCP=6, UDP=17
    
    def reverse(self):
        """Create reverse tuple (for matching bidirectional flows)"""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )
        
    def __str__(self):
        # socket.inet_ntoa expects packed 32-bit bytes in network byte order
        # Assuming the integer is host byte order we pack it using "<I" or ">I"
        # The C++ code prints bytes by shifting, so it assumes the int is
        # stored in Little-Endian format (x >> 0, x >> 8, etc.) 
        # But commonly IPv4 are stored such that socket.inet_ntoa struct.pack('!I', x) works
        # Let's write a python manual packer to mirror the C++ exact formatting.
        src_str = f"{(self.src_ip >> 0) & 0xFF}.{(self.src_ip >> 8) & 0xFF}.{(self.src_ip >> 16) & 0xFF}.{(self.src_ip >> 24) & 0xFF}"
        dst_str = f"{(self.dst_ip >> 0) & 0xFF}.{(self.dst_ip >> 8) & 0xFF}.{(self.dst_ip >> 16) & 0xFF}.{(self.dst_ip >> 24) & 0xFF}"
        proto_str = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{src_str}:{self.src_port} -> {dst_str}:{self.dst_port} ({proto_str})"


# ============================================================================
# Connection Entry (tracked per flow)
# ============================================================================
@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""  # Server Name Indication (if detected)
    
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    
    action: PacketAction = PacketAction.FORWARD
    
    # For TCP state tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False

# ============================================================================
# Packet wrapper for queue passing
# ============================================================================
@dataclass
class PacketJob:
    packet_id: int
    data: bytes  # Actual raw bytes 
    tuple: Optional[FiveTuple] = None
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    
    # Timestamps
    ts_sec: int = 0
    ts_usec: int = 0

# ============================================================================
# Statistics Component
# ============================================================================
@dataclass
class DPIStats:
    # We don't need std::atomic in python for basic counting if 
    # we use GIL-safe operations + locks where explicitly needed across processes,
    # but we can just use normal integers.
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0

import threading
from typing import Set, List, Optional, Tuple
from enum import Enum
import socket
import struct
from .types import AppType


class BlockReasonType(Enum):
    IP = "IP"
    APP = "APP"
    DOMAIN = "DOMAIN"
    PORT = "PORT"


class BlockReason:
    def __init__(self, reason_type: BlockReasonType, value: str):
        self.reason_type = reason_type
        self.value = value


class RuleManager:
    def __init__(self):
        self.blocked_ips: Set[int] = set()
        self.blocked_apps: Set[AppType] = set()
        
        self.blocked_domains: Set[str] = set()
        self.domain_patterns: List[str] = []
        
        self.blocked_ports: Set[int] = set()
        
        # In python, threading locks can be used analogously to shared_mutex
        self.ip_lock = threading.RLock()
        self.app_lock = threading.RLock()
        self.domain_lock = threading.RLock()
        self.port_lock = threading.RLock()

    # ============================================================================
    # Helper Methods
    # ============================================================================
    @staticmethod
    def parse_ip(ip_str: str) -> int:
        """Parses an IP string into an integer mimicking the C++ implementation.
        C++ code does: result |= (octet << shift); shift += 8;
        This means the first octet goes into the lower 8 bits (Little Endian).
        Example: 192.168.1.100 -> 192 + (168<<8) + (1<<16) + (100<<24)"""
        octets = ip_str.split('.')
        if len(octets) != 4:
            return 0
        try:
            return (int(octets[0]) << 0) | \
                   (int(octets[1]) << 8) | \
                   (int(octets[2]) << 16) | \
                   (int(octets[3]) << 24)
        except ValueError:
            return 0

    @staticmethod
    def ip_to_string(ip: int) -> str:
        return f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"

    # ============================================================================
    # IP Blocking
    # ============================================================================
    def block_ip(self, ip: str | int):
        with self.ip_lock:
            if isinstance(ip, str):
                ip_int = self.parse_ip(ip)
            else:
                ip_int = ip
            self.blocked_ips.add(ip_int)

    def unblock_ip(self, ip: str | int):
        with self.ip_lock:
            if isinstance(ip, str):
                ip_int = self.parse_ip(ip)
            else:
                ip_int = ip
            self.blocked_ips.discard(ip_int)

    def is_ip_blocked(self, ip: int) -> bool:
        with self.ip_lock:
            return ip in self.blocked_ips

    # ============================================================================
    # Application Blocking
    # ============================================================================
    def block_app(self, app: AppType | str):
        with self.app_lock:
            if isinstance(app, str):
                app_enum = self._string_to_app(app)
                if app_enum:
                    self.blocked_apps.add(app_enum)
            else:
                self.blocked_apps.add(app)

    def unblock_app(self, app: AppType):
        with self.app_lock:
            self.blocked_apps.discard(app)

    def is_app_blocked(self, app: AppType) -> bool:
        if app == AppType.UNKNOWN:
            return False
            
        with self.app_lock:
            return app in self.blocked_apps

    def _string_to_app(self, app_str: str) -> Optional[AppType]:
        app_str_lower = app_str.lower()
        
        # Create a reverse mapping
        from .types import app_type_to_string
        for app in AppType:
            if app_type_to_string(app).lower() == app_str_lower:
                return app
                
        # Alternative mappings for common variations
        mapping = {
            "youtube": AppType.YOUTUBE,
            "google": AppType.GOOGLE,
            "facebook": AppType.FACEBOOK,
            "tiktok": AppType.TIKTOK,
            "twitter": AppType.TWITTER,
            "instagram": AppType.INSTAGRAM,
        }
        return mapping.get(app_str_lower)

    # ============================================================================
    # Domain Blocking
    # ============================================================================
    def block_domain(self, domain: str):
        with self.domain_lock:
            if '*' in domain:
                if domain not in self.domain_patterns:
                    self.domain_patterns.append(domain)
            else:
                self.blocked_domains.add(domain)

    def unblock_domain(self, domain: str):
        with self.domain_lock:
            if '*' in domain:
                if domain in self.domain_patterns:
                    self.domain_patterns.remove(domain)
            else:
                self.blocked_domains.discard(domain)

    def _domain_matches_pattern(self, domain: str, pattern: str) -> bool:
        if len(pattern) >= 2 and pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            
            # Check if domain ends with the pattern
            if domain.endswith(suffix):
                return True
                
            # Also match the bare domain
            if domain == pattern[2:]:
                return True
                
        return False

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
            
        with self.domain_lock:
            if domain in self.blocked_domains:
                return True
                
            lower_domain = domain.lower()
            
            for pattern in self.domain_patterns:
                lower_pattern = pattern.lower()
                if self._domain_matches_pattern(lower_domain, lower_pattern):
                    return True
                    
            return False

    # ============================================================================
    # Port Blocking
    # ============================================================================
    def block_port(self, port: int):
        with self.port_lock:
            self.blocked_ports.add(port)

    def unblock_port(self, port: int):
        with self.port_lock:
            self.blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self.port_lock:
            return port in self.blocked_ports

    # ============================================================================
    # Combined Check
    # ============================================================================
    def should_block(self, src_ip: int, dst_port: int, app: AppType, domain: str) -> Optional[BlockReason]:
        # Check IP
        if self.is_ip_blocked(src_ip):
            return BlockReason(BlockReasonType.IP, self.ip_to_string(src_ip))
            
        # Check port
        if self.is_port_blocked(dst_port):
            return BlockReason(BlockReasonType.PORT, str(dst_port))
            
        # Check app
        if self.is_app_blocked(app):
            from .types import app_type_to_string
            return BlockReason(BlockReasonType.APP, app_type_to_string(app))
            
        # Check domain
        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReasonType.DOMAIN, domain)
            
        return None

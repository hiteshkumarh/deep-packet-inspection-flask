import struct
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Magic numbers for PCAP files
PCAP_MAGIC_NATIVE = 0xa1b2c3d4
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1

@dataclass
class PcapGlobalHeader:
    magic_number: int = 0
    version_major: int = 0
    version_minor: int = 0
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 0
    network: int = 0

@dataclass
class PcapPacketHeader:
    ts_sec: int = 0
    ts_usec: int = 0
    incl_len: int = 0
    orig_len: int = 0

@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes

class PcapReader:
    def __init__(self):
        self.file = None
        self.global_header = PcapGlobalHeader()
        self.needs_byte_swap = False
        # PCAP Global Header Format:
        # magic_number(4), version_major(2), version_minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4) = 24 bytes
        # We will use struct format strings. '=' means native byte order, standard size.
        # However, we will read it as '<' (Little Endian) first and check magic
        self._global_fmt_le = "<I H H i I I I"
        self._global_fmt_be = ">I H H i I I I"
        
        # PCAP Packet Header Format:
        # ts_sec(4), ts_usec(4), incl_len(4), orig_len(4) = 16 bytes
        self._packet_fmt_le = "<I I I I"
        self._packet_fmt_be = ">I I I I"
        
        self._packet_fmt = self._packet_fmt_le

    def __del__(self):
        self.close()

    def open(self, filename: str) -> bool:
        self.close()
        try:
            self.file = open(filename, "rb")
        except IOError as e:
            logger.error(f"Error: Could not open file: {filename} - {e}")
            return False

        header_bytes = self.file.read(24)
        if len(header_bytes) < 24:
            logger.error("Error: Could not read PCAP global header")
            self.close()
            return False

        # First try unpacking as Little Endian (which is standard for x86)
        magic = struct.unpack("<I", header_bytes[:4])[0]
        
        if magic == PCAP_MAGIC_NATIVE:
            self.needs_byte_swap = False
            self._packet_fmt = self._packet_fmt_le
            unpacked = struct.unpack(self._global_fmt_le, header_bytes)
        elif magic == PCAP_MAGIC_SWAPPED:
            self.needs_byte_swap = True
            self._packet_fmt = self._packet_fmt_be
            unpacked = struct.unpack(self._global_fmt_be, header_bytes)
        else:
            logger.error(f"Error: Invalid PCAP magic number: 0x{magic:x}")
            self.close()
            return False

        self.global_header.magic_number = unpacked[0]
        self.global_header.version_major = unpacked[1]
        self.global_header.version_minor = unpacked[2]
        self.global_header.thiszone = unpacked[3]
        self.global_header.sigfigs = unpacked[4]
        self.global_header.snaplen = unpacked[5]
        self.global_header.network = unpacked[6]

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}")
        print(f"  Snaplen: {self.global_header.snaplen} bytes")
        link_str = " (Ethernet)" if self.global_header.network == 1 else ""
        print(f"  Link type: {self.global_header.network}{link_str}")

        return True

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()
        self.file = None
        self.needs_byte_swap = False

    def read_next_packet(self) -> RawPacket | None:
        """
        Reads the next packet, returns None if no more packets.
        """
        if not self.file or self.file.closed:
            return None

        header_bytes = self.file.read(16)
        if len(header_bytes) < 16:
            return None # End of file

        unpacked = struct.unpack(self._packet_fmt, header_bytes)
        
        packet_header = PcapPacketHeader(
            ts_sec=unpacked[0],
            ts_usec=unpacked[1],
            incl_len=unpacked[2],
            orig_len=unpacked[3]
        )

        if packet_header.incl_len > self.global_header.snaplen or packet_header.incl_len > 65535:
            logger.error(f"Error: Invalid packet length: {packet_header.incl_len}")
            return None
            
        data = self.file.read(packet_header.incl_len)
        if len(data) < packet_header.incl_len:
            logger.error("Error: Could not read packet data (unexpected EOF)")
            return None

        return RawPacket(header=packet_header, data=data)

    def is_open(self) -> bool:
        return self.file is not None and not self.file.closed

    def get_global_header(self) -> PcapGlobalHeader:
        return self.global_header

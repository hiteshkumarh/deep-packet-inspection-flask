from typing import Optional, List, Tuple
import struct

class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def read_uint16_be(data: bytes, offset: int) -> int:
        return struct.unpack(">H", data[offset:offset+2])[0]

    @staticmethod
    def read_uint24_be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset+1] << 8) | data[offset+2]

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        length = len(payload)
        if length < 9:
            return False
            
        # Byte 0: Content Type
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False
            
        # Bytes 1-2: TLS Version
        version = SNIExtractor.read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
            
        # Bytes 3-4: Record length
        record_length = SNIExtractor.read_uint16_be(payload, 3)
        if record_length > length - 5:
            return False
            
        # Byte 5: Handshake Type
        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False
            
        return True

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload):
            return None
            
        length = len(payload)
        offset = 5 # Skip TLS record header
        
        # Skip handshake type and length
        offset += 4
        
        # Skip client version
        offset += 2
        
        # Skip random bytes
        offset += 32
        
        # Session ID
        if offset >= length: return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        
        # Cipher suites
        if offset + 2 > length: return None
        cipher_suites_length = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_length
        
        # Compression methods
        if offset >= length: return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        
        # Extensions
        if offset + 2 > length: return None
        extensions_length = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2
        
        extensions_end = offset + extensions_length
        if extensions_end > length:
            extensions_end = length
            
        while offset + 4 <= extensions_end:
            extension_type = SNIExtractor.read_uint16_be(payload, offset)
            extension_length = SNIExtractor.read_uint16_be(payload, offset + 2)
            offset += 4
            
            if offset + extension_length > extensions_end:
                break
                
            if extension_type == SNIExtractor.EXTENSION_SNI:
                if extension_length < 5: break
                
                sni_list_length = SNIExtractor.read_uint16_be(payload, offset)
                if sni_list_length < 3: break
                
                sni_type = payload[offset + 2]
                sni_length = SNIExtractor.read_uint16_be(payload, offset + 3)
                
                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME: break
                if sni_length > extension_length - 5: break
                
                try:
                    return payload[offset + 5 : offset + 5 + sni_length].decode('utf-8')
                except UnicodeDecodeError:
                    return None
                    
            offset += extension_length
            
        return None


class HTTPHostExtractor:
    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4: return False
        methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
        for method in methods:
            if payload[:4] == method:
                return True
        return False

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload):
            return None
            
        host_header = b"Host: "
        
        # Convert to a format we can search
        lower_payload = payload.lower()
        host_idx = lower_payload.find(b"host:")
        
        if host_idx != -1:
            start = host_idx + 5
            # Skip spaces
            while start < len(payload) and payload[start] in (32, 9): # space or tab
                start += 1
                
            # Find newline
            end = start
            while end < len(payload) and payload[end] not in (13, 10): # \r or \n
                end += 1
                
            if end > start:
                host_str = payload[start:end].decode('utf-8', errors='ignore')
                # Remove port if present
                if ":" in host_str:
                    host_str = host_str.split(":")[0]
                return host_str
                
        return None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12: return False
        
        # Check QR bit (byte 2, bit 7) - should be 0 for query
        flags = payload[2]
        if flags & 0x80: return False
        
        # Check QDCOUNT
        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0: return False
        
        return True

    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload):
            return None
            
        offset = 12
        domain_parts = []
        length = len(payload)
        
        while offset < length:
            label_length = payload[offset]
            
            if label_length == 0:
                break
                
            if label_length > 63:
                break
                
            offset += 1
            if offset + label_length > length: break
            
            try:
                part = payload[offset : offset + label_length].decode('utf-8')
                domain_parts.append(part)
            except:
                break
                
            offset += label_length
            
        if not domain_parts:
            return None
            
        return ".".join(domain_parts)

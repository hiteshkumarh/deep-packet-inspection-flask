import sys
import os
import argparse
from typing import Dict
import struct

from core.pcap_reader import PcapReader, PcapPacketHeader
from core.packet_parser import PacketParser, ParsedPacket, Protocol
from core.types import FiveTuple, AppType, app_type_to_string, sni_to_app_type
from core.rule_manager import RuleManager
from core.sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor

class Flow:
    def __init__(self, tuple_obj: FiveTuple):
        self.tuple = tuple_obj
        self.app_type = AppType.UNKNOWN
        self.sni = ""
        self.packets = 0
        self.bytes = 0
        self.blocked = False

def print_usage(prog_name: str):
    print(f"""
DPI Engine - Deep Packet Inspection System (Python)
===================================================

Usage: python {prog_name} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  python {prog_name} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")

def main():
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    rules = RuleManager()
    
    # Parse options
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1
            rules.block_ip(sys.argv[i])
            print(f"[Rules] Blocked IP: {sys.argv[i]}")
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1
            rules.block_app(sys.argv[i].lower())
            print(f"[Rules] Blocked app: {sys.argv[i]}")
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1
            rules.block_domain(sys.argv[i])
            print(f"[Rules] Blocked domain: {sys.argv[i]}")
        elif not arg.startswith("--"):
            # Implicit rule blocking (for web UI simplicity where user just types 'youtube')
            rules.block_app(arg.lower())
            rules.block_domain(arg.lower())
            print(f"[Rules] Auto-blocked app/domain: {arg}")
        i += 1

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║              DPI ENGINE v2.0 (Python Edition)                ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    reader = PcapReader()
    if not reader.open(input_file):
        sys.exit(1)

    try:
        out_f = open(output_file, "wb")
    except IOError:
        print("Error: Cannot open output file\n")
        sys.exit(1)

    # Write PCAP Global Header
    gh = reader.get_global_header()
    # Ensure it writes in correct byte order (native, as struct default implies) 
    # Or mimic standard 24 bytes header. 
    packet_fmt = reader._packet_fmt
    # Reconstruct original bytes because pcap standard dictates we rewrite raw:
    # Actually, we should just write using struct pack
    out_f.write(struct.pack("I H H i I I I", 
                            0xa1b2c3d4, 
                            2, 4, 0, 0, 
                            gh.snaplen, gh.network))

    flows: Dict[FiveTuple, Flow] = {}
    
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = {}
    
    print("[DPI] Processing packets...")

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break
            
        total_packets += 1
        
        parsed = PacketParser.parse(raw)
        if not parsed: continue
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp): continue
        
        # Create five-tuple key
        tuple_key = FiveTuple(
            src_ip=parsed.src_ip_int,
            dst_ip=parsed.dest_ip_int,
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol
        )
        
        # flow matching bidirectional
        flow = flows.get(tuple_key)
        if not flow:
            flow = flows.get(tuple_key.reverse())
            if not flow:
                flow = Flow(tuple_key)
                flows[tuple_key] = flow
                
        flow.packets += 1
        flow.bytes += len(raw.data)
        
        payload_data = parsed.payload_data
        payload_len = parsed.payload_length

        if payload_data and payload_len > 0:
            # Try SNI Extraction
            if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
                if payload_len > 5:
                    sni = SNIExtractor.extract(payload_data)
                    if sni:
                        flow.sni = sni
                        flow.app_type = sni_to_app_type(sni)

            # Try HTTP Host Extraction
            if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 80:
                host = HTTPHostExtractor.extract(payload_data)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

            # Try DNS Parsing
            if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
                flow.app_type = AppType.DNS
                domain = DNSExtractor.extract_query(payload_data)
                if domain:
                    flow.sni = domain

        # Final basic fallbacks
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443: flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80: flow.app_type = AppType.HTTP
            
        # Blocking evaluation happens at the flow-level tracking
        if not flow.blocked:
            block_reason = rules.should_block(
                src_ip=tuple_key.src_ip, 
                dst_port=tuple_key.dst_port, 
                app=flow.app_type, 
                domain=flow.sni
            )
            if block_reason:
                flow.blocked = True
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}" + (f": {flow.sni})" if flow.sni else ")"))

        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1
        
        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            # Pack exactly what the C++ code did
            hdr_bytes = struct.pack("I I I I", 
                                    raw.header.ts_sec, 
                                    raw.header.ts_usec, 
                                    raw.header.incl_len, 
                                    raw.header.orig_len)
            out_f.write(hdr_bytes)
            out_f.write(raw.data)
            
    reader.close()
    out_f.close()
    
    # Print processing report matching EXACTLY the UI server string scanning schema
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:<10}                             ║")
    print(f"║ Forwarded:          {forwarded:<10}                             ║")
    print(f"║ Dropped:            {dropped:<10}                             ║")
    print(f"║ Active Flows:       {len(flows):<10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    
    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app_type, count in sorted_apps:
        pct = 100.0 * count / total_packets if total_packets > 0 else 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        app_name = app_type_to_string(app_type)
        # Formatting heavily specifically to match alignment for regex parser
        print(f"║ {app_name:<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")
        
    print("╚══════════════════════════════════════════════════════════════╝\n")
    
    print("[Detected Applications/Domains]")
    unique_snis = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type
            
    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {app_type_to_string(app)}")
        
    print(f"\nOutput written to: {os.path.basename(output_file)}")


if __name__ == "__main__":
    main()

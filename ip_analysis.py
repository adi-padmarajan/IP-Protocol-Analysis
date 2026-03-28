#!/usr/bin/env python3
"""
IP Protocol Analysis - CSc 361 Assignment 3

Analyzes traceroute pcap trace files to extract:
- Source and destination IP addresses
- Intermediate routers (ordered by hop count)
- Protocol field values
- Fragmentation information
- RTT statistics (average and standard deviation)

Usage: python3 ip_analysis.py <pcap_file>
"""

import struct
import sys
import math
from collections import defaultdict



# Pcap / packet parsing (no external libraries)


def read_pcap(filename):
    """Read a pcap file manually and return a list of packet dicts."""
    packets = []
    with open(filename, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return packets

        magic = struct.unpack('<I', global_header[0:4])[0]
        if magic == 0xa1b2c3d4:
            ts_div = 1e6
            endian = '<'
        elif magic == 0xa1b23c4d:
            ts_div = 1e9
            endian = '<'
        elif magic == 0xd4c3b2a1:
            ts_div = 1e6
            endian = '>'
        elif magic == 0x4d3cb2a1:
            ts_div = 1e9
            endian = '>'
        else:
            print(f"Error: Unknown pcap magic 0x{magic:08x}")
            sys.exit(1)

        link_type = struct.unpack(endian + 'I', global_header[20:24])[0]

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                endian + 'IIII', pkt_hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append({
                'timestamp': ts_sec + ts_frac / ts_div,
                'data': data,
                'link_type': link_type,
            })
    return packets


def parse_ip(data):
    """Parse an IPv4 header. Returns a dict or None."""
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack('>H', data[2:4])[0]
    ident = struct.unpack('>H', data[4:6])[0]
    flags_frag = struct.unpack('>H', data[6:8])[0]
    mf = (flags_frag >> 13) & 1
    df = (flags_frag >> 14) & 1
    frag_offset = (flags_frag & 0x1FFF) * 8
    ttl = data[8]
    protocol = data[9]
    src = '.'.join(str(b) for b in data[12:16])
    dst = '.'.join(str(b) for b in data[16:20])
    end = min(total_len, len(data))
    return {
        'ihl': ihl, 'total_len': total_len, 'id': ident,
        'mf': mf, 'df': df, 'frag_offset': frag_offset,
        'ttl': ttl, 'protocol': protocol,
        'src': src, 'dst': dst,
        'payload': data[ihl:end],
    }


def parse_udp(data):
    """Parse a UDP header (first 8 bytes). Returns dict or None."""
    if len(data) < 4:
        return None
    return {
        'src_port': struct.unpack('>H', data[0:2])[0],
        'dst_port': struct.unpack('>H', data[2:4])[0],
    }


def parse_icmp(data):
    """Parse an ICMP header. Returns dict or None."""
    if len(data) < 4:
        return None
    result = {
        'type': data[0],
        'code': data[1],
    }
    if data[0] in (0, 8) and len(data) >= 8:       # Echo Reply / Request
        result['id'] = struct.unpack('>H', data[4:6])[0]
        result['seq'] = struct.unpack('>H', data[6:8])[0]
    elif data[0] in (3, 11) and len(data) > 8:     # Error messages
        result['inner_data'] = data[8:]
    return result



# Main analysis


def analyze_trace(filename):
    raw_packets = read_pcap(filename)

    
    # Pass 1 – Parse every IPv4 packet
   
    parsed = []                # list of enriched packet dicts
    protocols_seen = set()     # protocol numbers (only ICMP / UDP kept)

    for rpkt in raw_packets:
        if rpkt['link_type'] != 1:          # only Ethernet
            continue
        if len(rpkt['data']) < 14:
            continue
        eth_type = struct.unpack('>H', rpkt['data'][12:14])[0]
        if eth_type != 0x0800:              # only IPv4
            continue
        ip = parse_ip(rpkt['data'][14:])
        if ip is None:
            continue

        proto = ip['protocol']
        if proto in (1, 17):
            protocols_seen.add(proto)

        info = {'timestamp': rpkt['timestamp'], 'ip': ip}

        if proto == 17 and ip['frag_offset'] == 0:
            udp = parse_udp(ip['payload'])
            if udp:
                info['udp'] = udp

        elif proto == 1:
            icmp = parse_icmp(ip['payload'])
            if icmp:
                info['icmp'] = icmp
                if icmp['type'] in (3, 11) and 'inner_data' in icmp:
                    inner_ip = parse_ip(icmp['inner_data'])
                    if inner_ip:
                        info['inner_ip'] = inner_ip
                        if inner_ip['protocol'] == 17:
                            inner_udp = parse_udp(inner_ip['payload'])
                            if inner_udp:
                                info['inner_udp'] = inner_udp
                        elif inner_ip['protocol'] == 1:
                            inner_icmp = parse_icmp(inner_ip['payload'])
                            if inner_icmp:
                                info['inner_icmp'] = inner_icmp

        parsed.append(info)

    
    # Pass 2 – Detect traceroute mode (UDP vs ICMP) and source/dest
   
    udp_probes = [p for p in parsed
                  if 'udp' in p and p['ip']['protocol'] == 17
                  and 33434 <= p['udp']['dst_port'] <= 33529]

    icmp_echo_probes = [p for p in parsed
                        if 'icmp' in p and p['icmp']['type'] == 8]

    if udp_probes:
        mode = 'UDP'
        source_ip = udp_probes[0]['ip']['src']
        dest_ip = udp_probes[0]['ip']['dst']
    elif icmp_echo_probes:
        mode = 'ICMP'
        # Pick (src, dst) pair that has echo requests with TTL = 1
        ttl1 = [p for p in icmp_echo_probes if p['ip']['ttl'] == 1]
        if ttl1:
            source_ip = ttl1[0]['ip']['src']
            dest_ip = ttl1[0]['ip']['dst']
        else:
            source_ip = icmp_echo_probes[0]['ip']['src']
            dest_ip = icmp_echo_probes[0]['ip']['dst']
        # Keep only probes from source to dest
        icmp_echo_probes = [p for p in icmp_echo_probes
                            if p['ip']['src'] == source_ip
                            and p['ip']['dst'] == dest_ip]
    else:
        print("Error: no traceroute probes found in", filename)
        sys.exit(1)

    
    # Pass 3 – Build probe table

    # Each probe is keyed by its matching identifier (UDP src_port or
    # ICMP echo sequence number).  For fragmented datagrams the key is
    # taken from fragment-0; other fragments are associated via IP ID.

    probes = {}            # match_key -> probe dict
    ip_id_to_key = {}      # ip_id -> match_key  (for fragment association)

    if mode == 'UDP':
        # Fragment-0 probes (have UDP header)
        for p in udp_probes:
            if p['ip']['src'] != source_ip or p['ip']['dst'] != dest_ip:
                continue
            key = p['udp']['src_port']
            probes[key] = {
                'key': key,
                'ttl': p['ip']['ttl'],
                'ip_id': p['ip']['id'],
                'fragments': [{
                    'timestamp': p['timestamp'],
                    'frag_offset': p['ip']['frag_offset'],
                    'mf': p['ip']['mf'],
                    'ip_id': p['ip']['id'],
                }],
            }
            ip_id_to_key[p['ip']['id']] = key

        # Additional fragments (frag_offset > 0) from source→dest, proto 17
        for p in parsed:
            ip = p['ip']
            if (ip['protocol'] == 17 and ip['src'] == source_ip
                    and ip['dst'] == dest_ip and ip['frag_offset'] > 0):
                if ip['id'] in ip_id_to_key:
                    key = ip_id_to_key[ip['id']]
                    probes[key]['fragments'].append({
                        'timestamp': p['timestamp'],
                        'frag_offset': ip['frag_offset'],
                        'mf': ip['mf'],
                        'ip_id': ip['id'],
                    })

    else:   # ICMP mode
        for p in icmp_echo_probes:
            key = p['icmp']['seq']
            probes[key] = {
                'key': key,
                'ttl': p['ip']['ttl'],
                'ip_id': p['ip']['id'],
                'fragments': [{
                    'timestamp': p['timestamp'],
                    'frag_offset': p['ip']['frag_offset'],
                    'mf': p['ip']['mf'],
                    'ip_id': p['ip']['id'],
                }],
            }

    
    # Pass 4 – Collect ICMP responses and match to probes
   
    # For each response we store:
    #   router_ip, match_key, timestamp

    router_rtts = defaultdict(list)    # router_ip -> [rtt, ...]
    router_min_ttl = {}                # router_ip -> minimum probe TTL
    router_first_idx = {}              # router_ip -> index of first appearance
    response_idx = 0

    for p in parsed:
        ip = p['ip']
        if ip['protocol'] != 1 or 'icmp' not in p:
            continue
        icmp = p['icmp']

        match_key = None
        router_ip = ip['src']
        is_relevant = False

        # --- TTL Exceeded (intermediate routers) ---
        if icmp['type'] == 11 and 'inner_ip' in p:
            iip = p['inner_ip']
            if iip['src'] == source_ip and iip['dst'] == dest_ip:
                if mode == 'UDP' and 'inner_udp' in p:
                    match_key = p['inner_udp']['src_port']
                    is_relevant = True
                elif mode == 'ICMP' and 'inner_icmp' in p:
                    match_key = p['inner_icmp']['seq']
                    is_relevant = True

        # --- Destination Unreachable (often from ultimate dest for UDP) ---
        elif icmp['type'] == 3 and 'inner_ip' in p:
            iip = p['inner_ip']
            if iip['src'] == source_ip and iip['dst'] == dest_ip:
                if mode == 'UDP' and 'inner_udp' in p:
                    match_key = p['inner_udp']['src_port']
                    is_relevant = True
                elif mode == 'ICMP' and 'inner_icmp' in p:
                    match_key = p['inner_icmp']['seq']
                    is_relevant = True

        # --- Echo Reply (from ultimate dest for ICMP mode) ---
        elif icmp['type'] == 0 and mode == 'ICMP':
            if 'seq' in icmp and ip['src'] == dest_ip:
                match_key = icmp['seq']
                is_relevant = True

        if not is_relevant or match_key is None:
            continue
        if match_key not in probes:
            continue

        probe = probes[match_key]
        ttl = probe['ttl']
        resp_ts = p['timestamp']

        # Compute RTT for every fragment of this probe
        for frag in probe['fragments']:
            rtt_ms = (resp_ts - frag['timestamp']) * 1000.0
            router_rtts[router_ip].append(rtt_ms)

        if router_ip not in router_min_ttl or ttl < router_min_ttl[router_ip]:
            router_min_ttl[router_ip] = ttl
        if router_ip not in router_first_idx:
            router_first_idx[router_ip] = response_idx
        response_idx += 1

    # Build ordered list of intermediate routers and ultimate destination

    intermediate = []
    ultimate_ip = None

    for rip in router_rtts:
        if rip == dest_ip:
            ultimate_ip = rip
        else:
            intermediate.append(rip)

    # Sort intermediate routers by (min TTL, first appearance)
    intermediate.sort(key=lambda r: (router_min_ttl.get(r, 999),
                                     router_first_idx.get(r, 999)))

    
    # Fragmentation analysis (outgoing probes only)
    
    frag_count = 0
    last_frag_offset = 0

    for key, probe in probes.items():
        frags = probe['fragments']
        if len(frags) > 1 or any(f['mf'] == 1 for f in frags):
            frag_count = len(frags)
            last_frag_offset = max(f['frag_offset'] for f in frags)
            break       # all datagrams fragment the same way

   
    # Output
   
    print(f"The IP address of the source node: {source_ip}")
    print(f"The IP address of ultimate destination node: {dest_ip}")

    print("The IP addresses of the intermediate destination nodes:")
    for i, rip in enumerate(intermediate):
        sep = ',' if i < len(intermediate) - 1 else '.'
        print(f"router {i+1}: {rip}{sep}")

    print()
    print("The values in the protocol field of IP headers:")
    for proto in sorted(protocols_seen):
        name = {1: 'ICMP', 17: 'UDP'}.get(proto, str(proto))
        print(f"{proto}: {name}")

    print()
    print(f"The number of fragments created from the original datagram is: {frag_count}")
    print(f"The offset of the last fragment is: {last_frag_offset}")

    print()
    # RTTs for intermediate routers (in order)
    for rip in intermediate:
        rtts = router_rtts[rip]
        avg = sum(rtts) / len(rtts)
        if len(rtts) > 1:
            var = sum((r - avg) ** 2 for r in rtts) / len(rtts)
            sd = math.sqrt(var)
        else:
            sd = 0.0
        print(f"The avg RTT between {source_ip} and {rip} is: {avg:.2f} ms, the s.d. is: {sd:.2f} ms")

    # RTT for ultimate destination
    if ultimate_ip and ultimate_ip in router_rtts:
        rtts = router_rtts[ultimate_ip]
        avg = sum(rtts) / len(rtts)
        if len(rtts) > 1:
            var = sum((r - avg) ** 2 for r in rtts) / len(rtts)
            sd = math.sqrt(var)
        else:
            sd = 0.0
        print(f"The avg RTT between {source_ip} and {ultimate_ip} is: {avg:.2f} ms, the s.d. is: {sd:.2f} ms")

    print()



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 ip_analysis.py <pcap_file>")
        sys.exit(1)
    analyze_trace(sys.argv[1])

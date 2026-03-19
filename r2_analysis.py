#!/usr/bin/env python3
"""
R2 Analysis - CSc 361 Assignment 3

Analyzes the two groups of trace files for Requirement 2.
Outputs:
 - Number of probes per TTL for each trace
 - Whether intermediate router sequences are the same/different
 - RTT comparison table (if sequences are the same)
 - Which hop incurs maximum delay

Usage: python3 r2_analysis.py
"""

import struct
import sys
import math
from collections import defaultdict, OrderedDict


# ---------------------------------------------------------------------------
# Pcap / packet parsing (reused from ip_analysis.py)
# ---------------------------------------------------------------------------

def read_pcap(filename):
    packets = []
    with open(filename, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24:
            return packets
        magic = struct.unpack('<I', gh[0:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            endian = '<'
        else:
            endian = '>'
        ts_div = 1e9 if (magic in (0xa1b23c4d, 0x4d3cb2a1)) else 1e6
        link_type = struct.unpack(endian + 'I', gh[20:24])[0]

        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_frac, incl_len, _ = struct.unpack(endian + 'IIII', ph)
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
    frag_offset = (flags_frag & 0x1FFF) * 8
    ttl = data[8]
    protocol = data[9]
    src = '.'.join(str(b) for b in data[12:16])
    dst = '.'.join(str(b) for b in data[16:20])
    end = min(total_len, len(data))
    return {
        'ihl': ihl, 'total_len': total_len, 'id': ident,
        'mf': mf, 'frag_offset': frag_offset,
        'ttl': ttl, 'protocol': protocol,
        'src': src, 'dst': dst,
        'payload': data[ihl:end],
    }


def parse_udp(data):
    if len(data) < 4:
        return None
    return {
        'src_port': struct.unpack('>H', data[0:2])[0],
        'dst_port': struct.unpack('>H', data[2:4])[0],
    }


def parse_icmp(data):
    if len(data) < 4:
        return None
    result = {'type': data[0], 'code': data[1]}
    if data[0] in (0, 8) and len(data) >= 8:
        result['id'] = struct.unpack('>H', data[4:6])[0]
        result['seq'] = struct.unpack('>H', data[6:8])[0]
    elif data[0] in (3, 11) and len(data) > 8:
        result['inner_data'] = data[8:]
    return result


# ---------------------------------------------------------------------------
# Per-trace analysis returning structured data
# ---------------------------------------------------------------------------

def analyze_one_trace(filename):
    """Return structured analysis results for one trace file."""
    raw = read_pcap(filename)
    parsed = []

    for rpkt in raw:
        if rpkt['link_type'] != 1 or len(rpkt['data']) < 14:
            continue
        eth_type = struct.unpack('>H', rpkt['data'][12:14])[0]
        if eth_type != 0x0800:
            continue
        ip = parse_ip(rpkt['data'][14:])
        if ip is None:
            continue

        info = {'timestamp': rpkt['timestamp'], 'ip': ip}

        if ip['protocol'] == 17 and ip['frag_offset'] == 0:
            udp = parse_udp(ip['payload'])
            if udp:
                info['udp'] = udp
        elif ip['protocol'] == 1:
            icmp = parse_icmp(ip['payload'])
            if icmp:
                info['icmp'] = icmp
                if icmp['type'] in (3, 11) and 'inner_data' in icmp:
                    iip = parse_ip(icmp['inner_data'])
                    if iip:
                        info['inner_ip'] = iip
                        if iip['protocol'] == 17:
                            iu = parse_udp(iip['payload'])
                            if iu:
                                info['inner_udp'] = iu
                        elif iip['protocol'] == 1:
                            ic = parse_icmp(iip['payload'])
                            if ic:
                                info['inner_icmp'] = ic
        parsed.append(info)

    # Detect mode
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
        ttl1 = [p for p in icmp_echo_probes if p['ip']['ttl'] == 1]
        if ttl1:
            source_ip = ttl1[0]['ip']['src']
            dest_ip = ttl1[0]['ip']['dst']
        else:
            source_ip = icmp_echo_probes[0]['ip']['src']
            dest_ip = icmp_echo_probes[0]['ip']['dst']
        icmp_echo_probes = [p for p in icmp_echo_probes
                            if p['ip']['src'] == source_ip
                            and p['ip']['dst'] == dest_ip]
    else:
        return None

    # Build probes
    probes = {}
    ip_id_to_key = {}

    if mode == 'UDP':
        for p in udp_probes:
            if p['ip']['src'] != source_ip or p['ip']['dst'] != dest_ip:
                continue
            key = p['udp']['src_port']
            probes[key] = {
                'key': key, 'ttl': p['ip']['ttl'],
                'ip_id': p['ip']['id'],
                'fragments': [{'timestamp': p['timestamp'],
                               'frag_offset': p['ip']['frag_offset'],
                               'mf': p['ip']['mf'],
                               'ip_id': p['ip']['id']}],
            }
            ip_id_to_key[p['ip']['id']] = key
        for p in parsed:
            ip = p['ip']
            if (ip['protocol'] == 17 and ip['src'] == source_ip
                    and ip['dst'] == dest_ip and ip['frag_offset'] > 0):
                if ip['id'] in ip_id_to_key:
                    key = ip_id_to_key[ip['id']]
                    probes[key]['fragments'].append({
                        'timestamp': p['timestamp'],
                        'frag_offset': ip['frag_offset'],
                        'mf': ip['mf'], 'ip_id': ip['id']})
    else:
        for p in icmp_echo_probes:
            key = p['icmp']['seq']
            probes[key] = {
                'key': key, 'ttl': p['ip']['ttl'],
                'ip_id': p['ip']['id'],
                'fragments': [{'timestamp': p['timestamp'],
                               'frag_offset': p['ip']['frag_offset'],
                               'mf': p['ip']['mf'],
                               'ip_id': p['ip']['id']}],
            }

    # Count probes per TTL
    ttl_counts = defaultdict(int)
    for k, pr in probes.items():
        ttl_counts[pr['ttl']] += 1

    # Match responses
    router_rtts = defaultdict(list)
    router_min_ttl = {}
    router_first_idx = {}
    # Per-TTL RTTs (for comparison table)
    ttl_rtts = defaultdict(list)    # ttl -> [rtt, ...]
    resp_idx = 0

    for p in parsed:
        ip = p['ip']
        if ip['protocol'] != 1 or 'icmp' not in p:
            continue
        icmp = p['icmp']
        match_key = None
        router_ip = ip['src']
        is_relevant = False

        if icmp['type'] == 11 and 'inner_ip' in p:
            iip = p['inner_ip']
            if iip['src'] == source_ip and iip['dst'] == dest_ip:
                if mode == 'UDP' and 'inner_udp' in p:
                    match_key = p['inner_udp']['src_port']
                    is_relevant = True
                elif mode == 'ICMP' and 'inner_icmp' in p:
                    match_key = p['inner_icmp']['seq']
                    is_relevant = True
        elif icmp['type'] == 3 and 'inner_ip' in p:
            iip = p['inner_ip']
            if iip['src'] == source_ip and iip['dst'] == dest_ip:
                if mode == 'UDP' and 'inner_udp' in p:
                    match_key = p['inner_udp']['src_port']
                    is_relevant = True
                elif mode == 'ICMP' and 'inner_icmp' in p:
                    match_key = p['inner_icmp']['seq']
                    is_relevant = True
        elif icmp['type'] == 0 and mode == 'ICMP':
            if 'seq' in icmp and ip['src'] == dest_ip:
                match_key = icmp['seq']
                is_relevant = True

        if not is_relevant or match_key is None or match_key not in probes:
            continue

        probe = probes[match_key]
        ttl = probe['ttl']
        resp_ts = p['timestamp']

        for frag in probe['fragments']:
            rtt_ms = (resp_ts - frag['timestamp']) * 1000.0
            router_rtts[router_ip].append(rtt_ms)
            ttl_rtts[ttl].append(rtt_ms)

        if router_ip not in router_min_ttl or ttl < router_min_ttl[router_ip]:
            router_min_ttl[router_ip] = ttl
        if router_ip not in router_first_idx:
            router_first_idx[router_ip] = resp_idx
        resp_idx += 1

    # Ordered intermediate router list
    intermediate = [r for r in router_rtts if r != dest_ip]
    intermediate.sort(key=lambda r: (router_min_ttl.get(r, 999),
                                     router_first_idx.get(r, 999)))

    # Per-TTL average RTT
    ttl_avg_rtt = {}
    for ttl in sorted(ttl_rtts):
        rtts = ttl_rtts[ttl]
        ttl_avg_rtt[ttl] = sum(rtts) / len(rtts)

    # Determine probes-per-TTL (mode value)
    if ttl_counts:
        ppt = max(set(ttl_counts.values()), key=list(ttl_counts.values()).count)
    else:
        ppt = 0

    return {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'mode': mode,
        'probes_per_ttl': ppt,
        'ttl_counts': dict(ttl_counts),
        'intermediate_routers': intermediate,
        'router_min_ttl': router_min_ttl,
        'ttl_avg_rtt': ttl_avg_rtt,
        'router_rtts': dict(router_rtts),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyze_group(group_name, trace_files):
    print("=" * 70)
    print(f"  {group_name}")
    print("=" * 70)
    print()

    results = []
    for f in trace_files:
        r = analyze_one_trace(f)
        results.append(r)

    # 1. Probes per TTL
    print(f"Source: {results[0]['source_ip']}")
    print(f"Destination: {results[0]['dest_ip']}")
    print(f"Mode: {results[0]['mode']}")
    print()
    print("1) Number of probes per TTL:")
    for i, r in enumerate(results):
        print(f"   Trace {i+1}: {r['probes_per_ttl']} probes per TTL")
    print()

    # 2. Are intermediate router sequences the same?
    seqs = []
    for r in results:
        seqs.append(r['intermediate_routers'])

    all_same = all(s == seqs[0] for s in seqs)

    print("2) Are intermediate router sequences the same across the 5 traces?")
    if all_same:
        print("   YES - the sequence of intermediate routers is identical.")
    else:
        print("   NO - the sequences differ.")
    print()

    if not all_same:
        # 3. List differences and explain
        print("3) Differences in intermediate router sequences:")
        print()
        # Find the common prefix
        min_len = min(len(s) for s in seqs)
        common_prefix_len = 0
        for j in range(min_len):
            if all(seqs[i][j] == seqs[0][j] for i in range(len(seqs))):
                common_prefix_len = j + 1
            else:
                break

        print(f"   The first {common_prefix_len} hops are identical across all traces:")
        for j in range(common_prefix_len):
            print(f"     Hop {j+1}: {seqs[0][j]}")
        print()
        print(f"   From hop {common_prefix_len + 1} onward, routes diverge:")
        for i, seq in enumerate(seqs):
            hops_after = seq[common_prefix_len:]
            print(f"     Trace {i+1}: {', '.join(hops_after)}")
        print()
        print("   Explanation: The divergence occurs because of Equal-Cost Multi-Path")
        print("   (ECMP) routing / load balancing in the network. Multiple paths of equal")
        print("   cost exist toward the destination, and different probe packets may be")
        print("   forwarded along different paths by intermediate routers using hash-based")
        print("   load balancing on packet fields (e.g., source port). Since each UDP probe")
        print("   uses a different source port, different probes may be hashed to different")
        print("   next hops, resulting in different intermediate routers being observed.")
        print()

    else:
        # 4. Draw RTT comparison table and analyze delay
        print("3) RTT Comparison Table:")
        print()
        # Get all TTLs from intermediate routers (not from destination)
        max_ttl_intermediate = 0
        for r in results:
            for rip in r['intermediate_routers']:
                t = r['router_min_ttl'].get(rip, 0)
                if t > max_ttl_intermediate:
                    max_ttl_intermediate = t
        # Also include the destination hop
        dest_ttl = max_ttl_intermediate + 1

        # Get all TTLs
        all_ttls = sorted(set().union(*(r['ttl_avg_rtt'].keys() for r in results)))

        # Print table header
        header = f"{'TTL':<6}"
        for i in range(5):
            header += f"{'Trace ' + str(i+1):>14}"
        print(f"   {header}")
        print(f"   {'-'*76}")

        # Print each TTL row
        for ttl in all_ttls:
            row = f"{ttl:<6}"
            for i, r in enumerate(results):
                if ttl in r['ttl_avg_rtt']:
                    row += f"{r['ttl_avg_rtt'][ttl]:>14.2f}"
                else:
                    row += f"{'N/A':>14}"
            print(f"   {row}")
        print()

        # Find max delay hop
        # "Maximum delay" = hop where the RTT increase from previous hop is largest
        print("   Analysis: Which hop is likely to incur the maximum delay?")
        print()

        # Calculate per-hop delay increase for each trace
        avg_increase = {}
        per_trace_increase = {}
        for ttl in all_ttls:
            if ttl == min(all_ttls):
                continue
            prev_ttl = ttl - 1
            if prev_ttl not in all_ttls:
                continue
            increases = []
            for r in results:
                if ttl in r['ttl_avg_rtt'] and prev_ttl in r['ttl_avg_rtt']:
                    inc = r['ttl_avg_rtt'][ttl] - r['ttl_avg_rtt'][prev_ttl]
                    increases.append(inc)
            if increases:
                avg_increase[ttl] = sum(increases) / len(increases)
                per_trace_increase[ttl] = increases

        if avg_increase:
            # Show per-hop delay table
            print("   Per-hop delay increase (RTT[hop] - RTT[hop-1]) averaged across traces:")
            for ttl in sorted(avg_increase):
                print(f"     Hop {ttl}: {avg_increase[ttl]:+.2f} ms")
            print()

            max_delay_ttl = max(avg_increase, key=avg_increase.get)
            print(f"   Conclusion: Hop {max_delay_ttl} (TTL={max_delay_ttl}) is likely to incur")
            print(f"   the maximum delay, with an average per-hop RTT increase of")
            print(f"   {avg_increase[max_delay_ttl]:.2f} ms compared to the previous hop.")
            print()

            # Identify router at that hop
            for r in results:
                for rip in r['intermediate_routers']:
                    if r['router_min_ttl'].get(rip) == max_delay_ttl:
                        print(f"   The router at hop {max_delay_ttl} is {rip}.")
                        break
                break
            print()
            print(f"   This is likely because the link between hop {max_delay_ttl-1} and")
            print(f"   hop {max_delay_ttl} traverses a longer physical distance (e.g.,")
            print("   crossing between ISP networks or geographic regions) or experiences")
            print("   higher queuing delay due to congestion.")
        print()


def main():
    group1_files = [f'PcapTracesAssignment3/group1-trace{i}.pcap' for i in range(1, 6)]
    group2_files = [f'PcapTracesAssignment3/group2-trace{i}.pcap' for i in range(1, 6)]

    analyze_group("Group 1 Analysis", group1_files)
    analyze_group("Group 2 Analysis", group2_files)


if __name__ == '__main__':
    main()

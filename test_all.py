#!/usr/bin/env python3
"""Automated verification of ip_analysis.py against all pcap traces."""

import subprocess
import re
import sys

traces = [
    ('PcapTracesAssignment3/group1-trace1.pcap', 'UDP', '192.168.100.17', '8.8.8.8'),
    ('PcapTracesAssignment3/group1-trace2.pcap', 'UDP', '192.168.100.17', '8.8.8.8'),
    ('PcapTracesAssignment3/group1-trace3.pcap', 'UDP', '192.168.100.17', '8.8.8.8'),
    ('PcapTracesAssignment3/group1-trace4.pcap', 'UDP', '192.168.100.17', '8.8.8.8'),
    ('PcapTracesAssignment3/group1-trace5.pcap', 'UDP', '192.168.100.17', '8.8.8.8'),
    ('PcapTracesAssignment3/group2-trace1.pcap', 'ICMP', '192.168.0.16', '8.8.8.8'),
    ('PcapTracesAssignment3/group2-trace2.pcap', 'ICMP', '192.168.0.16', '8.8.8.8'),
    ('PcapTracesAssignment3/group2-trace3.pcap', 'ICMP', '192.168.0.16', '8.8.8.8'),
    ('PcapTracesAssignment3/group2-trace4.pcap', 'ICMP', '192.168.0.16', '8.8.8.8'),
    ('PcapTracesAssignment3/group2-trace5.pcap', 'ICMP', '192.168.0.16', '8.8.8.8'),
    ('PcapTracesAssignment3/traceroute-frag.pcap', 'UDP', '192.168.0.108', '4.2.2.2'),
    ('PcapTracesAssignment3/win_trace1.pcap', 'ICMP', '192.168.0.17', '8.8.8.8'),
    ('PcapTracesAssignment3/win_trace2.pcap', 'ICMP', '192.168.0.17', '4.2.2.2'),
]

# Expected router counts from tcpdump verification
expected_routers = {
    'group1-trace1.pcap': 16,
    'group1-trace2.pcap': 16,
    'group1-trace3.pcap': 16,
    'group1-trace4.pcap': 16,
    'group1-trace5.pcap': 15,
    'group2-trace1.pcap': 8,
    'group2-trace2.pcap': 8,
    'group2-trace3.pcap': 8,
    'group2-trace4.pcap': 8,
    'group2-trace5.pcap': 8,
    'traceroute-frag.pcap': 16,
    'win_trace1.pcap': 13,
    'win_trace2.pcap': 16,
}

# Expected fragmentation data
expected_frags = {
    'traceroute-frag.pcap': (2, 1480),
}

fails = 0
warns = 0

def fail(msg):
    global fails
    fails += 1
    print(f"  FAIL: {msg}")

def warn(msg):
    global warns
    warns += 1
    print(f"  WARN: {msg}")

def ok(msg):
    print(f"  OK:   {msg}")

print("=" * 70)
print("R1 VERIFICATION: ip_analysis.py")
print("=" * 70)

for f, expected_mode, expected_src, expected_dst in traces:
    fname = f.split('/')[-1]
    print(f"\n--- {fname} ---")

    r = subprocess.run(['python3', 'ip_analysis.py', f],
                       capture_output=True, text=True)

    if r.returncode != 0:
        fail(f"exit code {r.returncode}")
        if r.stderr:
            print(f"  STDERR: {r.stderr[:200]}")
        continue

    out = r.stdout

    # 1) Source IP
    m = re.search(r'source node: (\S+)', out)
    src = m.group(1) if m else None
    if src == expected_src:
        ok(f"Source IP: {src}")
    else:
        fail(f"Source IP: expected {expected_src}, got {src}")

    # 2) Dest IP
    m = re.search(r'ultimate destination node: (\S+)', out)
    dst = m.group(1) if m else None
    if dst == expected_dst:
        ok(f"Dest IP: {dst}")
    else:
        fail(f"Dest IP: expected {expected_dst}, got {dst}")

    # 3) Intermediate routers
    routers = re.findall(r'router \d+: ([0-9.]+)', out)
    exp_r = expected_routers.get(fname)
    if exp_r and len(routers) == exp_r:
        ok(f"Router count: {len(routers)}")
    elif exp_r:
        fail(f"Router count: expected {exp_r}, got {len(routers)}")
    else:
        ok(f"Router count: {len(routers)} (no expected value)")

    # 4) Protocols
    if expected_mode == 'UDP':
        if '17: UDP' in out and '1: ICMP' in out:
            ok("Protocols: ICMP + UDP")
        else:
            fail("Protocols: expected both ICMP and UDP")
    else:
        if '1: ICMP' in out:
            ok("Protocols: ICMP present")
        else:
            fail("Protocols: ICMP missing")

    # 5) Fragmentation
    m_frag = re.search(r'number of fragments.*?: (\d+)', out)
    m_off = re.search(r'offset of the last fragment.*?: (\d+)', out)
    frag_count = int(m_frag.group(1)) if m_frag else -1
    frag_off = int(m_off.group(1)) if m_off else -1

    if fname in expected_frags:
        ef_count, ef_off = expected_frags[fname]
        if frag_count == ef_count and frag_off == ef_off:
            ok(f"Fragmentation: {frag_count} frags, offset {frag_off}")
        else:
            fail(f"Fragmentation: expected ({ef_count}, {ef_off}), got ({frag_count}, {frag_off})")
    else:
        if frag_count == 0 and frag_off == 0:
            ok("Fragmentation: none (correct)")
        else:
            fail(f"Fragmentation: expected 0, got ({frag_count}, {frag_off})")

    # 6) RTT lines
    rtt_lines = re.findall(r'avg RTT between .+ is: ([\d.]+) ms, the s\.d\. is: ([\d.]+) ms', out)
    expected_rtt_count = len(routers) + 1  # intermediate + destination
    if len(rtt_lines) == expected_rtt_count:
        ok(f"RTT entries: {len(rtt_lines)} (routers + dest)")
    else:
        fail(f"RTT entries: expected {expected_rtt_count}, got {len(rtt_lines)}")

    # 7) Check RTT values are reasonable (positive, < 500ms)
    bad_rtts = []
    for avg_s, sd_s in rtt_lines:
        avg_v = float(avg_s)
        sd_v = float(sd_s)
        if avg_v < 0 or avg_v > 500:
            bad_rtts.append(f"avg={avg_v}")
        if sd_v < 0 or sd_v > 200:
            bad_rtts.append(f"sd={sd_v}")
    if bad_rtts:
        warn(f"Unusual RTT values: {bad_rtts}")
    else:
        ok("All RTT values reasonable (0-500ms avg, 0-200ms sd)")

    # 8) Check RTT for destination is present
    if dst and f"and {expected_dst} is:" in out:
        ok(f"Destination RTT present for {expected_dst}")
    else:
        fail(f"Destination RTT missing for {expected_dst}")

print("\n" + "=" * 70)
print("R2 VERIFICATION: r2_analysis.py")
print("=" * 70)

r = subprocess.run(['python3', 'r2_analysis.py'], capture_output=True, text=True)
if r.returncode != 0:
    fail(f"r2_analysis.py exit code {r.returncode}")
    if r.stderr:
        print(f"  STDERR: {r.stderr[:500]}")
else:
    out = r.stdout
    ok("r2_analysis.py ran successfully")

    # Check Group 1 analysis
    if 'Group 1' in out:
        ok("Group 1 analysis present")
    else:
        fail("Group 1 analysis missing")

    if 'Group 2' in out:
        ok("Group 2 analysis present")
    else:
        fail("Group 2 analysis missing")

    # Check that probes per TTL = 3
    ppt = re.findall(r'(\d+) probes per TTL', out)
    if all(p == '3' for p in ppt):
        ok(f"Probes per TTL: all report 3 ({len(ppt)} traces)")
    else:
        fail(f"Probes per TTL: {ppt}")

    # Group 1 should show "NO" (different routes)
    if 'NO' in out or 'differ' in out:
        ok("Group 1: routes differ (ECMP detected)")
    else:
        warn("Group 1: expected different routes")

    # Group 2 should show "YES" (same routes)
    if 'YES' in out or 'identical' in out:
        ok("Group 2: routes identical")
    else:
        warn("Group 2: expected identical routes")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
if fails == 0 and warns == 0:
    print("ALL CHECKS PASSED - Ready for submission!")
elif fails == 0:
    print(f"PASSED with {warns} warning(s) - Review warnings above")
else:
    print(f"FAILED: {fails} failure(s), {warns} warning(s)")
sys.exit(1 if fails > 0 else 0)

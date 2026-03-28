#!/usr/bin/env python3
"""Cross-check R2 report RTT table against R1 output for group2 traces."""

import subprocess
import re

expected = {
    1: [3.33, 2.71, 7.85, 3.42, 1.75],
    2: [15.81, 17.12, 11.84, 13.25, 16.15],
    3: [18.87, 20.10, 22.58, 21.67, 21.60],
    4: [22.84, 19.42, 19.46, 19.75, 18.56],
    5: [26.50, 21.56, 20.32, 35.77, 20.72],
    6: [24.26, 19.98, 21.85, 22.67, 43.47],
    7: [18.41, 51.66, 22.76, 18.34, 26.92],
    8: [22.97, 108.74, 20.59, 24.57, 25.62],
    9: [18.10, 21.91, 23.14, 19.94, 21.44],
}

print("=== Cross-checking R2 report RTT values against R1 output ===\n")

all_match = True
for i in range(1, 6):
    f = f'PcapTracesAssignment3/group2-trace{i}.pcap'
    r = subprocess.run(['python3', 'ip_analysis.py', f], capture_output=True, text=True)
    rtts = re.findall(r'avg RTT between .+ and ([0-9.]+) is: ([0-9.]+) ms', r.stdout)
    rtt_map = {ip: float(avg) for ip, avg in rtts}
    routers = re.findall(r'router \d+: ([0-9.]+)', r.stdout)
    m = re.search(r'ultimate destination node: (\S+)', r.stdout)
    dest = m.group(1) if m else ''

    all_ips = routers + [dest]
    for j, rip in enumerate(all_ips):
        ttl = j + 1
        actual = rtt_map.get(rip, -1)
        exp = expected.get(ttl, [None]*5)[i-1]
        if exp is not None and abs(actual - exp) > 0.01:
            print(f"  MISMATCH: Trace {i}, TTL {ttl} ({rip}): report={exp}, actual={actual}")
            all_match = False

if all_match:
    print("ALL R2 report RTT values match R1 output exactly!")

# Also verify Group 1 router sequences match report
print("\n=== Cross-checking Group 1 router sequences ===\n")

expected_g1_common = [
    '142.104.68.167', '142.104.68.1', '192.168.9.5',
    '192.168.10.1', '192.168.8.6', '142.104.252.37',
    '142.104.252.246', '207.23.244.242', '206.12.3.17',
    '199.212.24.64', '206.81.80.17',
]

expected_g1_diverge = {
    1: ['74.125.37.91', '72.14.237.123', '209.85.250.121', '209.85.249.155', '209.85.249.153'],
    2: ['72.14.237.123', '74.125.37.91', '209.85.249.109', '209.85.250.57', '209.85.246.219'],
    3: ['74.125.37.91', '72.14.237.123', '209.85.245.65', '209.85.249.155', '209.85.247.63'],
    4: ['74.125.37.91', '72.14.237.123', '209.85.246.219', '209.85.250.123', '209.85.245.65'],
    5: ['72.14.237.123', '209.85.250.59', '209.85.249.153', '209.85.247.61'],
}

g1_ok = True
for i in range(1, 6):
    f = f'PcapTracesAssignment3/group1-trace{i}.pcap'
    r = subprocess.run(['python3', 'ip_analysis.py', f], capture_output=True, text=True)
    routers = re.findall(r'router \d+: ([0-9.]+)', r.stdout)
    
    exp_full = expected_g1_common + expected_g1_diverge[i]
    if routers == exp_full:
        print(f"  Trace {i}: router sequence matches report")
    else:
        print(f"  MISMATCH: Trace {i}")
        print(f"    Expected: {exp_full}")
        print(f"    Got:      {routers}")
        g1_ok = False

if g1_ok:
    print("\nAll Group 1 router sequences match R2 report!")

# Verify per-hop delay calculation
print("\n=== Verifying per-hop delay increase (Group 2) ===\n")

expected_delays = {
    2: 11.02, 3: 6.13, 4: -0.96, 5: 4.97,
    6: 1.48, 7: 1.17, 8: 12.88, 9: -19.59,
}

for ttl in sorted(expected_delays):
    increases = []
    for i in range(5):
        curr = expected[ttl][i]
        prev = expected[ttl-1][i]
        increases.append(curr - prev)
    avg_inc = sum(increases) / len(increases)
    exp_inc = expected_delays[ttl]
    match = "OK" if abs(avg_inc - exp_inc) < 0.02 else "MISMATCH"
    print(f"  Hop {ttl}: calculated={avg_inc:+.2f}, report={exp_inc:+.2f}  [{match}]")

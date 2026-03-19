---
title: "CSc 361 - Assignment 3: Requirement 2 (R2) Report"
geometry: margin=1in
fontsize: 11pt
---

# Group 1 Analysis

**Source:** 192.168.100.17  
**Destination:** 8.8.8.8  
**Traceroute mode:** Linux UDP-based  

## 1. Number of probes per TTL

| Trace File | Probes per TTL |
|:-----------|:--------------:|
| group1-trace1.pcap | 3 |
| group1-trace2.pcap | 3 |
| group1-trace3.pcap | 3 |
| group1-trace4.pcap | 3 |
| group1-trace5.pcap | 3 |

All five trace files use **3 probes per TTL**.

## 2. Are intermediate router sequences the same?

**No** — the sequence of intermediate routers differs across the five trace files.

The first 11 hops are identical across all traces:

| Hop | Router IP |
|:---:|:----------|
| 1 | 142.104.68.167 |
| 2 | 142.104.68.1 |
| 3 | 192.168.9.5 |
| 4 | 192.168.10.1 |
| 5 | 192.168.8.6 |
| 6 | 142.104.252.37 |
| 7 | 142.104.252.246 |
| 8 | 207.23.244.242 |
| 9 | 206.12.3.17 |
| 10 | 199.212.24.64 |
| 11 | 206.81.80.17 |

## 3. Differences and explanation

From hop 12 onward, different traces observe different routers:

| Hop | Trace 1 | Trace 2 | Trace 3 | Trace 4 | Trace 5 |
|:---:|:--------|:--------|:--------|:--------|:--------|
| 12 | 74.125.37.91 | 72.14.237.123 | 74.125.37.91 | 74.125.37.91 | 72.14.237.123 |
| 13 | 72.14.237.123 | 74.125.37.91 | 72.14.237.123 | 72.14.237.123 | 209.85.250.59 |
| 14 | 209.85.250.121 | 209.85.249.109 | 209.85.245.65 | 209.85.246.219 | 209.85.249.153 |
| 15 | 209.85.249.155 | 209.85.250.57 | 209.85.249.155 | 209.85.250.123 | 209.85.247.61 |
| 16 | 209.85.249.153 | 209.85.246.219 | 209.85.247.63 | 209.85.245.65 | — |

**Explanation:** The divergence starting at hop 12 is caused by **Equal-Cost Multi-Path (ECMP) routing** / **load balancing** in the network. The routers at and beyond hop 11 (which are within Google's network, as indicated by their 72.14.x.x, 74.125.x.x, and 209.85.x.x IP addresses) implement hash-based load balancing. Since each UDP traceroute probe uses a different source port number, different probes may be routed along different equal-cost paths. This results in different intermediate routers being observed for the same hop in different trace runs. The first 11 hops remain stable because those routers are in a simpler, single-path portion of the network between the source and Google's edge.

\newpage

# Group 2 Analysis

**Source:** 192.168.0.16  
**Destination:** 8.8.8.8  
**Traceroute mode:** ICMP-based  

## 1. Number of probes per TTL

| Trace File | Probes per TTL |
|:-----------|:--------------:|
| group2-trace1.pcap | 3 |
| group2-trace2.pcap | 3 |
| group2-trace3.pcap | 3 |
| group2-trace4.pcap | 3 |
| group2-trace5.pcap | 3 |

All five trace files use **3 probes per TTL**.

## 2. Are intermediate router sequences the same?

**Yes** — all five traces have the identical sequence of intermediate routers:

| Hop | Router IP |
|:---:|:----------|
| 1 | 192.168.0.1 |
| 2 | 24.108.0.1 |
| 3 | 64.59.161.197 |
| 4 | 66.163.72.26 |
| 5 | 66.163.68.18 |
| 6 | 72.14.221.102 |
| 7 | 108.170.245.113 |
| 8 | 209.85.249.249 |

Ultimate destination (8.8.8.8) is reached at hop 9.

## 3. RTT Comparison Table

Average RTT (in ms) between the source and each hop:

| TTL | Trace 1 | Trace 2 | Trace 3 | Trace 4 | Trace 5 |
|:---:|--------:|--------:|--------:|--------:|--------:|
| 1 | 3.33 | 2.71 | 7.85 | 3.42 | 1.75 |
| 2 | 15.81 | 17.12 | 11.84 | 13.25 | 16.15 |
| 3 | 18.87 | 20.10 | 22.58 | 21.67 | 21.60 |
| 4 | 22.84 | 19.42 | 19.46 | 19.75 | 18.56 |
| 5 | 26.50 | 21.56 | 20.32 | 35.77 | 20.72 |
| 6 | 24.26 | 19.98 | 21.85 | 22.67 | 43.47 |
| 7 | 18.41 | 51.66 | 22.76 | 18.34 | 26.92 |
| 8 | 22.97 | 108.74 | 20.59 | 24.57 | 25.62 |
| 9 (dest) | 18.10 | 21.91 | 23.14 | 19.94 | 21.44 |

## 4. Which hop incurs the maximum delay?

To determine which hop contributes the most delay, we compute the per-hop delay increase (the difference in average RTT between consecutive hops), averaged across all five traces:

| From → To | Average per-hop increase |
|:---------:|-------------------------:|
| Hop 1 → Hop 2 | +11.02 ms |
| Hop 2 → Hop 3 | +6.13 ms |
| Hop 3 → Hop 4 | −0.96 ms |
| Hop 4 → Hop 5 | +4.97 ms |
| Hop 5 → Hop 6 | +1.48 ms |
| Hop 6 → Hop 7 | +1.17 ms |
| Hop 7 → Hop 8 | +12.88 ms |
| Hop 8 → Hop 9 | −19.59 ms |

**Conclusion:** The link between **Hop 1 and Hop 2** (from 192.168.0.1 to 24.108.0.1) consistently incurs the largest per-hop delay across all five traces, with an increase of approximately 11.02 ms. This hop represents the transition from the local home/campus network to the ISP (Internet Service Provider) backbone, which typically involves traversing a WAN (Wide Area Network) link with higher latency than local network hops.

While the average across all traces shows Hop 7→8 with the highest average increase (12.88 ms), this is heavily influenced by a single outlier measurement in Trace 2 (108.74 ms at TTL=8, compared to ~20–25 ms in other traces). This outlier is likely caused by transient network congestion or queuing delay in that particular trace run rather than a consistently slow link. In contrast, the Hop 1→2 delay is consistently high (ranging from 3.99 to 14.41 ms across traces), making it the most reliably slow hop in the path.

The negative per-hop delay at Hop 8→9 is because the ICMP echo reply from the destination (8.8.8.8) arrives faster than the ICMP TTL-exceeded messages from intermediate routers, as the reply follows a potentially more optimized return path.

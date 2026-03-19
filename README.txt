CSc 361 - Assignment 3: Analysis of IP Protocol
=================================================

Files Included
--------------
- ip_analysis.py      : Main Python program for Requirement 1 (R1)
- r2_analysis.py      : Python program for Requirement 2 (R2) analysis
- R2_Report.pdf       : PDF report with R2 answers
- R2_Report.md        : Source markdown for R2 report
- README.txt          : This file
- PcapTracesAssignment3/  : Folder containing all trace files

How to Compile and Run
----------------------
No compilation needed. The program is written in Python 3. 
Only standard library modules are used (struct, sys, math, collections).

Requirement 1 (R1):
  Run the main analysis script with a pcap file as argument:

    python3 ip_analysis.py <pcap_file>

  Examples:
    python3 ip_analysis.py PcapTracesAssignment3/group1-trace1.pcap
    python3 ip_analysis.py PcapTracesAssignment3/group2-trace1.pcap
    python3 ip_analysis.py PcapTracesAssignment3/win_trace1.pcap
    python3 ip_analysis.py PcapTracesAssignment3/win_trace2.pcap
    python3 ip_analysis.py PcapTracesAssignment3/traceroute-frag.pcap

  The program automatically detects:
  - Linux/UDP traceroute (matching by UDP source port)
  - Windows/ICMP traceroute (matching by ICMP echo sequence number)
  - Fragmented datagrams

Requirement 2 (R2):
  Run the R2 analysis script (no arguments needed):

    python3 r2_analysis.py

  This analyzes all group1-trace*.pcap and group2-trace*.pcap files
  and outputs the comparison data used to produce R2_Report.pdf.

Environment
-----------
Tested on: linux.csc.uvic.ca (Python 3)
No external packages required.
